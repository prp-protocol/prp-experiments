#include "reserved_netlink.h"
#include <errno.h>
#include <string.h>
static int bad(struct rn_port *p, int e)
{
    if (!p->primary)
        p->primary = e;
    if (!p->transport.primary)
        p->transport.primary = e;
    struct rp_ticket *t = p->bound ? rp_get(p->retained) : NULL;
    if (t) {
        t->revision++;
        if (!t->primary)
            t->primary = SA_REFUSED;
        else if (!t->secondary)
            t->secondary = SA_REFUSED;
        if (!t->transaction.primary)
            t->transaction.primary = t->primary;
    }
    return 0;
}
static int same(const struct nt_context *a, const struct nt_context *b)
{
    return a->socket == b->socket && a->epoch == b->epoch && a->netns == b->netns &&
           a->seq == b->seq && a->port == b->port && a->family == b->family &&
           a->deadline == b->deadline;
}
static int check(struct rn_port *p, int count_join)
{
    if (!p || !p->initialized)
        return 0;
    if (p->primary)
        return 0;
    struct rp_handle h = *p->selected;
    if (h.pool != p->pool)
        return bad(p, ESTALE);
    if (p->bound && (h.slot != p->retained.slot || h.id != p->retained.id ||
                     h.generation != p->retained.generation))
        return bad(p, ESTALE);
    struct rp_ticket *t = rp_get(h);
    if (!t || !t->busy || !t->ran || t->primary || t->raw_row != 5 || !t->commands || !t->facts ||
        t->persist_attempted || !t->transaction.started ||
        !same(&t->transaction.bound, &p->transport.context) ||
        t->budget.calls != p->transport.max_calls ||
        (count_join && t->budget.body_bytes != p->transport.remaining + t->ledger.retained) ||
        t->budget.ticks_per_ms != 1000000 ||
        t->held[0].body < t->budget.body_bytes + t->tx_reserved || t->held[1].body < 3072 ||
        t->held[2].body < 2048 || (!t->final && p->pool->primary))
        return bad(p, ESTALE);
    if (t->transaction.expires_at && t->transaction.expires_at < p->transport.operation_end)
        p->transport.operation_end = t->transaction.expires_at;
    if (!p->bound) {
        if (t->socket_fact.present)
            return bad(p, EALREADY);
        p->retained = h;
        p->bound = 1;
        t->socket_fact.present = 1;
    }
    return 1;
}
static int guard(struct rn_port *p)
{
    return check(p, 1);
}
static int admission(void *v)
{
    return check(v, 0);
}
static void snapshot(struct rn_port *p)
{
    struct rp_ticket *t = p->bound ? rp_get(p->retained) : NULL;
    if (!t)
        return;
    struct ns_port *n = &p->transport;
    t->socket_fact = (struct rp_socket_fact){1,
                                             n->fd,
                                             n->primary,
                                             n->secondary,
                                             n->send_errno,
                                             n->possible,
                                             n->send_result,
                                             n->dev,
                                             n->ino,
                                             n->send_before,
                                             n->send_after,
                                             n->receive_after,
                                             n->calls};
}
static uint64_t tick(void *v)
{
    struct rn_port *p = v;
    if (p->busy) {
        bad(p, EDEADLK);
        return UINT64_MAX;
    }
    if (!guard(p))
        return UINT64_MAX;
    p->busy = 1;
    struct nt_stream s = ns_stream(&p->transport);
    uint64_t n = s.clock(s.arg);
    snapshot(p);
    p->busy = 0;
    if (!guard(p))
        return UINT64_MAX;
    return n;
}
static int send_one(void *v, const unsigned char *b, size_t n)
{
    struct rn_port *p = v;
    if (p->busy) {
        bad(p, EDEADLK);
        return -EDEADLK;
    }
    if (!guard(p))
        return -ESTALE;
    struct rp_ticket *t = rp_get(p->retained);
    if (n > t->tx_reserved)
        return bad(p, EMSGSIZE), -EMSGSIZE;
    p->busy = 1;
    struct nt_stream s = ns_stream(&p->transport);
    int rc = s.send(s.arg, b, n);
    snapshot(p);
    p->busy = 0;
    if (!guard(p) && !rc)
        rc = -ESTALE;
    return rc;
}
static void receive_one(void *v, size_t cap, struct nt_reply *r)
{
    struct rn_port *p = v;
    if (p->busy) {
        bad(p, EDEADLK);
        r->rc = -EDEADLK;
        return;
    }
    if (!guard(p)) {
        r->rc = -ESTALE;
        return;
    }
    p->busy = 1;
    struct nt_stream s = ns_stream(&p->transport);
    s.receive(s.arg, cap, r);
    snapshot(p);
    p->busy = 0;
    /* The outer ledger has not yet charged this returned prefix. Do not compare
  * remaining/ledger here, and never discard raw data during post-validation. */
    struct rp_ticket *t = rp_get(p->retained);
    struct rp_handle h = *p->selected;
    if (!t || h.pool != p->retained.pool || h.slot != p->retained.slot || h.id != p->retained.id ||
        h.generation != p->retained.generation || t->primary || !t->busy ||
        !same(&t->transaction.bound, &p->transport.context)) {
        bad(p, ESTALE);
        if (!r->rc)
            r->rc = -ESTALE;
    }
}
int rn_init(struct rn_port *p, struct rp_pool *pool, const struct rp_handle *h, int fd,
            uint64_t dev, uint64_t ino, const struct nt_context *c, const struct nt_budget *b)
{
    if (!p || p->initialized)
        return 0;
    p->initialized = 1;
    p->pool = pool;
    p->selected = h;
    if (!pool || !pool->initialized || !h || ns_init(&p->transport, fd, dev, ino, c, b))
        return bad(p, EINVAL);
    p->transport.admission = admission;
    p->transport.admission_arg = p;
    return 1;
}
struct nt_stream rn_stream(struct rn_port *p)
{
    return (struct nt_stream){tick, send_one, receive_one, p};
}
