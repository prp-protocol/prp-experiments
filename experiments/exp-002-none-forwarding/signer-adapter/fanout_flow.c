#include "fanout_flow.h"
#include <string.h>
static int bad(struct ff_flow *f, int rc)
{
    if (!f->primary)
        f->primary = rc;
    else if (!f->secondary)
        f->secondary = rc;
    f->revision++;
    f->ready = 0;
    return f->primary;
}
struct guard {
    struct ff_flow *f;
    struct nt_stream io;
    unsigned i;
    uint64_t revision;
};
static int check(struct guard *g)
{
    struct ff_flow *f = g->f;
    struct rp_handle p;
    if (g->revision != f->revision ||
        (g->i != 4 && (f->primary || sf_active_ticket(f->plan.egress, &p) ||
                       f->plan.egress->revision != f->parent_revision || p.pool != f->parent.pool ||
                       p.id != f->parent.id || p.generation != f->parent.generation ||
                       p.slot != f->parent.slot))) {
        rp_readback(f->ticket[g->i], 0, 0, 0);
        return 0;
    }
    return 1;
}
static uint64_t clock_one(void *v)
{
    struct guard *g = v;
    check(g);
    uint64_t n = g->io.clock(g->io.arg);
    check(g);
    return n;
}
static int send_one(void *v, const unsigned char *b, size_t n)
{
    struct guard *g = v;
    if (!check(g))
        return -1;
    int r = g->io.send(g->io.arg, b, n);
    check(g);
    return r;
}
static void receive_one(void *v, size_t n, struct nt_reply *r)
{
    struct guard *g = v;
    if (!check(g)) {
        r->rc = -1;
        return;
    }
    g->io.receive(g->io.arg, n, r);
    check(g);
}
static int operation(struct ff_flow *f, unsigned i, const struct nt_stream io[5])
{
    struct nt_fanout p = f->plan.mapping;
    p.command = i == 0 || i == 3 ? 4 : i == 1 ? 1 : i == 2 ? 3 : 2;
    p.handle = i < 2 ? 0 : f->handle;
    struct guard g = {f, io[i], i, f->revision};
    struct nt_stream ops = {clock_one, send_one, receive_one, &g};
    return rp_fanout(f->ticket[i], &f->plan.context[i], &p, &ops);
}
static int streams(const struct nt_stream io[5])
{
    if (!io)
        return 0;
    for (unsigned i = 0; i < 5; i++)
        if (!io[i].clock || !io[i].send || !io[i].receive)
            return 0;
    return 1;
}
int ff_open(struct ff_flow *f, const struct ff_plan *p, const struct nt_stream io[5])
{
    if (!f)
        return SA_REFUSED;
    if (f->started)
        return bad(f, SA_REPEAT);
    f->started = 1;
    if (!p || !streams(io) || sf_active_ticket(p->egress, &f->parent) || p->mapping.handle ||
        !p->mapping.peer || !p->mapping.generation || !p->mapping.max_members)
        return bad(f, SA_IDENTITY);
    const struct rp_ticket *t = rp_get(f->parent);
    const struct nt_context *c = &t->transaction.bound;
    const struct nt_readback *r = &t->transaction.expected_readback;
    struct rp_pool *pool = f->parent.pool;
    if (r->scope != 1 || r->alias || !(r->direction & 2) || r->peer != p->mapping.peer)
        return bad(f, SA_IDENTITY);
    for (unsigned i = 0; i < 5; i++) {
        const struct nt_context *q = &p->context[i];
        if (q->socket != c->socket || q->netns != c->netns || q->epoch != c->epoch ||
            q->family != c->family || q->port != c->port || q->seq <= c->seq ||
            (i && q->seq <= p->context[i - 1].seq) || !q->deadline ||
            q->deadline > (i == 4 ? pool->close_end : c->deadline))
            return bad(f, SA_IDENTITY);
    }
    f->plan = *p;
    f->parent_revision = p->egress->revision;
    f->busy = 1;
    for (unsigned i = 0; i < 5; i++)
        if (!rp_reserve(pool, i == 4, &p->budget, &f->ticket[i])) {
            f->busy = 0;
            return bad(f, SA_REFUSED);
        }
    for (unsigned i = 0; i < 4 && !f->primary; i++) {
        int rc = operation(f, i, io);
        if (rc) {
            bad(f, rc);
            break;
        }
        if (i == 1)
            f->handle = rp_get(f->ticket[i])->transaction.handle;
    }
    f->busy = 0;
    f->ready = !f->primary;
    return f->primary;
}
int ff_close(struct ff_flow *f, const struct nt_stream io[5])
{
    if (!f)
        return SA_REFUSED;
    if (!f->started || f->finished || f->busy)
        return bad(f, SA_REPEAT);
    f->finished = f->busy = 1;
    f->ready = 0;
    if (!streams(io))
        bad(f, SA_REFUSED);
    else if (f->handle) {
        int rc = operation(f, 4, io);
        if (rc)
            bad(f, rc);
        else
            f->delete_ack = 1;
    }
    f->busy = 0;
    return f->primary;
}
int ff_archive(struct ff_flow *f, uint64_t end, const struct rp_store *s)
{
    if (!f)
        return SA_REFUSED;
    if (!f->finished || f->busy || f->archive_started || !s)
        return bad(f, SA_REPEAT);
    f->busy = f->archive_started = 1;
    for (unsigned i = 0; i < 5; i++) {
        struct rp_ticket *t = rp_get(f->ticket[i]);
        if (!t || !t->ran)
            continue;
        if (t->persist_attempted || (!t->length && !rp_encode(f->ticket[i], 0)) ||
            !rp_persist(f->ticket[i], end, s))
            bad(f, SA_CALLBACK);
    }
    f->busy = 0;
    return f->primary;
}

int ff_mapping_ticket(const struct ff_flow *f, struct rp_handle *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    struct rp_handle parent;
    if (!f || !out || !f->ready || f->busy || f->finished || f->primary || f->archive_started ||
        sf_active_ticket(f->plan.egress, &parent) ||
        f->plan.egress->revision != f->parent_revision || parent.pool != f->parent.pool ||
        parent.slot != f->parent.slot || parent.id != f->parent.id ||
        parent.generation != f->parent.generation)
        return SA_REFUSED;
    struct rp_ticket *t = rp_get(f->ticket[2]);
    if (!t || t->busy || t->primary || t->persist_attempted || !t->transaction.accepted ||
        t->transaction.request[16] != 3 || t->transaction.handle != f->handle ||
        t->transaction.fanout.peer != f->plan.mapping.peer ||
        t->transaction.fanout.generation != f->plan.mapping.generation ||
        t->transaction.fanout.max_bytes != f->plan.mapping.max_bytes ||
        t->transaction.fanout.max_members != f->plan.mapping.max_members ||
        t->transaction.fanout.lease_ms != f->plan.mapping.lease_ms ||
        t->transaction.fanout.flags != f->plan.mapping.flags ||
        t->transaction.bound.socket != f->plan.context[2].socket ||
        t->transaction.bound.netns != f->plan.context[2].netns ||
        t->transaction.bound.epoch != f->plan.context[2].epoch ||
        t->transaction.bound.seq != f->plan.context[2].seq ||
        t->transaction.bound.port != f->plan.context[2].port ||
        t->transaction.bound.family != f->plan.context[2].family ||
        t->transaction.bound.deadline != f->plan.context[2].deadline)
        return SA_IDENTITY;
    *out = f->ticket[2];
    return 0;
}
struct checkpoint {
    struct ff_flow *flow;
    struct rp_store store;
    struct rp_handle target;
    uint64_t revision;
};
static int checkpoint_valid(struct checkpoint *c)
{
    struct ff_flow *f = c->flow;
    struct rp_handle h;
    if (f->revision != c->revision || f->primary || f->finished || f->parent.pool->primary ||
        sf_active_ticket(f->plan.egress, &h) || f->plan.egress->revision != f->parent_revision ||
        h.pool != f->parent.pool || h.slot != f->parent.slot || h.id != f->parent.id ||
        h.generation != f->parent.generation) {
        if (!f->primary)
            bad(f, SA_REENTRY);
        rp_readback(c->target, NULL, NULL, NULL);
        return 0;
    }
    return 1;
}
static uint64_t checkpoint_clock(void *v)
{
    struct checkpoint *c = v;
    checkpoint_valid(c);
    uint64_t n = c->store.clock(c->store.arg);
    checkpoint_valid(c);
    return n;
}
static void checkpoint_write(void *v, uint64_t id, const unsigned char *b, size_t n,
                             struct rp_write_result *r)
{
    struct checkpoint *c = v;
    if (!checkpoint_valid(c)) {
        r->rc = SA_REENTRY;
        return;
    }
    c->store.write_once(c->store.arg, id, b, n, r);
    checkpoint_valid(c);
}
int ff_checkpoint(struct ff_flow *f, const struct rp_store *store)
{
    struct rp_handle active;
    if (!f)
        return SA_REFUSED;
    if (f->checkpoint_started || ff_mapping_ticket(f, &active) || !store || !store->clock ||
        !store->write_once)
        return bad(f, SA_REFUSED);
    f->checkpoint_started = f->busy = 1;
    struct checkpoint c = {f, *store, {0}, f->revision};
    struct rp_store io = {checkpoint_clock, checkpoint_write, &c};
    unsigned indices[] = {0, 1, 3};
    for (unsigned j = 0; j < 3 && !f->primary; j++) {
        unsigned i = indices[j];
        c.target = f->ticket[i];
        struct rp_ticket *t = rp_get(c.target);
        if (!t || !t->ran || t->primary || t->busy || t->persist_attempted) {
            bad(f, SA_IDENTITY);
            break;
        }
        if ((t->length || rp_encode(c.target, NULL)) &&
            rp_persist(c.target, f->plan.context[2].deadline, &io))
            f->archived[i] = 1;
        else
            bad(f, t->primary ? t->primary : SA_CALLBACK);
    }
    f->busy = 0;
    return f->primary;
}
