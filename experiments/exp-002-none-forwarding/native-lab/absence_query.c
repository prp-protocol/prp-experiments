#include "absence_query.h"
#include <stdio.h>
struct guard {
    struct aq_result *result;
    struct rp_handle ticket;
    struct nt_stream io;
};
static int valid(struct guard *g)
{
    if (!g->result->primary)
        return 1;
    rp_readback(g->ticket, NULL, NULL, NULL);
    return 0;
}
static uint64_t clock_one(void *v)
{
    struct guard *g = v;
    valid(g);
    uint64_t n = g->io.clock(g->io.arg);
    valid(g);
    return n;
}
static int send_one(void *v, const unsigned char *b, size_t n)
{
    struct guard *g = v;
    if (!valid(g))
        return -1;
    int rc = g->io.send(g->io.arg, b, n);
    valid(g);
    return rc;
}
static void receive_one(void *v, size_t n, struct nt_reply *r)
{
    struct guard *g = v;
    if (!valid(g)) {
        r->rc = -1;
        return;
    }
    g->io.receive(g->io.arg, n, r);
    valid(g);
}
int aq_run(struct aq_result *r, struct rp_pool *p, struct so_owner *o, uint16_t family,
           uint32_t *seq, struct nq_store *store)
{
    if (!r)
        return SA_REFUSED;
    if (r->started) {
        if (!r->primary)
            r->primary = SA_REPEAT;
        return r->primary;
    }
    r->started = 1;
    if (!p || !p->initialized || p->primary || !o || !o->ready || o->closed || o->primary ||
        family < 16 || !seq || *seq > UINT32_MAX - 2 || !store || store->files.pool != p) {
        r->primary = SA_IDENTITY;
        return r->primary;
    }
    const unsigned commands[2] = {40, 72};
    struct nt_budget budget = {1024, sizeof(struct nt_ledger), 4, 1000000};
    struct rn_port port[2] = {0};
    for (unsigned i = 0; i < 2 && !r->primary; i++) {
        r->context[i] = (struct nt_context){o->expected.ino, o->plan.epoch, o->plan.netns_ino,
                                            p->normal_end,   ++*seq,        o->plan.binding,
                                            family};
        if (!rp_reserve(p, 0, &budget, &r->ticket[i]) ||
            !rn_init(&port[i], p, &r->ticket[i], o->fd, o->expected.dev, o->expected.ino,
                     &r->context[i], &budget))
            r->primary = SA_REFUSED;
    }
    printf("{\"operations\":[");
    unsigned emitted = 0;
    for (unsigned i = 0; i < 2 && !r->primary; i++) {
        struct guard g = {r, r->ticket[i], rn_stream(&port[i])};
        struct nt_stream io = {clock_one, send_one, receive_one, &g};
        int rc = rp_empty_list(r->ticket[i], &r->context[i], commands[i], &io);
        struct rp_ticket *t = rp_get(r->ticket[i]);
        if (!i)
            r->before = t->transaction.before;
        r->after = t->transaction.after;
        if (rc) {
            if (!r->primary)
                r->primary = rc;
            else if (!r->secondary)
                r->secondary = rc;
        } else if (!r->primary)
            r->observed |= 1u << i;
        if (emitted++)
            putchar(',');
        printf("{\"command\":%u,\"rc\":%d,\"ticket\":%llu,\"generation\":%llu,\"receipt\":\"",
               commands[i], rc, (unsigned long long)r->ticket[i].id,
               (unsigned long long)r->ticket[i].generation);
        int encoded = rp_encode(r->ticket[i], NULL);
        for (size_t j = 0; j < t->length; j++)
            printf("%02x", t->receipt[j]);
        printf("\"}");
        if (!encoded || !nq_archive_before(store, r->ticket[i], p->normal_end)) {
            if (!r->primary)
                r->primary = SA_CALLBACK;
            else if (!r->secondary)
                r->secondary = SA_CALLBACK;
        } else
            r->archived |= 1u << i;
    }
    printf("],\"observed_mask\":%u,\"archived_mask\":%u,\"primary\":%d,\"secondary\":%d}",
           r->observed, r->archived, r->primary, r->secondary);
    return r->primary ? r->primary : r->secondary;
}
