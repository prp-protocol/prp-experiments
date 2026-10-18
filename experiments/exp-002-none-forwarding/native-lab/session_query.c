#include "session_query.h"
static int parent_valid(struct sq_parent_guard *g)
{
    struct rp_handle h;
    if (sf_active_ticket(g->parent, &h) || g->parent->revision != g->revision ||
        h.pool != g->active.pool || h.slot != g->active.slot || h.id != g->active.id ||
        h.generation != g->active.generation) {
        rp_readback(g->target, NULL, NULL, NULL);
        return 0;
    }
    return 1;
}
static uint64_t parent_clock(void *v)
{
    struct sq_parent_guard *g = v;
    parent_valid(g);
    uint64_t n = g->io.clock(g->io.arg);
    parent_valid(g);
    return n;
}
static int parent_send(void *v, const unsigned char *b, size_t n)
{
    struct sq_parent_guard *g = v;
    if (!parent_valid(g))
        return -1;
    int rc = g->io.send(g->io.arg, b, n);
    parent_valid(g);
    return rc;
}
static void parent_receive(void *v, size_t n, struct nt_reply *r)
{
    struct sq_parent_guard *g = v;
    if (!parent_valid(g)) {
        r->rc = -1;
        return;
    }
    g->io.receive(g->io.arg, n, r);
    parent_valid(g);
}

static int open_query(struct sq_query *q, struct rp_pool *p, struct so_owner *o, uint16_t family,
                      uint32_t *seq, const struct nt_selection *selection, uint64_t capacity,
                      struct sf_flow *parent)
{
    if (!q || !p || !o || !o->ready || o->closed || o->primary || !seq || *seq > UINT32_MAX - 5 ||
        !selection)
        return SA_REFUSED;
    struct rp_handle active = {0};
    if (parent &&
        (sf_active_ticket(parent, &active) || active.pool != p || selection->match.scope != 2 ||
         selection->match.alias != 1 || selection->match.peer != parent->active.peer ||
         selection->valid_until > parent->plan.context[3].deadline))
        return SA_IDENTITY;
    struct sf_plan plan = {0};
    plan.pool = p;
    plan.capacity = capacity;
    plan.selection = *selection;
    /* Native session diagnostics plus DONE/ACK exceed 1024 bytes. The existing
  * transaction arena and row6 budget permit 4096 aggregate received bytes. */
    plan.budget = (struct nt_budget){4096, sizeof(struct nt_ledger), 4, 1000000};
    for (unsigned i = 0; i < 5; i++)
        plan.context[i] = (struct nt_context){o->expected.ino,
                                              o->plan.epoch,
                                              o->plan.netns_ino,
                                              i == 4 ? p->close_end : selection->valid_until,
                                              ++*seq,
                                              o->plan.binding,
                                              family};
    int rc = sf_init(&q->flow, &plan);
    if (rc)
        return rc;
    for (unsigned i = 0; i < 5; i++) {
        if (!rn_init(&q->port[i], p, &q->flow.ticket[i], o->fd, o->expected.dev, o->expected.ino,
                     &plan.context[i], &plan.budget))
            return SA_REFUSED;
        q->io[i] = rn_stream(&q->port[i]);
        if (parent && i != 4) {
            q->guard[i] = (struct sq_parent_guard){parent, active, q->flow.ticket[i],
                                                   parent->revision, q->io[i]};
            q->io[i] = (struct nt_stream){parent_clock, parent_send, parent_receive, &q->guard[i]};
        }
    }
    return sf_activate(&q->flow, q->io);
}
int sq_checkpoint(struct sq_query *q, struct nq_store *store)
{
    if (!q || !store || store->files.pool != q->flow.plan.pool)
        return SA_REFUSED;
    struct rp_store io = rf_operations(&store->files);
    return sf_checkpoint(&q->flow, &io);
}
int sq_close(struct sq_query *q, struct nq_store *store)
{
    if (!q || !store || store->files.pool != q->flow.plan.pool)
        return SA_REFUSED;
    sf_finish(&q->flow, q->io);
    struct rp_store io = rf_operations(&store->files);
    return sf_archive(&q->flow, store->files.end, &io);
}

int sq_open(struct sq_query *q, struct rp_pool *p, struct so_owner *o, uint16_t family,
            uint32_t *seq, const struct nt_selection *s, uint64_t capacity)
{
    return open_query(q, p, o, family, seq, s, capacity, NULL);
}
int sq_open_parent(struct sq_query *q, struct rp_pool *p, struct so_owner *o, uint16_t family,
                   uint32_t *seq, const struct nt_selection *s, uint64_t capacity,
                   struct sf_flow *parent)
{
    if (!parent)
        return SA_IDENTITY;
    return open_query(q, p, o, family, seq, s, capacity, parent);
}

int sq_compact(struct sq_query *q, struct nq_store *store)
{
    if (!q || !store || store->files.pool != q->flow.plan.pool)
        return SA_REFUSED;
    struct rp_store io = rf_operations(&store->files);
    return sf_compact(&q->flow, &io);
}
