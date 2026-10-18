#ifndef EXP_PAIRED_QUERY_H
#define EXP_PAIRED_QUERY_H
#include "peer_path.h"
#include "m1_query.h"
#include "pair_plan.h"
int pq_run(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, const struct pp_path *,
           struct nq_store *, struct mq_identity *, struct so_owner *, const struct pair_plan *);
struct sq_query;
/* Caller establishes empty baseline once and owns independent final close.
 * Selected RX context is persisted after validation before new reservations. */
int pq_hold(struct sq_query *, struct rp_pool *, struct so_owner *, uint16_t, uint32_t *,
            const struct pp_path *, struct nq_store *, struct mq_identity *, struct so_owner *,
            const struct pair_plan *);
#endif
