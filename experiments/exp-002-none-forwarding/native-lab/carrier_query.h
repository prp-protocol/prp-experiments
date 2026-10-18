#ifndef EXP_CARRIER_QUERY_H
#define EXP_CARRIER_QUERY_H
#include "suite_query.h"
#include "receipt_store.h"
struct mq_identity;
struct pair_plan;
int cq_run(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, unsigned, unsigned,
           struct nq_store *
#ifdef M1_QUERY
           ,
           uint16_t, struct mq_identity *, struct mq_identity *, struct so_owner *,
           const struct pair_plan *
#endif
);
#endif
