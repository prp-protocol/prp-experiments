#ifndef EXP_ROUTE_QUERY_H
#define EXP_ROUTE_QUERY_H
#include "paired_query.h"
/* Actual query composition, no socket creation. Version2 binds both links.
 * This milestone proves only observed local session/configuration state; it
 * does not claim payload delivery, remote acceptance or performance. */
int rq_run(struct rp_pool *,struct so_owner *,uint16_t,uint32_t *,struct pp_path [2],struct nq_store *,struct mq_identity *,struct mq_identity *,struct so_owner *,const struct pair_plan *);
#endif
