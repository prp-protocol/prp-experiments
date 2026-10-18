#ifndef EXP_SESSION_QUERY_H
#define EXP_SESSION_QUERY_H
#include "session_flow.h"
#include "carrier_query.h"
/* Caller must retain this storage through close/archive. No socket creation.
 * Open observes/activates exactly one independently selected adjacent session. */
struct sq_parent_guard {
    struct sf_flow *parent;
    struct rp_handle active, target;
    uint64_t revision;
    struct nt_stream io;
};
struct sq_query {
    struct sf_flow flow;
    struct rn_port port[5];
    struct nt_stream io[5];
    struct sq_parent_guard guard[5];
};
int sq_open(struct sq_query *, struct rp_pool *, struct so_owner *, uint16_t, uint32_t *,
            const struct nt_selection *, uint64_t);
int sq_open_parent(struct sq_query *, struct rp_pool *, struct so_owner *, uint16_t, uint32_t *,
                   const struct nt_selection *, uint64_t, struct sf_flow *);
int sq_checkpoint(struct sq_query *, struct nq_store *);
int sq_compact(struct sq_query *, struct nq_store *);
int sq_close(struct sq_query *, struct nq_store *);
#endif
