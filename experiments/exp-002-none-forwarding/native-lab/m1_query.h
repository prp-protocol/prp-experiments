#ifndef EXP_M1_QUERY_H
#define EXP_M1_QUERY_H
#include "carrier_query.h"
#include "native_prepare.h"
#include "captured_m1.h"
#include "session_flow.h"
struct mq_identity {
    unsigned char seed[32], public_key[32];
};
int mq_run(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, struct rp_handle,
           struct nq_store *, struct mq_identity *);
struct mq_result {
    unsigned started, commit_possible, submitted, session_possible, cancel_ack, provider_closed,
        session_observed, session_delete_ack, session_setup_retired, handshake_retired;
    uint64_t capture_id, capture_generation, peer;
    int primary, secondary;
};
/* A submitted M2 can leave a PENDING local session; CANCEL does not delete it. */
int mq_respond(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, struct rp_handle,
               struct nq_store *, struct mq_identity *, const struct cm_m1 *, struct mq_result *);
int mq_pair(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, struct rp_handle,
            struct nq_store *, struct mq_identity *, const struct cm_m1 *,
            const struct nt_selection *, struct mq_result *);
int mq_direct(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, struct rp_handle,
              struct nq_store *, struct mq_identity *, struct sf_flow *, uint32_t,
              const struct nt_remote_m1 *, struct mq_result *);
int mq_direct_respond(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, struct rp_handle,
                      struct nq_store *, struct mq_identity *, struct sf_flow *, uint32_t,
                      const struct cm_m1 *, struct mq_result *);
struct sq_query;
/* Caller owns the retained session and must call sq_close after use/failure. */
int mq_pair_hold(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, struct rp_handle,
                 struct nq_store *, struct mq_identity *, const struct cm_m1 *,
                 const struct nt_selection *, struct sq_query *, struct mq_result *);
/* Independent DIRECT selection and admitted capture; keep ACTIVE until caller
 * finishes payload use. No claim of remote acceptance from transmit ACK. */
int mq_direct_hold(struct rp_pool *, struct so_owner *, uint16_t, uint32_t *, struct rp_handle,
                   struct nq_store *, struct mq_identity *, struct sf_flow *, uint32_t,
                   const struct cm_m1 *, const struct nt_selection *, struct sq_query *,
                   struct mq_result *);
#endif
