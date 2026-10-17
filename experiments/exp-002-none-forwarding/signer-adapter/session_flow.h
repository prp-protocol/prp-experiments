#ifndef EXP_SESSION_FLOW_H
#define EXP_SESSION_FLOW_H
#include "reservations.h"
/* One observed adjacent incarnation, not a handshake or remote-delivery proof.
 * Caller owns exclusive administration and supplies identity before LIST. */
struct sf_plan {
 struct rp_pool *pool;
 struct nt_budget budget;
 struct nt_context context[5]; /* LIST, pending GET, SET, active GET, DEL */
 struct nt_selection selection;
 uint64_t capacity;
};
struct sf_flow {
 struct sf_plan plan;
 struct rp_handle ticket[5];
 struct nt_readback pending,active;
 uint64_t revision,compact_clock;
 unsigned initialized,started,busy,finished,archive_started,observed,delete_ack,checkpoint_started,compact_started,cleanup_active;
 unsigned archived[5];
 int primary,secondary;
};
/* Reserve all five operations before any effect. No retry on partial admission;
 * unresolved reservations remain visible in the shared pool. */
int sf_init(struct sf_flow *,const struct sf_plan *);
int sf_activate(struct sf_flow *,const struct nt_stream [5]);
/* Retire only consumed LIST and SET receipts while keeping pending GET for
 * exact cleanup, ACTIVE GET for downstream use, and the reserved DEL ticket.
 * Persistence is admitted inside the ORIGINAL normal bound, not a fresh phase. */
int sf_checkpoint(struct sf_flow *,const struct rp_store *);
/* Returns only the still-owned ACTIVE GET receipt; not native liveness proof. */
/* After checkpoint, retire PENDING GET only when exact ACTIVE GET supplies
 * the same incarnation for final DEL. That cleanup source is selected before
 * fallible persistence, so a file error cannot erase the ACTIVE observation. */
int sf_compact(struct sf_flow *,const struct rp_store *);
int sf_active_ticket(const struct sf_flow *,struct rp_handle *);
int sf_finish(struct sf_flow *,const struct nt_stream [5]);
/* Call only after finish. Persistence never turns uncertain cleanup into PASS. */
int sf_archive(struct sf_flow *,uint64_t,const struct rp_store *);
#endif
