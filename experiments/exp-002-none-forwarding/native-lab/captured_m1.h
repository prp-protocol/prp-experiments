#ifndef EXP_CAPTURED_M1_H
#define EXP_CAPTURED_M1_H
#include "native_prepare.h"
#include "session_flow.h"
/* Independent caller-selected path, never learned as trust from packet bytes.
 * context is the receiving guest's Netlink context, not the packet socket.
 * generation is a preselected expectation, NOT inferred from an M1 (which has
 * no generation). The subsequent kernel M2 prefix must match it exactly.
 * not_before/end use only this receiving guest's monotonic clock domain. */
struct cm_path {
 struct nt_context context;
 uint64_t peer,not_before,end;
 uint32_t generation;
 unsigned ifindex;
 unsigned char source[6],destination[6],public_key[32];
};
struct cm_m1 {
 struct nt_remote_m1 remote;
 uint64_t receipt_id,receipt_generation,before,after,parent_id,parent_generation;
 unsigned scope;uint32_t transfer;
};
/* A bounded projection of a live pool3 capture before its persistence retires
 * the ticket. No socket operation, signature acceptance or session inference.
 * A rejected or consumed capture cannot be replayed into a second admission.
 * The caller must keep failure custody and persist the original raw receipt. */
int cm_admit(struct rp_handle,const struct cm_path *,uint64_t,struct cm_m1 *);
/* Single complete kind7 M1; parent is independently observed adjacent RX.
 * transfer is fixed by the caller, never selected from received bytes. */
struct cm_direct_path {struct cm_path path;struct sf_flow *parent;uint32_t transfer;};
int cm_admit_direct(struct rp_handle,const struct cm_direct_path *,uint64_t,struct sb_backend *,struct cm_m1 *);
#endif
