#ifndef EXP_CONTROL_CAPTURE_H
#define EXP_CONTROL_CAPTURE_H
#include "carrier_query.h"
#include "captured_m1.h"
/* Two existing endpoint packet sockets only. Full returned frames, including
 * non-PRP traffic, receive unique pool3 reservations before recvmsg. */
/* Optional live receive-to-M2 handoff. Path is independent and fixed before
 * capture; output is usable only on return0 after original receipt custody. */
int nc_receive_m1(struct rp_pool *,struct so_owner [2],struct nq_store *,const struct cm_path *,struct cm_m1 *);
int nc_run(struct rp_pool *,struct so_owner [2],struct nq_store *);
int nc_receive_direct_m1(struct rp_pool *,struct so_owner [2],struct nq_store *,const struct cm_direct_path *,struct sb_backend *,struct cm_m1 *);
int nc_quiet(struct rp_pool *,struct so_owner [2],struct nq_store *);
#endif
