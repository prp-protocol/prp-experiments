#ifndef EXP_PEER_PATH_H
#define EXP_PEER_PATH_H
#include "receipt_store.h"
/* Select by independently supplied interface, never by dump order. */
struct pp_path {
 struct rp_handle list,context[4],tx,rx;
 uint64_t revision[5];
 unsigned ifindex,index,initialized,attempted,retired;
 int primary;
};
int pp_select(struct pp_path *,struct rp_handle,const struct rp_handle [4],unsigned);
/* Retain selected TX/RX. Persist only LIST and the other member's two CTXs;
 * no ticket is canceled to manufacture room after failed custody. */
int pp_retire(struct pp_path *,struct nq_store *);
/* Both interfaces selected before retiring their single shared LIST.
 * All four CTX receipts stay owned; no additional slots are granted. */
int pp_retire_list(struct pp_path [2],struct nq_store *);
#endif
