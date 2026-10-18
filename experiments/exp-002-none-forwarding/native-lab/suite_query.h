#ifndef EXP_NATIVE_SUITE_QUERY_H
#define EXP_NATIVE_SUITE_QUERY_H
#include "socket_owner.h"
#include "reserved_netlink.h"
/* Borrow the caller's original live socket. No identity, session or key creation. */
int sq_run(struct rp_pool *, struct so_owner *, uint16_t, uint32_t, struct rp_handle *);
#endif
