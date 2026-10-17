#ifndef EXP_RESERVED_NETLINK_H
#define EXP_RESERVED_NETLINK_H
#include "reservations.h"
#include "netlink_socket.h"
/* The controller fills *selected only after allocating the transaction ticket.
 * Storage and FD lifetime are caller-owned; no allocation or descriptor creation. */
struct rn_port {
 struct ns_port transport;
 struct rp_pool *pool;
 const struct rp_handle *selected;
 struct rp_handle retained;
 unsigned initialized,bound,busy;
 int primary;
};
int rn_init(struct rn_port *,struct rp_pool *,const struct rp_handle *,int,
            uint64_t,uint64_t,const struct nt_context *,const struct nt_budget *);
struct nt_stream rn_stream(struct rn_port *);
#endif
