/* Experiment-owned bounded socket port. No socket creation or lab activation. */
#ifndef EXP002_SOCKET_BACKEND_H
#define EXP002_SOCKET_BACKEND_H
#include "measure.h"
#include "wire_adapter.h"
struct es_raw {unsigned lane,index;size_t reported,kept;int error,flags;int64_t result;uint64_t before,after;unsigned address_length;unsigned char address[32];unsigned char bytes[4096];};
struct es_ports {
 /* Memory-only callbacks during measurement. Reserve request/ACK/frame/error
  * custody before effects; commit copies raw bytes before returning success. */
 int (*reserve)(void *,unsigned,size_t,size_t,size_t);
 int (*commit)(void *,const struct es_raw *);
 int (*cleanup)(void *);
 void *arg;
};
struct es_backend {
 int cleanup_fault;
 int initialized,busy,primary,secondary,time_failed,possible,pending,closed;
 unsigned index;uint64_t last,hard_end;
 int netlink_fd,packet_fd,ingress_fd,ingress_enabled;struct ew_link ingress_link;
 const struct ep_packet *inputs,*requests;
 struct ew_link link;uint32_t port;
 struct es_ports ports;struct es_raw raw;
};
/* Caller owns two exclusively bound, nonblocking, qualified descriptors and
 * immutable precomputed request/input arrays. This API does not establish that
 * authority or target health. No runtime entrypoint is supplied. */
int es_init(struct es_backend *,int,int,const struct ep_packet *,const struct ep_packet *,
            const struct ew_link *,const struct ew_tx *,uint64_t,const struct es_ports *);
/* Optional third exclusively bound descriptor; binding is supplied by the
 * caller, never inferred from a send or namespace numeric equality. */
int es_bind_ingress(struct es_backend *,int,const struct ew_link *);
struct ep_io es_operations(struct es_backend *);
#endif
