#include "suite_query.h"
#include <errno.h>
int sq_run(struct rp_pool *pool,struct so_owner *owner,uint16_t family,
           uint32_t seq,struct rp_handle *handle){
 if(!pool||!owner||!handle||!owner->created||!owner->ready||owner->close_started||owner->closed||owner->primary||owner->time_failed||
    handle->pool||owner->fd!=owner->expected.fd||owner->plan.binding!=owner->expected.binding||
    owner->plan.slot<2||owner->plan.slot>4||family<16||!seq||
    owner->plan.normal_end!=pool->normal_end)return -EINVAL;
 struct nt_context context={owner->expected.ino,owner->plan.epoch,
  owner->plan.netns_ino,pool->normal_end,seq,owner->plan.binding,family};
 /* Restrictive qualification: ACK plus result, at most four datagrams and
  * 512 aggregate returned bytes. A larger valid result refuses, never retries. */
 struct nt_budget budget={512,sizeof(struct nt_ledger),4,1000000};
 struct rn_port port={0};
 if(!rn_init(&port,pool,handle,owner->fd,owner->expected.dev,
             owner->expected.ino,&context,&budget))return -EINVAL;
 if(!rp_reserve(pool,0,&budget,handle))return -ENOBUFS;
 struct nt_stream stream=rn_stream(&port);
 struct nt_readback expected={.command=57};
 int primary=rp_readback(*handle,&context,&expected,&stream);
 if(!rp_encode(*handle,NULL)&&!primary)primary=-EBADMSG;
 return primary;
}
