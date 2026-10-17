#define _POSIX_C_SOURCE 200809L
#include "paired_query.h"
#ifdef PRELIMINARY_DATA
#include "preliminary_data.h"
#endif
#include "absence_query.h"
#include "session_query.h"
#include "control_capture.h"
#include "public-blake3/blake3.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
static uint64_t tick(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0)return UINT64_MAX;return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static int paired(struct sq_query *held,struct rp_pool *p,struct so_owner *o,uint16_t family,uint32_t *seq,const struct pp_path *path,struct nq_store *store,struct mq_identity *id,struct so_owner *packets,const struct pair_plan *plan){
 struct rp_ticket *tx=path?rp_get(path->tx):NULL,*rx=path?rp_get(path->rx):NULL;
 if(!p||!p->initialized||p->primary||!tx||!rx||tx==rx||path->tx.pool!=p||path->rx.pool!=p||!tx->ran||!rx->ran||tx->busy||rx->busy||tx->persist_attempted||rx->persist_attempted||!tx->transaction.accepted||!rx->transaction.accepted||tx->transaction.request[16]!=76||rx->transaction.request[16]!=76||tx->transaction.member_context.direction!=1||rx->transaction.member_context.direction!=2||!plan||plan->generation!=1||(plan->role!=1&&plan->role!=2)||!o||!seq||*seq>UINT32_MAX-16||!id||!store||tx->primary||rx->primary||tx->transaction.peer_context!=rx->transaction.peer_context||(plan->role==2&&!packets))return SA_IDENTITY;
 uint64_t before=tick();if(before>=p->normal_end)return SA_TIME;
 unsigned char strong[32],suite[2]={0,1};blake3_hasher hash;blake3_hasher_init(&hash);blake3_hasher_update(&hash,"PRP-STRONG-ID-v4",16);blake3_hasher_update(&hash,suite,2);blake3_hasher_update(&hash,plan->public_key,32);blake3_hasher_finalize(&hash,strong,32);
 struct nt_readback expect={0};expect.command=53;expect.peer=tx->transaction.peer_context;expect.scope=1;memcpy(expect.strong_id,strong,32);
 struct nt_budget budget={1024,sizeof(struct nt_ledger),4,1000000};struct rp_handle h[3]={{0}};struct rn_port ports[3]={0};struct nt_context c[3];int primary=0,secondary=0;
 printf("{\"role\":%u,\"peer\":%llu",plan->role,(unsigned long long)expect.peer);
 if(held&&!primary&&!nq_archive_before(store,path->rx,p->normal_end))primary=SA_CALLBACK;
 struct aq_result baseline={0};if(!held&&!primary){printf(",\"empty_baseline\":");primary=aq_run(&baseline,p,o,family,seq,store);}
 for(unsigned i=0;i<3&&!primary;i++){
  c[i]=(struct nt_context){o->expected.ino,o->plan.epoch,o->plan.netns_ino,i==2?p->close_end:p->normal_end,++*seq,o->plan.binding,family};
  if(!rp_reserve(p,i==2,&budget,&h[i])||!rn_init(&ports[i],p,&h[i],o->fd,o->expected.dev,o->expected.ino,&c[i],&budget))primary=SA_REFUSED;
 }
 if(!primary){struct nt_stream io=rn_stream(&ports[0]);primary=rp_expectation(h[0],path->tx,&c[0],&expect,&io);}
 if(!primary){expect.command=55;struct nt_stream io=rn_stream(&ports[1]);primary=rp_readback(h[1],&c[1],&expect,&io);}
 if(!primary&&!nq_archive(store,h[1]))primary=SA_CALLBACK;
#ifdef PRELIMINARY_DATA
 if(!primary)primary=pd_handshake();
#endif
 struct cm_m1 captured={0};
 if(!primary&&plan->role==2){
  struct cm_path cp={.context=c[0],.peer=expect.peer,.not_before=before,.end=p->normal_end,.generation=plan->generation,.ifindex=path->ifindex};memcpy(cp.source,plan->remote,6);memcpy(cp.destination,plan->local,6);memcpy(cp.public_key,plan->public_key,32);
  printf(held?",\"capture\":[":",\"capture\":");primary=nc_receive_m1(p,packets,store,&cp,&captured);
#ifdef PRELIMINARY_DATA
  if(!primary){putchar(',');primary=nc_quiet(p,packets,store);}
#endif
  if(held)putchar(']');
 }
 struct mq_result result={0};
 if(!primary){
  struct nt_selection selection={0};selection.match=expect;selection.match.command=14;selection.match.state=1;selection.match.direction=3;selection.match.generation=plan->generation;selection.population=held?3:1;selection.not_before=before;selection.valid_until=p->normal_end;
  printf(held?",\"exchange\":[":",\"exchange\":");primary=held?mq_pair_hold(p,o,family,seq,path->tx,store,id,plan->role==2?&captured:NULL,&selection,held,&result):mq_pair(p,o,family,seq,path->tx,store,id,plan->role==2?&captured:NULL,&selection,&result);if(held)putchar(']');
 }
 struct rp_ticket *set=rp_get(h[0]);
 if(set&&set->transaction.possible&&h[2].pool){expect.command=54;struct nt_stream io=rn_stream(&ports[2]);int rc=rp_expectation(h[2],h[0],&c[2],&expect,&io);if(rc){if(!primary)primary=rc;else secondary=rc;}}
 for(unsigned i=0;i<3;i++){struct rp_ticket *t=rp_get(h[i]);if(t&&t->ran&&!t->persist_attempted&&!nq_archive(store,h[i])){if(!primary)primary=SA_CALLBACK;else if(!secondary)secondary=SA_CALLBACK;}}
 printf(",\"session_observed\":%s,\"session_delete_ack\":%s,\"session_possible\":%s,\"primary\":%d,\"secondary\":%d,\"payload_delivered\":false}",result.session_observed?"true":"false",result.session_delete_ack?"true":"false",result.session_possible?"true":"false",primary,secondary);
 return primary?primary:secondary;
}

int pq_run(struct rp_pool *p,struct so_owner *o,uint16_t f,uint32_t *seq,const struct pp_path *path,struct nq_store *store,struct mq_identity *id,struct so_owner *packets,const struct pair_plan *plan){return paired(NULL,p,o,f,seq,path,store,id,packets,plan);}
int pq_hold(struct sq_query *held,struct rp_pool *p,struct so_owner *o,uint16_t f,uint32_t *seq,const struct pp_path *path,struct nq_store *store,struct mq_identity *id,struct so_owner *packets,const struct pair_plan *plan){
 if(!held||held->flow.initialized||held->flow.started)return SA_REFUSED;
 return paired(held,p,o,f,seq,path,store,id,packets,plan);
}
