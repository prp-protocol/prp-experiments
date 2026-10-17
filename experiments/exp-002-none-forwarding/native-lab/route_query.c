#define _POSIX_C_SOURCE 200809L
#include "route_query.h"
#ifdef PRELIMINARY_DATA
#include "preliminary_data.h"
#endif
#include "absence_query.h"
#include "control_capture.h"
#include "fanout_query.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <poll.h>
#include <errno.h>
static uint64_t clock_(void *unused){(void)unused;struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000)return UINT64_MAX;return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
static void error(int *primary,int *secondary,int rc){if(rc){if(!*primary)*primary=rc;else if(!*secondary)*secondary=rc;}}
static int direct(struct sq_query *out,struct sf_flow *parent,struct rp_pool *p,struct so_owner *o,uint16_t family,uint32_t *seq,const struct pp_path *path,struct nq_store *store,struct mq_identity *id,struct so_owner *packets,const struct pair_plan *plan){
 struct rp_handle active;struct rp_ticket *tx=rp_get(path->tx);
 if(sf_active_ticket(parent,&active)||!tx||tx->primary||!tx->transaction.accepted||tx->transaction.peer_context!=parent->active.peer||!seq||*seq>UINT32_MAX-16)return SA_IDENTITY;
 uint64_t before=clock_(NULL);if(before>=p->normal_end)return SA_TIME;
 struct nt_readback expect={.command=53,.peer=parent->active.peer,.scope=2,.alias=1};memcpy(expect.strong_id,parent->active.strong_id,32);
 struct nt_budget budget={1024,sizeof(struct nt_ledger),4,1000000};struct rp_handle h[3]={{0}};struct rn_port port[3]={0};struct nt_context c[3];int primary=0,secondary=0;
 for(unsigned i=0;i<3&&!primary;i++){
  c[i]=(struct nt_context){o->expected.ino,o->plan.epoch,o->plan.netns_ino,i==2?p->close_end:p->normal_end,++*seq,o->plan.binding,family};
  if(!rp_reserve(p,i==2,&budget,&h[i])||!rn_init(&port[i],p,&h[i],o->fd,o->expected.dev,o->expected.ino,&c[i],&budget))primary=SA_REFUSED;
 }
 if(!primary){struct nt_stream io=rn_stream(&port[0]);primary=rp_expectation(h[0],active,&c[0],&expect,&io);}
 if(!primary){expect.command=55;struct nt_stream io=rn_stream(&port[1]);primary=rp_readback(h[1],&c[1],&expect,&io);}
 if(!primary&&!nq_archive_before(store,h[1],p->normal_end))primary=SA_CALLBACK;
#ifdef PRELIMINARY_DATA
 if(!primary)primary=pd_handshake();
#endif
 struct cm_m1 captured={0};struct sb_backend hash={0};OSSL_LIB_CTX *lib=NULL;int hash_closed=1;
 if(!primary&&plan->role==2){
  lib=OSSL_LIB_CTX_new();if(!lib||OSSL_LIB_CTX_load_config(lib,NULL)!=1||EVP_default_properties_is_fips_enabled(lib))primary=SA_REFUSED;
  const OSSL_PROVIDER *provider=NULL;EVP_MD *md=!primary?EVP_MD_fetch(lib,"SHA256","provider=default"):NULL;
  if(md)provider=EVP_MD_get0_provider(md);
  if(!primary&&(!provider||strcmp(OSSL_PROVIDER_get0_name(provider),"default")))primary=SA_REFUSED;
  if(!primary){struct sb_policy hp={lib,provider,"provider=default",id->seed,32,clock_,NULL};if(!sb_init(&hash,&hp))primary=SA_REFUSED;}
  if(!primary){struct cm_direct_path cp={.parent=parent,.transfer=1,.path={.context=c[0],.peer=expect.peer,.not_before=before,.end=p->normal_end,.generation=plan->generation,.ifindex=path->ifindex}};
   memcpy(cp.path.source,plan->remote,6);memcpy(cp.path.destination,plan->local,6);memcpy(cp.path.public_key,plan->public_key,32);
   printf(",\"direct_capture\":[");primary=nc_receive_direct_m1(p,packets,store,&cp,&hash,&captured);
#ifdef PRELIMINARY_DATA
   if(!primary){putchar(',');primary=nc_quiet(p,packets,store);}
#endif
   printf("]");
  }
  hash_closed=!hash.initialized||sb_destroy(&hash);if(!hash_closed)error(&primary,&secondary,SA_TIME);EVP_MD_free(md);
 }
 struct mq_result result={0};
 if(!primary){struct nt_selection selection={0};selection.match=expect;selection.match.command=14;selection.match.state=1;selection.match.direction=3;selection.match.generation=plan->generation;selection.population=3;selection.not_before=before;selection.valid_until=p->normal_end;
  printf(",\"direct_exchange\":[");primary=mq_direct_hold(p,o,family,seq,path->tx,store,id,parent,plan->role==1?1:2,plan->role==2?&captured:NULL,&selection,out,&result);printf("]");
 }
 if(lib&&hash_closed)OSSL_LIB_CTX_free(lib);
 struct rp_ticket *set=rp_get(h[0]);if(set&&set->transaction.possible&&h[2].pool){expect.command=54;struct nt_stream io=rn_stream(&port[2]);error(&primary,&secondary,rp_expectation(h[2],h[0],&c[2],&expect,&io));}
 for(unsigned i=0;i<3;i++){struct rp_ticket *t=rp_get(h[i]);if(t&&t->ran&&!t->persist_attempted&&!nq_archive(store,h[i]))error(&primary,&secondary,SA_CALLBACK);}
 return primary?primary:secondary;
}
int rq_run(struct rp_pool *p,struct so_owner *o,uint16_t family,uint32_t *seq,struct pp_path paths[2],struct nq_store *store,struct mq_identity *identity,struct mq_identity *second_identity,struct so_owner *packets,const struct pair_plan *plan){
 if(!p||!p->initialized||p->primary||!paths||!store||store->files.pool!=p||!identity||!plan||plan->links!=2||plan->generation!=1||(plan->role!=1&&plan->role!=2)||!o||!seq||*seq>UINT32_MAX-64||paths[0].ifindex==paths[1].ifindex||(plan->role==2&&(!packets||!second_identity)))return SA_IDENTITY;
 struct mq_identity master=*identity,second=plan->role==2?*second_identity:*identity;OPENSSL_cleanse(identity->seed,32);if(second_identity)OPENSSL_cleanse(second_identity->seed,32);
 struct sq_query adjacent[2]={0},recursive={0};struct fq_query fanout={0};struct aq_result baseline={0};int primary=0,secondary=0;unsigned opened=0;
 printf("{\"schema\":\"EXP002-PAIRED-ROUTE-1\",\"role\":%u,\"empty_baseline\":",plan->role);primary=aq_run(&baseline,p,o,family,seq,store);
 printf(",\"adjacent\":[");
 for(unsigned i=0;i<2&&!primary;i++){
  struct pair_plan link=*plan;link.links=1;if(i){memcpy(link.local,plan->local_second,6);memcpy(link.remote,plan->remote_second,6);memcpy(link.public_key,plan->public_key_second,32);}
  struct mq_identity owned=i?second:master;if(i)putchar(',');putchar('[');primary=pq_hold(&adjacent[i],p,o,family,seq,&paths[i],store,&owned,packets,&link);OPENSSL_cleanse(owned.seed,32);putchar(']');opened=i+1;
 }
 printf("]");
 if(!primary&&!nq_archive_before(store,paths[1].tx,p->normal_end))primary=SA_CALLBACK;
 struct mq_identity owned=master;
 if(!primary)primary=direct(&recursive,&adjacent[0].flow,p,o,family,seq,&paths[0],store,&owned,packets,plan);
 OPENSSL_cleanse(owned.seed,32);OPENSSL_cleanse(master.seed,32);OPENSSL_cleanse(second.seed,32);
 /* Configure only after DIRECT activation: the mapping's two retained tickets
  * must not overlap the handshake peak. No payload was submitted before this. */
 if(!primary&&plan->role==1){struct nt_fanout map={.peer=adjacent[1].flow.active.peer,.generation=1,.max_members=1};primary=fq_open(&fanout,o,family,seq,&adjacent[1].flow,&map);if(!primary)primary=fq_checkpoint(&fanout,store);printf(",\"fanout\":{\"peer\":%llu,\"primary\":%d}",(unsigned long long)map.peer,primary);}

 struct rp_handle selected={0};int ready=!primary&&!sf_active_ticket(&adjacent[0].flow,&selected)&&!sf_active_ticket(&adjacent[1].flow,&selected)&&!sf_active_ticket(&recursive.flow,&selected);
 if(!primary&&!ready)primary=SA_IDENTITY;
 printf(",\"active_receipts\":[");
 if(ready){
  struct rp_handle records[4];unsigned n=3;int rc=sf_active_ticket(&adjacent[0].flow,&records[0]);if(!rc)rc=sf_active_ticket(&adjacent[1].flow,&records[1]);if(!rc)rc=sf_active_ticket(&recursive.flow,&records[2]);
  if(!rc&&plan->role==1){rc=ff_mapping_ticket(&fanout.flow,&records[3]);n=4;}
  error(&primary,&secondary,rc);
  for(unsigned i=0;i<n&&!primary;i++){struct rp_ticket *t=rp_get(records[i]);if(!t||clock_(NULL)>=p->normal_end||(!t->length&&!rp_encode(records[i],NULL))){primary=SA_REFUSED;break;}if(i)putchar(',');printf("{\"id\":%llu,\"generation\":%llu,",(unsigned long long)records[i].id,(unsigned long long)records[i].generation);
#ifdef PRELIMINARY_DATA
   printf("\"receipt_encoding\":\"base64\",\"receipt\":");pd_body64(t->receipt,t->length);
#else
   printf("\"receipt\":\"");for(size_t j=0;j<t->length;j++)printf("%02x",t->receipt[j]);putchar('"');
#endif
   putchar('}');}
  if(clock_(NULL)>=p->normal_end)error(&primary,&secondary,SA_TIME);
 }
 printf("]");

#ifdef PRELIMINARY_DATA
 if(!primary&&plan->role==2){printf(",\"payload_quiet\":");primary=nc_quiet(p,packets,store);}
 if(!primary)primary=pd_run(&adjacent[0].flow,&recursive.flow,o,packets,family,seq,plan);
#else
 /* Preserve owned state through the original normal boundary. This is not
  * a readiness handshake with the peer or authority for an unobserved payload. */
 if(!primary){uint64_t before=clock_(NULL);if(before>=p->normal_end)primary=SA_TIME;else {uint64_t left=p->normal_end-before;int rc=poll(NULL,0,(int)(left/1000000+(left%1000000!=0)));uint64_t after=clock_(NULL);if(rc||after<before||after>=p->close_end)primary=SA_TIME;}}
 #endif
 if(recursive.flow.initialized&&!recursive.flow.finished)error(&primary,&secondary,sq_close(&recursive,store));
 if(fanout.flow.parent.pool)error(&primary,&secondary,fq_close(&fanout,store));
 for(unsigned i=opened;i;i--)if(adjacent[i-1].flow.initialized&&!adjacent[i-1].flow.finished)error(&primary,&secondary,sq_close(&adjacent[i-1],store));
 printf(",\"local_sessions_observed\":%s,\"direct_delete_ack\":%s,\"primary\":%d,\"secondary\":%d,\"payload_delivered\":false}",ready?"true":"false",recursive.flow.delete_ack?"true":"false",primary,secondary);
 return primary?primary:secondary;
}
