#define _POSIX_C_SOURCE 200809L
#include "preliminary_data.h"
#include "preliminary_profile.h"
#include "payload_geometry.h"
#ifdef PD_WARMED
#include "raw_export.h"
static struct rx_export packed;
#endif
#include "member_catalogue.h"
#include <openssl/provider.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <stdlib.h>
static struct em_storage storage;
#ifdef PD_WARMED
_Static_assert(sizeof(storage)+sizeof(packed)+16384<=4311232,"Named data bound");
#endif
static int control_fd=-1;
static uint64_t frontier;
struct rp_pool *pd_pool(void){return &storage.pool;}
int pd_control(int fd){if(fd<3||control_fd>=0)return -EINVAL;control_fd=fd;return 0;}
static uint64_t clock_(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0)return UINT64_MAX;uint64_t n=(uint64_t)t.tv_sec*1000000000+t.tv_nsec;if(n<frontier)return UINT64_MAX;frontier=n;return n;}
static int sync_(unsigned mode,const char *event,char token){
 uint64_t end=storage.pool.normal_end;if(control_fd<0||clock_()>=end)return -ETIMEDOUT;
 if(event){fprintf(stderr,"EXP002_DATA %u %s\n",mode,event);fflush(stderr);}
 char expected[16];int len=snprintf(expected,sizeof(expected),"%c %u\n",token,mode);char b[16];size_t used=0;
 while(used<(size_t)len){uint64_t n=clock_();if(n>=end)return -ETIMEDOUT;struct pollfd p={control_fd,POLLIN,0};int rc=poll(&p,1,(int)((end-n)/1000000));if(rc!=1||clock_()>=end)return -ETIMEDOUT;ssize_t z=read(control_fd,b+used,(size_t)len-used);if(z<=0)return -EIO;used+=(size_t)z;}
 return memcmp(b,expected,(size_t)len)?-EPROTO:0;
}
int pd_handshake(void){static unsigned stage=3;if(stage>5)return -EPROTO;return sync_(stage++,"READY",'G');}
static void hex(const unsigned char *b,size_t n){putchar('"');for(size_t i=0;i<n;i++)printf("%02x",b[i]);putchar('"');}
/* Lossless post-measurement encoding; no compression or discarded evidence. */
void pd_body64(const unsigned char *b,size_t n){
 static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 putchar('"');
 for(size_t i=0;i<n;i+=3){
  unsigned x=(unsigned)b[i]<<16;
  if(i+1<n)x|=(unsigned)b[i+1]<<8;
  if(i+2<n)x|=b[i+2];
  putchar(alphabet[x>>18]);putchar(alphabet[(x>>12)&63]);
  putchar(i+1<n?alphabet[(x>>6)&63]:'=');putchar(i+2<n?alphabet[x&63]:'=');
 }
 putchar('"');
}
static int snapshot(void){
 unsigned char b[8192];int fd=open("/proc/net/prp/annex",O_RDONLY|O_CLOEXEC);if(fd<0)return -errno;
 ssize_t n=read(fd,b,sizeof(b));int e=errno;int rc=close(fd);if(n<0)return -e;if(n==(ssize_t)sizeof(b)||rc||clock_()>=storage.pool.normal_end)return -EIO;hex(b,(size_t)n);return 0;
}
static int policy(const char *name,int value){
 char path[128],text[16];snprintf(path,sizeof(path),"/proc/sys/net/prp/%s",name);int n=snprintf(text,sizeof(text),"%d\n",value);
 if(clock_()>=storage.pool.normal_end)return -ETIMEDOUT;
 int fd=open(path,O_WRONLY|O_CLOEXEC);if(fd<0)return -errno;ssize_t written=write(fd,text,(size_t)n);int e=errno,closed=close(fd);if(written!=n||closed)return written<0?-e:-EIO;
 fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return -errno;char b[16]={0};ssize_t got=read(fd,b,sizeof(b)-1);closed=close(fd);if(got<=0||closed||strcmp(b,text)||clock_()>=storage.pool.normal_end)return -EIO;return 0;
}
static int cleanup(void *v){(void)v;return 0; /* Socket owner closes after route cleanup. */}
static int valid(struct sf_flow *a,struct sf_flow *d){struct rp_handle x,y;return !sf_active_ticket(a,&x)&&!sf_active_ticket(d,&y)&&x.pool==&storage.pool&&y.pool==&storage.pool;}
int pd_run(struct sf_flow *a,struct sf_flow *d,struct so_owner *o,struct so_owner *packets,uint16_t family,uint32_t *seq,const struct pair_plan *plan){
 int rc=0;struct em_preparation prep={0};struct ep_io io={0};
#ifdef PD_REFERENCE_ONLY
 printf(",\"preliminary\":{\"schema\":\"EXP002-REFERENCE-DATA-1\",\"records_per_mode\":%u,\"warmup_records\":%u,\"payload_bytes\":%u,\"pilot\":false,\"order\":[%u],\"runs\":[",PD_MEASURED,PD_WARMUP,EG_PAYLOAD,pd_mode(1));
#else
 printf(",\"preliminary\":{\"schema\":\"EXP002-SHORT-DATA-2\",\"records_per_mode\":%u,\"warmup_records\":%u,\"payload_bytes\":%u,\"pilot\":false,\"order\":[%u,%u],\"runs\":[",PD_MEASURED,PD_WARMUP,EG_PAYLOAD,pd_mode(1),pd_mode(2));
#endif
 if(!valid(a,d)||!seq||*seq>UINT32_MAX-EP_COUNT||control_fd<0){rc=-EINVAL;goto done;}
 if(plan->role==2){
  struct ew_tx tx={family,*seq+1,o->plan.binding,a->active.peer};struct ew_link link={.netns=o->plan.netns_ino,.epoch=o->plan.epoch,.ifindex=packets[1].plan.binding,.direction=1};
  struct ew_link in={.netns=o->plan.netns_ino,.epoch=o->plan.epoch,.ifindex=packets[0].plan.binding,.direction=2};
  memcpy(link.source,plan->remote_second,6);memcpy(link.destination,plan->local_second,6);memcpy(in.source,plan->local,6);memcpy(in.destination,plan->remote,6);
  OSSL_LIB_CTX *lib=OSSL_LIB_CTX_new();EVP_MD *md=NULL;
  if(!lib||OSSL_LIB_CTX_load_config(lib,NULL)!=1||EVP_default_properties_is_fips_enabled(lib))rc=-EACCES;
  if(!rc){md=EVP_MD_fetch(lib,"SHA256","provider=default");if(!md||strcmp(OSSL_PROVIDER_get0_name(EVP_MD_get0_provider(md)),"default"))rc=-EACCES;}
  if(!rc)rc=ec_prepare(&prep,&storage,0,&tx,&link,md);
  EVP_MD_free(md);OSSL_LIB_CTX_free(lib);if(rc)goto done;
  struct es_ports ports={el_reserve,el_commit,cleanup,&storage.ledger};
  rc=es_init(&storage.backend,o->fd,packets[1].fd,storage.inputs,storage.tx,&link,&tx,storage.pool.normal_end,&ports);
  if(!rc)rc=es_bind_ingress(&storage.backend,packets[0].fd,&in);
  if(!rc)rc=el_compact_stride_init(&storage.ledger,&storage.pool,storage.custody,sizeof(storage.custody),storage.tx,&link,(unsigned char *)storage.received,1104);
  if(!rc)rc=el_bind_ingress(&storage.ledger,storage.ingress,storage.ingress_metadata,&in);
  if(rc)goto done;
  io=es_operations(&storage.backend);*seq+=EP_COUNT;
 }
 for(unsigned phase=1;phase<=PD_PHASES&&!rc;phase++){
  unsigned mode=pd_mode(phase);
  if(phase>1)putchar(',');
  printf("{\"mode\":%u",mode);
  if(plan->role==1){rc=policy("assembly_records",1);if(!rc)rc=policy("assembly_delay_ms",100);if(!rc)rc=policy("verify_annex",PD_VERIFY_ANNEX);if(!rc)rc=policy("assembly_mode",(int)mode);printf(",\"before\":");if(!rc)rc=snapshot();else printf("null");}
  if(!rc)rc=sync_(phase,"READY",'G');
  if(!rc&&!valid(a,d))rc=-ESTALE;
  if(!rc&&plan->role==2){
   uint64_t begin=io.now(io.ctx),last=begin;unsigned received=0;
   for(unsigned j=0;j<PD_PER_MODE&&!rc;j++){
    if(j==PD_WARMUP)begin=io.now(io.ctx);
    unsigned i=(phase-1)*PD_PER_MODE+j;uint64_t now=io.now(io.ctx),end=now+40000000ULL;if(now>=storage.pool.normal_end||end>=storage.pool.normal_end||!valid(a,d)){rc=-ETIMEDOUT;break;}
    int n=io.send(io.ctx,storage.inputs[i].bytes,EG_INPUT,end);if(n!=EG_INPUT){rc=n<0?n:-EIO;break;}
    n=io.receive(io.ctx,storage.received[i],1104,end);last=io.now(io.ctx);storage.lengths[i]=n>0?(size_t)n:0;
    if(n!=EG_FRAME||last<now||last>=end||!valid(a,d)){rc=n<0?n:-EPROTO;break;}
#ifndef PD_POST_VERIFY
    if(memcmp(storage.received[i],storage.expected[0],24)||memcmp(storage.received[i]+24,storage.inputs[i].bytes+52,EG_SUFFIX)||memcmp(storage.ingress[i]+14,storage.inputs[i].bytes,EG_INPUT)){rc=-EBADMSG;break;}
#endif
    if(j>=PD_WARMUP)received++;
   }
#ifdef PD_POST_VERIFY
   /* All received bytes remain in exclusive array slots. This oracle runs
      after the final receive timestamp; failures invalidate the whole phase. */
   if(!rc)for(unsigned j=0;j<PD_PER_MODE;j++){
    unsigned i=(phase-1)*PD_PER_MODE+j;
    if(storage.lengths[i]!=EG_FRAME||memcmp(storage.received[i],storage.expected[0],24)||memcmp(storage.received[i]+24,storage.inputs[i].bytes+52,EG_SUFFIX)||memcmp(storage.ingress[i]+14,storage.inputs[i].bytes,EG_INPUT)){rc=-EBADMSG;break;}
   }
#endif
   printf(",\"begin_ns\":%llu,\"last_receive_ns\":%llu,\"received\":%u,\"verified_bytes\":%u",(unsigned long long)begin,(unsigned long long)last,received,received*EG_PAYLOAD);
   if(!rc)rc=sync_(phase,"DONE",'N');
  }else if(!rc){rc=sync_(phase,NULL,'E');printf(",\"after\":");if(!rc)rc=snapshot();else printf("null");if(!rc)rc=sync_(phase,"DONE",'N');}
  printf(",\"primary\":%d}",rc);
 }
 done:
 /* These fields are emitted after runs, without changing historical defaults. */
#ifdef EXP002_PRP_CAPTURE
 printf("],\"capture_policy\":\"PRP_ETHERTYPE_LOCKED_V1\",\"primary\":%d,\"raw_body_encoding\":\"base64\",\"raw\":[",rc);
#else
 printf("],\"primary\":%d,\"raw_body_encoding\":\"base64\",\"raw\":[",rc);
#endif
#ifdef PD_WARMED
 /* No future receive call occurs after this point. The unoffered tail is
    never referenced by a retained record; kernel socket queues do not write it. */
 _Static_assert((EP_COUNT-PD_PHASES*PD_PER_MODE)*1104>=327680+RX_PACKED_MAX,"Unused receive tail");
 int export_error=rx_begin(&packed,storage.received[PD_PHASES*PD_PER_MODE],
                          (EP_COUNT-PD_PHASES*PD_PER_MODE)*1104);
#endif
 if(plan->role==2&&storage.ledger.pool){
  size_t at=0;unsigned count=0;while(at<storage.ledger.length){unsigned char header[64];const unsigned char *body;size_t n,next;int e=el_record(&storage.ledger,at,header,&body,&n,&next);if(e){if(!rc)rc=e;break;}
#ifdef PD_WARMED
  if(!export_error)export_error=rx_add(&packed,header,body,n);
  count++;
#else
  if(count++)putchar(',');putchar('[');hex(header,64);putchar(',');pd_body64(body,n);putchar(']');
#endif
  at=next;}
  for(unsigned i=0;i<storage.ledger.ingress_count;i++){unsigned char header[64];const unsigned char *body;size_t n;int e=el_ingress_record(&storage.ledger,i,header,&body,&n);if(e){if(!rc)rc=e;break;}
#ifdef PD_WARMED
  if(!export_error)export_error=rx_add(&packed,header,body,n);
  count++;
#else
  if(count++)putchar(',');putchar('[');hex(header,64);putchar(',');pd_body64(body,n);putchar(']');
#endif
  }
  if(io.cleanup){int e=io.cleanup(io.ctx);if(!rc)rc=e;}
 }
 printf("]");
#ifdef PD_WARMED
 size_t packed_length=0;int finish_error=rx_end(&packed,&packed_length);
 if(!export_error)export_error=finish_error;
 if(export_error&&!rc)rc=export_error;
 printf(",\"raw_codec\":\"zlib-records-v1\",\"raw_count\":%u,\"export_error\":%d,\"packed_raw\":",packed.count,export_error);
 pd_body64(packed.bytes,packed_length);
#endif
#ifdef PD_POST_VERIFY
 printf(",\"body_validation_timing\":\"POST_MEASUREMENT\"");
#else
 printf(",\"body_validation_timing\":\"IN_LOOP\"");
#endif
 printf(",\"requested_annex_verification\":%u",PD_VERIFY_ANNEX);
 printf(",\"final_error\":%d,\"native_acceptance\":false}",rc);return rc;
}
