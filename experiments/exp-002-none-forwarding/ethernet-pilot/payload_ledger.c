#include "payload_geometry.h"
#include "payload_ledger.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
static const unsigned rows[5]={3,4,1,6,7};
static int bad(struct el_ledger *l,int e){if(!l->primary)l->primary=e;if(l->pool&&!l->pool->primary)l->pool->primary=e;return l->primary;}
static void frontier(struct el_ledger *l,uint64_t n){if(n>l->clock_frontier)l->clock_frontier=n;}
static void raw_frontier(struct el_ledger *l,const struct es_raw *r){
 if(r->before<l->clock_frontier||r->after<r->before)l->clock_regressed=1;
 frontier(l,r->before);frontier(l,r->after);
}
static int room(struct rp_pool *p,unsigned row,struct rp_amount a){
 struct rp_amount u=p->used[row];struct rp_limit limit=rp_limits[row];
 return u.slots<=limit.count&&a.slots<=limit.count-u.slots&&u.body<=limit.count*limit.body&&a.body<=limit.count*limit.body-u.body&&u.encoded<=limit.count*(limit.body+limit.header)&&a.encoded<=limit.count*(limit.body+limit.header)-u.encoded;
}
static void add(struct rp_amount *v,struct rp_amount a){v->slots+=a.slots;v->body+=a.body;v->encoded+=a.encoded;}
static void release(struct el_ledger *l,unsigned i){struct rp_amount *u=&l->pool->used[rows[i]],a=l->held[i];u->slots-=a.slots;u->body-=a.body;u->encoded-=a.encoded;memset(&l->held[i],0,sizeof(l->held[i]));}
int el_init(struct el_ledger *l,struct rp_pool *p,unsigned char *arena,size_t cap,const struct ep_packet *requests,const struct ew_link *link){
 if(!l||l->pool||!p||!p->initialized||p->primary||!arena||cap<7440||!requests||!link)return -EINVAL;
 for(unsigned i=0;i<EP_COUNT;i++)if(!requests[i].bytes||requests[i].len!=EG_REQUEST)return -EINVAL;
 unsigned slot;for(slot=0;slot<16&&(p->tickets[slot].active||p->tickets[slot].observation_identity);slot++);
 if(slot==16||p->next_id==UINT64_MAX||p->tickets[slot].generation==UINT64_MAX||p->commands[0]>=1792||p->facts[0]>=768||p->used[9].slots>=984||!room(p,8,(struct rp_amount){0,3072,3072})||!room(p,9,(struct rp_amount){1,2048,2048}))return -ENOSPC;
 struct rp_ticket *t=&p->tickets[slot];uint64_t gen=t->generation+1;memset(t,0,sizeof(*t));t->generation=gen;t->id=++p->next_id;t->active=1;t->raw_row=UINT_MAX;
 add(&p->used[8],(struct rp_amount){0,3072,3072});add(&p->used[9],(struct rp_amount){1,2048,2048});p->commands[0]++;p->facts[0]++;
 l->id=t->id;l->generation=t->generation;l->pool=p;l->ticket=slot;l->arena=arena;l->capacity=cap;l->requests=requests;l->link=*link;return 0;
}
static int overlap(const void *a,size_t an,const void *b,size_t bn){
 uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
 return an>UINTPTR_MAX-x||bn>UINTPTR_MAX-y||(x<y+bn&&y<x+an);
}
int el_compact_stride_init(struct el_ledger *l,struct rp_pool *p,unsigned char *arena,size_t cap,const struct ep_packet *requests,const struct ew_link *link,unsigned char *frames,size_t stride){
 if(!frames||!requests||!arena||stride<1104||stride>EP_SLOT||cap>EL_COMPACT_BYTES||overlap(arena,cap,frames,EP_COUNT*stride))return -EINVAL;
 for(unsigned i=0;i<EP_COUNT;i++)if(overlap(requests[i].bytes,requests[i].len,arena,cap)||overlap(requests[i].bytes,requests[i].len,frames,EP_COUNT*stride))return -EINVAL;
 int rc=el_init(l,p,arena,cap,requests,link);if(!rc){l->frames=frames;l->frame_stride=stride;}return rc;
}
int el_bind_ingress(struct el_ledger *l,unsigned char frames[EP_COUNT][1146],unsigned char headers[EP_COUNT][64],const struct ew_link *link){
 if(!l||!l->pool)return -EINVAL;
 if(l->ingress||l->primary||l->pool->primary||l->stage||l->records||l->finished||!l->frames||!frames||!headers||!link||!link->netns||!link->epoch||!link->ifindex||link->ifindex>INT_MAX||(link->direction!=1&&link->direction!=2))return bad(l,-EINVAL);
 const void *a[2]={frames,headers};size_t z[2]={EP_COUNT*1146u,EP_COUNT*64u};
 if(overlap(frames,z[0],headers,z[1]))return bad(l,-EINVAL);
 for(unsigned k=0;k<2;k++){
  if(overlap(a[k],z[k],l,sizeof(*l))||overlap(a[k],z[k],l->arena,l->capacity)||overlap(a[k],z[k],l->frames,EP_COUNT*l->frame_stride))return bad(l,-EINVAL);
  for(unsigned i=0;i<EP_COUNT;i++)if(overlap(a[k],z[k],l->requests[i].bytes,l->requests[i].len))return bad(l,-EINVAL);
 }
 l->ingress=frames;l->ingress_headers=headers;l->ingress_link=*link;return 0;
}
int el_reserve(void *v,unsigned index,size_t tx,size_t ack,size_t frame){
 struct el_ledger *l=v;if(!l||!l->pool)return -EINVAL;
 if(l->primary||l->pool->primary||l->finished||l->stage||index!=l->index||index>=EP_COUNT||tx!=EG_REQUEST||ack!=4096||frame!=1984)return bad(l,-EPROTO);
 struct rp_amount a[5]={{1,1168,1232},{1,36,100},{1,1104,1168},{1,4096,4160},{1,1984,2048}};
 if(l->length>l->capacity||7440>l->capacity-l->length)return bad(l,-ENOSPC);
 for(unsigned i=0;i<5;i++)if(!room(l->pool,rows[i],a[i]))return bad(l,-ENOSPC);
 if(l->ingress&&(l->ingress_count!=index||!room(l->pool,0,(struct rp_amount){1,1146,1210})||!room(l->pool,7,(struct rp_amount){2,3968,4096})))return bad(l,-ENOSPC);
 for(unsigned i=0;i<5;i++){l->held[i]=a[i];add(&l->pool->used[rows[i]],a[i]);}
 if(l->ingress){l->ingress_held[0]=(struct rp_amount){1,1146,1210};l->ingress_held[1]=(struct rp_amount){1,1984,2048};add(&l->pool->used[0],l->ingress_held[0]);add(&l->pool->used[7],l->ingress_held[1]);}
 l->stage=1;return 0;
}
static uint32_t u32(const unsigned char *b){uint32_t v;memcpy(&v,b,4);return v;}
static uint16_t u16(const unsigned char *b){uint16_t v;memcpy(&v,b,2);return v;}
static void put(unsigned char *b,uint64_t n,unsigned count){for(unsigned i=0;i<count;i++){b[count-1-i]=(unsigned char)n;n>>=8;}}
static uint64_t get(const unsigned char *b,unsigned count){uint64_t v=0;for(unsigned i=0;i<count;i++)v=(v<<8)|b[i];return v;}
static int normal_ack(struct el_ledger *l,const struct es_raw *r){
 const unsigned char *b=r->bytes;const struct ep_packet *q=&l->requests[l->index];struct sockaddr_nl a={0};
 if(r->address_length!=sizeof(a))return 0;
 memcpy(&a,r->address,sizeof(a));
 return !r->error&&!r->flags&&r->kept==36&&r->reported==36&&u32(b)==36&&u16(b+4)==NLMSG_ERROR&&(u16(b+6)==0||u16(b+6)==256)&&!u32(b+16)&&q->len==EG_REQUEST&&!memcmp(b+8,q->bytes+8,8)&&!memcmp(b+20,q->bytes,16)&&a.nl_family==AF_NETLINK&&!a.nl_pid&&!a.nl_groups;
}
static int normal_frame(struct el_ledger *l,const struct es_raw *r){
 struct sockaddr_ll a={0};if(r->address_length!=sizeof(a))return 0;
 memcpy(&a,r->address,sizeof(a));
 return !r->error&&!r->flags&&r->reported==EG_FRAME&&r->kept==EG_FRAME&&a.sll_family==AF_PACKET&&a.sll_ifindex==(int)l->link.ifindex&&a.sll_halen==6&&a.sll_pkttype==(l->link.direction==1?PACKET_HOST:PACKET_OUTGOING)&&!memcmp(a.sll_addr,l->link.source,6)&&!ew_envelope(&l->link,&l->link,r->bytes,r->kept,0,0);
}
static void ingress_release(struct el_ledger *l,unsigned k){
 struct rp_amount *u=&l->pool->used[k?7:0],a=l->ingress_held[k];u->slots-=a.slots;u->body-=a.body;u->encoded-=a.encoded;memset(&l->ingress_held[k],0,sizeof(a));
}
static int ingress_commit(struct el_ledger *l,const struct es_raw *r){
 if(!l->ingress||l->finished||l->stage!=4||r->index!=l->index||r->index!=l->ingress_count||r->index>=EP_COUNT||r->kept>1984||r->address_length>UINT32_MAX||r->reported!=(r->result<0?0:(size_t)r->result)||!l->ingress_held[0].slots||!l->ingress_held[1].slots)return bad(l,-EPROTO);
 for(unsigned i=20;i<32;i++)if(r->address[i])return bad(l,-EPROTO);
 /* Retain a supported return even if a reentrant caller already failed the
  * ledger. Accepted progression is independently suppressed by sticky error. */
 unsigned char *h=l->ingress_headers[r->index];memset(h,0,64);h[0]=4;put(h+1,(uint32_t)r->flags,4);put(h+5,r->index,2);put(h+7,r->kept,2);put(h+9,(uint64_t)r->result,8);put(h+17,r->before,8);put(h+25,r->after,8);put(h+33,(uint32_t)r->error,4);put(h+37,r->address_length,4);memcpy(h+41,r->address,20);
 h[61]=r->kept<=1146?3:4;memcpy(r->kept<=1146?l->ingress[r->index]:l->ingress_error,r->bytes,r->kept);
 raw_frontier(l,r);
 l->ingress_count++;l->records++;l->wire_length+=64+r->kept;
 struct sockaddr_ll a={0};if(r->address_length==sizeof(a))memcpy(&a,r->address,sizeof(a));
 const struct ew_link *link=&l->ingress_link;
 int normal=!r->error&&!r->flags&&r->kept==EG_INGRESS&&r->reported==EG_INGRESS&&r->address_length==sizeof(a)&&a.sll_family==AF_PACKET&&a.sll_ifindex==(int)link->ifindex&&a.sll_halen==6&&a.sll_pkttype==(link->direction==1?PACKET_HOST:PACKET_OUTGOING)&&!memcmp(a.sll_addr,link->source,6)&&!ew_ingress_envelope(link,link,r->bytes,r->kept,0,0);
 ingress_release(l,0);ingress_release(l,1);add(&l->pool->used[normal?0:7],(struct rp_amount){1,r->kept,64+r->kept});
 if(!normal)bad(l,r->error?r->error:-EPROTO);
 if(!l->primary)l->stage=3;
 return l->primary;
}
int el_ingress_record(const struct el_ledger *l,unsigned index,unsigned char header[64],const unsigned char **body,size_t *length){
 if(!l||!l->ingress||!header||!body||!length||index>=l->ingress_count||index>=EP_COUNT)return -EINVAL;
 const unsigned char *h=l->ingress_headers[index];size_t n=get(h+7,2);
 if(h[0]!=4||get(h+5,2)!=index||n>1984||h[62]||h[63])return -EPROTO;
 if(h[61]==3&&n<=1146)*body=l->ingress[index];
 else if(h[61]==4&&n>1146&&index+1==l->ingress_count)*body=l->ingress_error;
 else return -EPROTO;
 memcpy(header,h,64);header[61]=0;*length=n;return 0;
}
int el_commit(void *v,const struct es_raw *r){
 struct el_ledger *l=v;if(!l||!l->pool||!r)return -EINVAL;
 if(r->lane==4)return ingress_commit(l,r);
 if(l->primary||l->finished||r->index!=l->index||r->lane!=l->stage||r->lane<1||r->lane>3||r->kept>4096||l->length>l->capacity||r->address_length>UINT32_MAX||r->kept>l->capacity-l->length||64>l->capacity-l->length-r->kept)return bad(l,-EPROTO);
 /* 64-byte header retains every distinct field. Reported length is derived
  * exactly from result for receive, and from retained request bytes for send. */
 if((r->lane==1&&(r->kept!=EG_REQUEST||r->reported!=EG_REQUEST))||(r->lane!=1&&r->reported!=(r->result<0?0:(size_t)r->result)))return bad(l,-EPROTO);
 for(unsigned i=20;i<32;i++)if(r->address[i])return bad(l,-EPROTO);
 unsigned selected=r->lane==1?0:r->lane==2?(normal_ack(l,r)?1:3):(normal_frame(l,r)?2:4);
 if(r->kept>l->held[selected].body)return bad(l,-EMSGSIZE);
 unsigned ref=0;
 if(l->frames&&r->lane==1&&!memcmp(r->bytes,l->requests[r->index].bytes,r->kept))ref=1;
 if(l->frames&&r->lane==3&&r->kept<=l->frame_stride)ref=2;
 unsigned char *b=l->arena+l->length;memset(b,0,64);b[0]=(unsigned char)r->lane;put(b+1,(uint32_t)r->flags,4);put(b+5,r->index,2);put(b+7,r->kept,2);put(b+9,(uint64_t)r->result,8);put(b+17,r->before,8);put(b+25,r->after,8);put(b+33,(uint32_t)r->error,4);put(b+37,r->address_length,4);memcpy(b+41,r->address,20);b[61]=(unsigned char)ref;
 if(ref==2)memcpy(l->frames+r->index*l->frame_stride,r->bytes,r->kept);
 if(!ref)memcpy(b+64,r->bytes,r->kept);
 raw_frontier(l,r);
 l->length+=64+(ref?0:r->kept);l->wire_length+=64+r->kept;l->records++;
 struct rp_amount actual={1,r->kept,64+r->kept};release(l,selected);add(&l->pool->used[rows[selected]],actual);
 if(r->lane==2)release(l,selected==1?3:1);
 if(r->lane==3)release(l,selected==2?4:2);
 if(r->error||selected>=3){l->primary=r->error?r->error:-EPROTO;return 0;}
 if(r->lane==3){l->stage=0;l->index++;}else if(r->lane==2&&l->ingress)l->stage=4;else l->stage++;
 return 0;
}
static int finish_body(struct el_ledger *l,const struct ep_result *r){
 if(!r->valid||r->primary||r->cleanup_error||r->clock_error||l->stage||l->index!=EP_COUNT||l->records!=(l->ingress?4:3)*EP_COUNT||(l->ingress&&l->ingress_count!=EP_COUNT))return bad(l,r->primary?r->primary:-EPROTO);
 if(l->ingress){
  for(unsigned i=0;i<EP_COUNT;i++)if(memcmp(l->ingress[i]+14,l->requests[i].bytes+36,EG_INPUT))return bad(l,-EBADMSG);
 }
 return l->primary;
}
static void finish_start(struct el_ledger *l,const struct ep_result *r){
 l->finished=1;l->result=*r;
 if(r->last_clock_ns<l->clock_frontier)l->clock_regressed=1;
 frontier(l,r->last_clock_ns);frontier(l,r->start_ns);frontier(l,r->observed_end_ns);
 if(r->primary)bad(l,r->primary);
}
int el_finish(struct el_ledger *l,const struct ep_result *r){
 if(!l||!l->pool||!r)return -EINVAL;
 if(l->finished||l->ingress)return bad(l,-EINVAL);
 finish_start(l,r);return finish_body(l,r);
}
static void validation_clock(struct el_ledger *l,uint64_t n){
 if(n<l->clock_frontier)l->clock_regressed=1;
 if(l->clock_regressed||n>=l->pool->normal_end){l->validation_error=-ETIMEDOUT;bad(l,-ETIMEDOUT);}
 frontier(l,n);
}
int el_finish_ingress(struct el_ledger *l,const struct ep_result *r,uint64_t (*clock)(void *),void *arg){
 if(!l||!l->pool||!r)return -EINVAL;
 if(l->finished||!l->ingress||!clock)return bad(l,-EINVAL);
 /* Latch before the callback; reentrant finish/commit cannot clear failure. */
 finish_start(l,r);
 l->validation_before=clock(arg);validation_clock(l,l->validation_before);
 if(!l->primary)finish_body(l,&l->result);
 l->validation_after=clock(arg);validation_clock(l,l->validation_after);
 l->validation_done=1;return l->primary;
}
int el_decode(const unsigned char *b,size_t n,struct es_raw *r,size_t *used){
 if(!b||!r||!used||n<64||b[0]<1||b[0]>4)return -EINVAL;
 size_t kept=get(b+7,2);if(kept>4096||kept>n-64||get(b+5,2)>=EP_COUNT)return -EPROTO;
 memset(r,0,sizeof(*r));r->lane=b[0];r->flags=(int32_t)get(b+1,4);r->index=(unsigned)get(b+5,2);r->kept=kept;r->result=(int64_t)get(b+9,8);r->before=get(b+17,8);r->after=get(b+25,8);r->error=(int32_t)get(b+33,4);r->address_length=(unsigned)get(b+37,4);memcpy(r->address,b+41,20);memcpy(r->bytes,b+64,kept);r->reported=r->lane==1?kept:r->result<0?0:(size_t)r->result;*used=64+kept;return 0;
}

int el_record(const struct el_ledger *l,size_t at,unsigned char header[64],const unsigned char **body,size_t *length,size_t *next){
 if(!l||!header||!body||!length||!next||at>l->length||l->length-at<64)return -EINVAL;
 const unsigned char *b=l->arena+at;unsigned lane=b[0],ref=b[61];size_t index=get(b+5,2),n=get(b+7,2);
 if(lane<1||lane>3||index>=EP_COUNT||n>4096||b[62]||b[63])return -EPROTO;
 if(ref==0){if(n>l->length-at-64)return -EPROTO;*body=b+64;*next=at+64+n;}
 else if(ref==1&&l->frames&&lane==1&&n==EG_REQUEST&&l->requests[index].len==n){*body=l->requests[index].bytes;*next=at+64;}
 else if(ref==2&&l->frames&&lane==3&&n<=l->frame_stride){*body=l->frames+index*l->frame_stride;*next=at+64;}
 else return -EPROTO;
 memcpy(header,b,64);header[61]=0;*length=n;return 0;
}

int el_compact_init(struct el_ledger *l,struct rp_pool *p,unsigned char *a,size_t cap,
 const struct ep_packet *q,const struct ew_link *link,unsigned char frames[EP_COUNT][EP_SLOT]) {
 return el_compact_stride_init(l,p,a,cap,q,link,(unsigned char *)frames,EP_SLOT);
}
