#include "reservations.h"
#include <string.h>
#include <limits.h>
const struct rp_limit rp_limits[13]={
{8448,1146,64},
{8448,1104,64},
{512,1984,64},
{8448,1168,64},
{8448,36,64},
{4096,4096,64},
{16,4096,64},
{16,4096,64},
{1,5242880,0},
{1024,2048,0},
{2048,4096,64},
{1,33554432,0},
{256,4096,0},
};
int rp_init(struct rp_pool *p,uint64_t normal_end,uint64_t close_end){if(!p||p->initialized||!normal_end||close_end<=normal_end)return 0;p->normal_end=normal_end;p->close_end=close_end;p->initialized=1;return 1;}
static int bad(struct rp_ticket *t,int e){t->revision++;if(t->transaction.started&&!t->transaction.primary)t->transaction.primary=e;if(!t->primary)t->primary=e;else if(!t->secondary)t->secondary=e;return t->primary;}
struct rp_ticket *rp_get(struct rp_handle h){if(!h.pool||h.slot>=RP_TICKETS)return NULL;struct rp_ticket *t=&h.pool->tickets[h.slot];return t->active&&t->generation==h.generation&&t->id==h.id?t:NULL;}
static int room(struct rp_pool *p,unsigned row,struct rp_amount a){struct rp_amount u=p->used[row];const struct rp_limit *l=&rp_limits[row];return u.slots<=l->count&&a.slots<=l->count-u.slots&&u.body<=l->count*l->body&&a.body<=l->count*l->body-u.body&&u.encoded<=l->count*(l->body+l->header)&&a.encoded<=l->count*(l->body+l->header)-u.encoded;}
int rp_reserve_local_pair(struct rp_pool *p,unsigned final_close,struct rp_handle h[2]){
 if(!p||!p->initialized||p->primary||!h||final_close>1)return 0;
 unsigned slots[2],found=0;
 for(unsigned i=0;i<RP_TICKETS&&found<2;i++)if(!p->tickets[i].active&&!p->tickets[i].observation_identity&&p->tickets[i].generation!=UINT64_MAX)slots[found++]=i;
 unsigned normal=final_close?1:2,final=final_close;
 struct rp_amount metadata={0,6144,6144},terminal={2,4096,4096};
 if(found!=2||p->next_id>UINT64_MAX-2||p->commands[0]>1792-normal||p->facts[0]>768-normal||p->commands[1]>256-final||p->facts[1]>256-final||p->used[9].slots>982||!room(p,8,metadata)||!room(p,9,terminal)){
  if(!p->primary)p->primary=SA_REFUSED;
  return 0;
 }
 for(unsigned i=0;i<2;i++){
  struct rp_ticket *t=&p->tickets[slots[i]];uint64_t generation=t->generation+1;
  memset(t,0,sizeof(*t));t->generation=generation;t->id=++p->next_id;t->active=1;t->final=i?final_close:0;t->commands=t->facts=1;
  /* Row8 is metadata, not a raw transport row. held[0] stays exactly zero. */
  t->raw_row=8;t->held[1]=(struct rp_amount){0,3072,3072};t->held[2]=(struct rp_amount){1,2048,2048};
  p->commands[t->final]++;p->facts[t->final]++;
  h[i]=(struct rp_handle){p,slots[i],generation,t->id};
 }
 p->used[8].body+=metadata.body;p->used[8].encoded+=metadata.encoded;
 p->used[9].slots+=terminal.slots;p->used[9].body+=terminal.body;p->used[9].encoded+=terminal.encoded;
 return 1;
}
int rp_reserve(struct rp_pool *p,unsigned final,const struct nt_budget *b,struct rp_handle *h){return rp_reserve_tx(p,final,b,256,h);}
static int reserve_row(struct rp_pool *p,unsigned final,const struct nt_budget *b,size_t tx,unsigned row,struct rp_handle *h);
int rp_reserve_tx(struct rp_pool *p,unsigned final,const struct nt_budget *b,size_t tx,struct rp_handle *h){return reserve_row(p,final,b,tx,5,h);}
int rp_reserve_capture(struct rp_pool *p,unsigned final,struct rp_handle *h){struct nt_budget b={1984,sizeof(struct nt_ledger),1,1};return reserve_row(p,final,&b,20,2,h);}
static int reserve_row(struct rp_pool *p,unsigned final,const struct nt_budget *b,size_t tx,unsigned row,struct rp_handle *h){
 if(!p||!p->initialized||!b||!h||final>1)return 0;
 if(p->primary&&!final)return 0;
 if(tx<20||tx>264||!b->calls||b->calls>8||!b->body_bytes||b->body_bytes>4096||!b->ticks_per_ms||b->metadata_bytes<sizeof(struct nt_ledger)-sizeof(((struct nt_ledger *)0)->records)+b->calls*sizeof(struct nt_record))goto refused;
 unsigned slot;for(slot=0;slot<16&&(p->tickets[slot].active||p->tickets[slot].observation_identity);slot++);
 if(slot==16||p->next_id==UINT64_MAX||p->tickets[slot].generation==UINT64_MAX)goto refused;
 uint64_t setups=b->calls+1,cmdmax=final?256:1792,factmax=final?256:768,setupmax=final?512:3584;
 struct rp_amount a[3]={{setups,b->body_bytes+tx,b->body_bytes+tx+64*setups},{0,3072,3072},{1,2048,2048}};
 if(row==2){setups=1;setupmax=final?128:384;a[0]=(struct rp_amount){1,1984,2048};}
 uint64_t population=row==2?p->captures[final]:p->setup[final];
 if(p->commands[final]>=cmdmax||p->facts[final]>=factmax||population>setupmax||setups>setupmax-population||p->used[9].slots>=984||!room(p,row,a[0])||!room(p,8,a[1])||!room(p,9,a[2]))goto refused;
 struct rp_ticket *t=&p->tickets[slot];uint64_t generation=t->generation+1;memset(t,0,sizeof(*t));t->generation=generation;t->id=++p->next_id;t->active=1;t->final=final;t->commands=t->facts=1;t->budget=*b;t->tx_reserved=tx;t->raw_row=row;
 unsigned rows[]={row,8,9};for(unsigned i=0;i<3;i++){t->held[i]=a[i];p->used[rows[i]].slots+=a[i].slots;p->used[rows[i]].body+=a[i].body;p->used[rows[i]].encoded+=a[i].encoded;}
 p->commands[final]++;p->facts[final]++;if(row==2)p->captures[final]+=setups;else p->setup[final]+=setups;*h=(struct rp_handle){p,slot,generation,t->id};return 1;
 refused:if(!p->primary)p->primary=SA_REFUSED;return 0;
}
static struct rp_ticket *admit(struct rp_handle h){struct rp_ticket *t=rp_get(h);if(!t)return NULL;if(t->busy||t->ran||t->primary||t->final||t->raw_row!=5){bad(t,t->busy?SA_REENTRY:SA_REPEAT);return NULL;}t->ran=1;t->busy=1;return t;}
struct flow {struct rp_handle h;struct nt_stream original;};
static void flow_guard(struct flow *f){struct rp_ticket *t=rp_get(f->h);if(t&&f->h.pool->primary&&!t->final)bad(t,f->h.pool->primary);}
static uint64_t flow_clock(void *v){struct flow *f=v;flow_guard(f);uint64_t t=f->original.clock(f->original.arg);flow_guard(f);return t;}
static int flow_send(void *v,const unsigned char *p,size_t n){struct flow *f=v;flow_guard(f);struct rp_ticket *t=rp_get(f->h);if(!t||t->primary)return -1;if(n>t->tx_reserved){bad(t,SA_REFUSED);return -1;}return f->original.send(f->original.arg,p,n);}
static void flow_receive(void *v,size_t n,struct nt_reply *r){struct flow *f=v;flow_guard(f);struct rp_ticket *t=rp_get(f->h);if(!t||t->primary){r->rc=-1;return;}f->original.receive(f->original.arg,n,r);}
int rp_prepare(struct rp_handle h,const struct nt_context *c,const struct nt_prepare *p,const struct nt_stream *o){struct rp_ticket *t=admit(h);if(!t)return SA_REFUSED;if(!c||c->deadline>h.pool->normal_end||!o||!o->clock||!o->send||!o->receive){t->busy=0;return bad(t,SA_REFUSED);}struct flow f={h,*o};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};int rc=nt_prepare_stream(&t->transaction,&t->ledger,&t->budget,c,p,&wrap);t->prepared=!rc&&t->transaction.accepted;if(rc)bad(t,rc);if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;t->busy=0;return t->primary;}
int rp_commit(struct rp_handle h,const struct nt_context *c,uint64_t handle,const struct sc_client *s,const struct nt_stream *o){struct rp_ticket *t=admit(h);if(!t)return SA_REFUSED;if(!c||c->deadline>h.pool->normal_end||!o||!o->clock||!o->send||!o->receive){t->busy=0;return bad(t,SA_REFUSED);}struct flow f={h,*o};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};int rc=nt_commit_stream(&t->transaction,&t->ledger,&t->budget,c,handle,s,&wrap);if(rc)bad(t,rc);if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;t->busy=0;return t->primary;}
struct sign_flow {struct rp_handle h;struct sc_client *client;struct sa_ops original;uint64_t seen;};
static void sign_guard(struct sign_flow *f){struct rp_ticket *t=rp_get(f->h);if(!t)return;if(f->h.pool->primary&&!t->primary)bad(t,f->h.pool->primary);if(t->revision!=f->seen){f->seen=t->revision;if(!f->client->signer.primary)f->client->signer.primary=t->primary?t->primary:SA_REFUSED;f->client->signer.failure_revision++;}}
static uint64_t sign_clock(void *v){struct sign_flow *f=v;sign_guard(f);uint64_t t=f->original.clock(f->original.arg);sign_guard(f);return t;}
static void sign_step(void *v,const struct sa_input *i,struct sa_output *o){struct sign_flow *f=v;sign_guard(f);if(i->stage!=SA_CLOSE&&f->client->signer.primary){o->rc=0;return;}f->original.step(f->original.arg,i,o);sign_guard(f);}
int rp_sign(struct rp_handle h,const struct nt_context *c,const struct nt_prepare *p,struct sc_client *client,const struct sa_policy *policy,const unsigned char binding[32],uint32_t generation,const struct sa_ops *ops){
 struct rp_ticket *t=rp_get(h);if(!t)return SA_REFUSED;
 if(t->busy||t->sign_attempted||t->persist_attempted||t->length||t->primary||!t->ran||!t->facts||!client||!ops||!ops->clock||!ops->step)return bad(t,SA_REFUSED);
 t->bound_client=client;t->sign_attempted=1;t->busy=1;struct sign_flow f={h,client,*ops,t->revision};struct sa_ops wrap={sign_clock,sign_step,&f};
 int rc=nt_sign_prepared(&t->transaction,c,p,client,policy,binding,generation,&wrap);if(rc)bad(t,rc);if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}
int rp_sign_m2(struct rp_handle h,const struct nt_context *c,const struct nt_prepare *p,struct sc_client *client,const struct sa_policy *policy,const struct nt_remote_m1 *remote,const unsigned char *wire,size_t n,struct sb_backend *verifier,const struct sa_ops *ops){
 struct rp_ticket *t=rp_get(h);if(!t)return SA_REFUSED;
 if(t->busy||t->sign_attempted||t->persist_attempted||t->length||t->primary||!t->ran||!t->facts||!client||!ops||!ops->clock||!ops->step)return bad(t,SA_REFUSED);
 t->bound_client=client;t->sign_attempted=1;t->busy=1;struct sign_flow f={h,client,*ops,t->revision};struct sa_ops wrap={sign_clock,sign_step,&f};
 int rc=nt_sign_m2(&t->transaction,c,p,client,policy,remote,wire,n,verifier,&wrap);if(rc)bad(t,rc);if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}
int rp_cancel(struct rp_handle h,struct rp_handle original,const struct nt_context *c,const struct nt_stream *o){
 struct rp_ticket *t=rp_get(h),*pre=rp_get(original);if(!t)return SA_REFUSED;
 if(t->busy||t->ran||t->raw_row!=5||!t->final||!pre||original.pool!=h.pool||pre==t||pre->cancel_attempted||pre->commit_attempted||!pre->prepared||pre->transaction.request[16]!=16||!pre->transaction.handle||!c||c->deadline>h.pool->close_end||c->socket!=pre->transaction.bound.socket||c->epoch!=pre->transaction.bound.epoch||c->netns!=pre->transaction.bound.netns||c->family!=pre->transaction.bound.family||c->port!=pre->transaction.bound.port||c->seq==pre->transaction.bound.seq||!o||!o->clock||!o->send||!o->receive)return bad(t,SA_REFUSED);
 pre->cancel_attempted=1;t->ran=1;t->busy=1;t->transaction.last=pre->transaction.last;
 struct flow f={h,*o};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};int rc=nt_cancel_stream(&t->transaction,&t->ledger,&t->budget,c,pre->transaction.handle,&wrap);if(rc)bad(t,rc);t->busy=0;return t->primary;
}
int rp_cancel_not_run(struct rp_handle h,struct rp_handle original,struct rp_handle committed,const struct nt_context *c){
 struct rp_ticket *t=rp_get(h),*pre=rp_get(original),*commit=rp_get(committed);if(!t)return SA_REFUSED;
 if(t->busy||t->ran||t->primary||t->persist_attempted||t->length||t->raw_row!=5||!t->final||t->ledger.send_called||t->ledger.calls||t->transaction.started||
    h.pool->primary||!pre||!commit||h.pool!=original.pool||h.pool!=committed.pool||t==pre||t==commit||pre==commit||
    pre->busy||pre->primary||pre->persist_attempted||!pre->prepared||!pre->commit_attempted||pre->cancel_attempted||pre->transaction.request[16]!=16||pre->transaction.setup.scope!=2||pre->transaction.setup.alias!=1||!pre->transaction.handle||
    commit->busy||commit->primary||commit->persist_attempted||!commit->ran||!commit->transaction.accepted||commit->transaction.request[16]!=17||commit->transaction.commit_source_id!=original.id||commit->transaction.commit_source_generation!=original.generation||
    !c||!c->deadline||c->deadline>h.pool->close_end||c->socket!=pre->transaction.bound.socket||c->netns!=pre->transaction.bound.netns||c->epoch!=pre->transaction.bound.epoch||c->port!=pre->transaction.bound.port||c->family!=pre->transaction.bound.family||!c->seq||c->seq==pre->transaction.bound.seq||c->seq==commit->transaction.bound.seq)
  return bad(t,SA_REFUSED);
 /* This is local disposition of a reserved operation. It does not set
  * cancel_attempted, transaction.accepted or any terminal/session fact. */
 t->ran=1;t->cancel_not_run=1;t->cancel_pre_id=original.id;t->cancel_pre_generation=original.generation;t->cancel_commit_id=committed.id;t->cancel_commit_generation=committed.generation;
 t->transaction.bound=*c;t->transaction.last=commit->transaction.last;
 return 0;
}
/* Exact owned adjacent peer only; no live-session deletion or cleanup proof. */
int rp_cancel_adjacent(struct rp_handle h,struct rp_handle original,const struct nt_context *c,const struct nt_stream *o){
 struct rp_ticket *t=rp_get(h),*pre=rp_get(original);if(!t)return SA_REFUSED;
 if(t->busy||t->ran||t->raw_row!=5||!t->final||!pre||original.pool!=h.pool||pre==t||pre->cancel_attempted||!pre->prepared||pre->transaction.setup.scope!=1||pre->transaction.setup.alias||!pre->transaction.setup.peer||pre->transaction.request[16]!=16||!pre->transaction.handle||!c||c->deadline>h.pool->close_end||c->socket!=pre->transaction.bound.socket||c->epoch!=pre->transaction.bound.epoch||c->netns!=pre->transaction.bound.netns||c->family!=pre->transaction.bound.family||c->port!=pre->transaction.bound.port||c->seq==pre->transaction.bound.seq||!o||!o->clock||!o->send||!o->receive)return bad(t,SA_REFUSED);
 pre->cancel_attempted=1;t->ran=1;t->busy=1;t->transaction.last=pre->transaction.last;
 struct flow f={h,*o};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};int rc=nt_cancel_peer_stream(&t->transaction,&t->ledger,&t->budget,c,pre->transaction.setup.peer,&wrap);if(rc)bad(t,rc);t->busy=0;return t->primary;
}
/* Canonical little-independent BE64 fields, fixed 64-byte raw record headers.
 * FNV64 checksum detects corruption only; it is not an authenticity signature. */
static void put(unsigned char *p,uint64_t v){for(int i=7;i>=0;i--){p[i]=(unsigned char)v;v>>=8;}}
static uint64_t get(const unsigned char *p){uint64_t v=0;for(int i=0;i<8;i++)v=(v<<8)|p[i];return v;}
static uint64_t sum(const unsigned char *p,size_t n){uint64_t v=14695981039346656037ULL;for(size_t i=0;i<n;i++){unsigned char c=i>=56&&i<64?0:p[i];v=(v^c)*1099511628211ULL;}return v;}
static void field(struct rp_ticket *t,size_t *n,uint64_t v){put(t->receipt+*n,v);*n+=8;}
static int capture_encode(struct rp_ticket *t);
int rp_encode(struct rp_handle h,const struct sc_client *client){
 struct rp_ticket *t=rp_get(h);if(!t)return 0;if(t->busy||!t->ran||t->persist_attempted||t->length){bad(t,SA_REPEAT);return 0;}
 if((client&&!t->sign_attempted)||(t->sign_attempted&&client!=t->bound_client)){bad(t,SA_IDENTITY);return 0;}
 if(t->raw_row==2)return capture_encode(t);
 if(t->raw_row==8){bad(t,SA_REFUSED);return 0;}
 if(client&&client->primary)bad(t,client->primary);
 struct nt_state *s=&t->transaction;struct nt_ledger *l=&t->ledger;
 if(l->calls>8||l->retained>4096||s->sent_length>t->tx_reserved||s->sent_length>sizeof(s->sent)){bad(t,SA_SHAPE);return 0;}
 memset(t->receipt,0,sizeof(t->receipt));memcpy(t->receipt,"E2REC001",8);size_t n=64;
 field(t,&n,t->id);field(t,&n,t->generation);field(t,&n,(uint64_t)t->primary);field(t,&n,(uint64_t)t->secondary);field(t,&n,s->possible);field(t,&n,s->accepted&&!t->primary);field(t,&n,s->before);field(t,&n,s->after);field(t,&n,s->expires_at);field(t,&n,s->last);
 field(t,&n,s->bound.socket);field(t,&n,s->bound.netns);field(t,&n,s->bound.epoch);field(t,&n,s->bound.seq);field(t,&n,s->bound.family);field(t,&n,s->bound.port);field(t,&n,s->bound.deadline);field(t,&n,l->calls);field(t,&n,l->reported);field(t,&n,l->send_called);field(t,&n,(uint64_t)(int64_t)l->send_rc);field(t,&n,l->send_after);field(t,&n,l->overflow);field(t,&n,s->handle);field(t,&n,s->expires);field(t,&n,s->request[16]);field(t,&n,s->primary);field(t,&n,s->secondary);
 for(unsigned i=0;i<l->calls;i++){struct nt_record *r=&l->records[i];field(t,&n,r->called);field(t,&n,r->reported);field(t,&n,r->retained);field(t,&n,r->before);field(t,&n,r->after);field(t,&n,(uint64_t)(int64_t)r->rc);field(t,&n,r->truncated);field(t,&n,r->sender);field(t,&n,r->context.socket);field(t,&n,r->context.netns);field(t,&n,r->context.epoch);}
 field(t,&n,s->remote_length);size_t remote=s->remote_length>130?130:s->remote_length;field(t,&n,remote);memcpy(t->receipt+n,s->remote_m1,remote);n+=remote;field(t,&n,(uint64_t)(int64_t)s->remote_verify_rc);field(t,&n,s->remote_before);field(t,&n,s->remote_after);field(t,&n,s->remote_hash_after);
 if(s->commit_source_id){field(t,&n,s->commit_source_id);field(t,&n,s->commit_source_generation);}
 if(s->control.command){field(t,&n,t->tx_reserved);field(t,&n,t->budget.body_bytes);field(t,&n,s->control.command);field(t,&n,s->control.peer);field(t,&n,s->control.transfer);field(t,&n,s->control.capacity);field(t,&n,s->control_pre_id);field(t,&n,s->control_pre_generation);field(t,&n,s->control_commit_id);field(t,&n,s->control_commit_generation);field(t,&n,s->control_parent_id);field(t,&n,s->control_parent_generation);field(t,&n,s->control_hash_before);field(t,&n,s->control_hash_after);}
 if(s->selection.match.state){field(t,&n,0x5354415445303031ULL);field(t,&n,nt_session_state(&s->selection.match));}
 if(s->request[16]==15){const struct nt_selection *x=&s->selection;const struct nt_readback *r=&x->match;field(t,&n,15);field(t,&n,x->population);field(t,&n,x->not_before);field(t,&n,x->valid_until);field(t,&n,r->peer);field(t,&n,r->generation);field(t,&n,r->max_bytes);field(t,&n,r->scope);field(t,&n,r->alias);field(t,&n,r->direction);memcpy(t->receipt+n,r->strong_id,32);n+=32;field(t,&n,s->population);field(t,&n,s->matches);field(t,&n,s->list_done);field(t,&n,s->selected_handle);}
 if(s->selection_id){field(t,&n,s->selection_id);field(t,&n,s->selection_generation);field(t,&n,s->selection_before);field(t,&n,s->selection_after);field(t,&n,s->selection_end);}
 if(s->expected_readback.state){field(t,&n,0x5354415445303031ULL);field(t,&n,nt_session_state(&s->expected_readback));}
 if(s->expected_readback.command){const struct nt_readback *r=&s->expected_readback;field(t,&n,r->command);field(t,&n,r->handle);field(t,&n,r->peer);field(t,&n,r->generation);field(t,&n,r->max_bytes);field(t,&n,r->scope);field(t,&n,r->alias);field(t,&n,r->direction);memcpy(t->receipt+n,r->strong_id,32);n+=32;field(t,&n,s->readback_observed&&!t->primary);}
 if(t->socket_fact.present){const struct rp_socket_fact *f=&t->socket_fact;field(t,&n,0x534f434b45543031ULL);field(t,&n,(uint64_t)(int64_t)f->fd);field(t,&n,f->dev);field(t,&n,f->ino);field(t,&n,f->primary);field(t,&n,f->secondary);field(t,&n,(uint64_t)(int64_t)f->send_result);field(t,&n,f->send_errno);field(t,&n,f->possible);field(t,&n,f->send_before);field(t,&n,f->send_after);field(t,&n,f->receive_after);field(t,&n,f->calls);}
 if(t->cancel_not_run){field(t,&n,0x4e4f5452554e3031ULL);field(t,&n,18);field(t,&n,t->cancel_pre_id);field(t,&n,t->cancel_pre_generation);field(t,&n,t->cancel_commit_id);field(t,&n,t->cancel_commit_generation);}
 size_t command=n,fact=0;
 if(client){t->unsettled=client->signer.owned_key!=NULL||client->signer.owned_md!=NULL;size_t start=n;field(t,&n,client->signer.owned_key!=NULL);field(t,&n,client->signer.owned_md!=NULL);field(t,&n,client->received_length);field(t,&n,client->primary);field(t,&n,client->signer.sign_possible);field(t,&n,client->signer.primary);field(t,&n,client->signer.secondary);field(t,&n,client->signer.time_refused);field(t,&n,client->final_time);
  for(unsigned i=0;i<SA_STAGES;i++){const struct sa_receipt *r=&client->signer.receipt[i];field(t,&n,r->called);field(t,&n,r->before);field(t,&n,r->after);field(t,&n,(uint64_t)(int64_t)r->raw.rc);field(t,&n,r->raw.length);size_t k=r->raw.length>64?64:r->raw.length;field(t,&n,k);memcpy(t->receipt+n,r->raw.bytes,k);n+=k;}fact=n-start;}
 size_t terminal=64;field(t,&n,t->primary);field(t,&n,t->secondary);field(t,&n,s->primary);field(t,&n,s->secondary);field(t,&n,s->possible);field(t,&n,0);field(t,&n,0);field(t,&n,0);
 unsigned records=0;size_t raw_start=n;
 if(l->send_called){put(t->receipt+n,1);put(t->receipt+n+8,s->sent_length);put(t->receipt+n+16,s->sent_length);n+=64;memcpy(t->receipt+n,s->sent,s->sent_length);n+=s->sent_length;records++;}
 for(unsigned i=0;i<l->calls;i++){struct nt_record *r=&l->records[i];if(!r->called)continue;if(r->offset>l->retained||r->retained>l->retained-r->offset){bad(t,SA_SHAPE);return 0;}put(t->receipt+n,2);put(t->receipt+n+8,r->reported);put(t->receipt+n+16,r->retained);put(t->receipt+n+24,i);n+=64;memcpy(t->receipt+n,s->raw.bytes+r->offset,r->retained);n+=r->retained;records++;}
 if(command>2048||fact>1024||n>RP_RECEIPT||n-raw_start>t->held[0].encoded){bad(t,SA_SHAPE);return 0;}
 put(t->receipt+8,n);put(t->receipt+16,command);put(t->receipt+24,fact);put(t->receipt+32,terminal);put(t->receipt+40,records);put(t->receipt+48,n-raw_start);put(t->receipt+56,sum(t->receipt,n));t->length=n;t->sealed_revision=t->revision;return 1;
}
int rp_decode(const unsigned char *p,size_t n,struct rp_decoded *d){
 if(!p||!d||n<128||n>RP_RECEIPT||get(p+8)!=n||get(p+56)!=sum(p,n))return 0;
 if(!memcmp(p,"E2LOC001",8)){
  if(n!=640||get(p+16)!=256||get(p+24)!=320||get(p+32)!=64||get(p+40)||get(p+48)||get(p+128)<1||get(p+128)>2)return 0;
  *d=(struct rp_decoded){get(p+64),get(p+72),0,256,320,64,0,(int)get(p+80),(int)get(p+96)};
  return d->id&&d->generation;
 }
 if(memcmp(p,"E2REC001",8))return 0;
 uint64_t command=get(p+16),fact=get(p+24),terminal=get(p+32),records=get(p+40),raw=get(p+48);
 if(command<248||command>2048||fact>1024||terminal!=64||records>9||raw>n||command+fact+terminal+raw!=n)return 0;
 size_t at=(size_t)(command+fact+terminal);for(unsigned i=0;i<records;i++){if(n-at<64)return 0;uint64_t kind=get(p+at),reported=get(p+at+8),kept=get(p+at+16);if((kind!=1&&kind!=2)||kept>4096||kept>reported||kept>n-at-64)return 0;at+=64+(size_t)kept;}if(at!=n)return 0;
 *d=(struct rp_decoded){get(p+64),get(p+72),(unsigned)records,(size_t)command,(size_t)fact,(size_t)terminal,(size_t)raw,(int)get(p+80),(int)get(p+96)};return d->id&&d->generation;
}
int rp_persist(struct rp_handle h,uint64_t end,const struct rp_store *ops){
 struct rp_ticket *t=rp_get(h);if(!t)return 0;if(t->busy||t->persist_attempted){bad(t,SA_REPEAT);return 0;}t->persist_attempted=1;t->busy=1;
 if(!ops||!ops->clock||!ops->write_once||!end||end>h.pool->close_end||!t->length||t->sealed_revision!=t->revision){bad(t,SA_REFUSED);goto fail;}
 struct rp_decoded initial;if((t->raw_row==8)!=(!memcmp(t->receipt,"E2LOC001",8))||!rp_decode(t->receipt,t->length,&initial)){bad(t,SA_SHAPE);goto fail;}size_t original_length=t->length;uint64_t original_hash=sum(t->receipt,t->length);
 struct rp_store o=*ops;uint64_t revision=t->revision;t->persist_before=o.clock(o.arg);
 if(t->persist_before>=end||t->persist_before<t->transaction.last){bad(t,SA_TIME);goto fail;}
 if(t->revision!=revision||t->length!=original_length||sum(t->receipt,t->length)!=original_hash)goto fail;
 struct rp_write_result result={0};o.write_once(o.arg,t->id,t->receipt,t->length,&result);
 t->written=result.written;t->read_length=result.read_length;t->write_rc=result.rc;t->writer_settled=result.settled;
 if(result.rc)bad(t,SA_CALLBACK);
 t->persist_after=o.clock(o.arg);
 if(t->persist_after>=end||t->persist_after<t->persist_before){bad(t,SA_TIME);goto fail;}
 if(t->revision!=revision||t->length!=original_length||sum(t->receipt,t->length)!=original_hash||result.rc||!result.settled||result.written!=t->length||result.read_length!=t->length||memcmp(result.readback,t->receipt,t->length)){bad(t,SA_SHAPE);goto fail;}
 struct rp_decoded decoded;if(!rp_decode(result.readback,result.read_length,&decoded)||decoded.id!=t->id||decoded.generation!=t->generation){bad(t,SA_IDENTITY);goto fail;}
 if(t->unsettled){bad(t,SA_REFUSED);goto fail;}
 struct rp_amount actual[3]={{decoded.records,decoded.raw-64*decoded.records,decoded.raw},{0,decoded.command+decoded.fact,decoded.command+decoded.fact},{1,64,64}};unsigned rows[]={t->raw_row,8,9};
 for(unsigned i=0;i<3;i++){h.pool->used[rows[i]].slots-=t->held[i].slots-actual[i].slots;h.pool->used[rows[i]].body-=t->held[i].body-actual[i].body;h.pool->used[rows[i]].encoded-=t->held[i].encoded-actual[i].encoded;}
 if(t->raw_row==2)h.pool->captures[t->final]-=t->held[0].slots-actual[0].slots;else h.pool->setup[t->final]-=t->held[0].slots-actual[0].slots;if(!decoded.fact)h.pool->facts[t->final]--;t->persisted=1;t->active=0;t->busy=0;return 1;
 fail:t->busy=0;return 0;
}

int rp_commit_prepared(struct rp_handle h,struct rp_handle original,const struct nt_context *c,const struct nt_stream *ops){
 struct rp_ticket *t=rp_get(h),*pre=rp_get(original);if(!t)return SA_REFUSED;
 if(!pre||h.pool!=original.pool||pre==t||pre->busy||pre->cancel_attempted||pre->commit_attempted||pre->primary||!pre->sign_attempted||!pre->facts||!pre->bound_client||!pre->bound_client->accepted||pre->persist_attempted||!c||c->seq==pre->transaction.bound.seq)return bad(t,SA_IDENTITY);
 pre->commit_attempted=1;t->transaction.commit_source_id=original.id;t->transaction.commit_source_generation=original.generation;
 return rp_commit(h,c,pre->transaction.handle,pre->bound_client,ops);
}

int rp_readback(struct rp_handle h,const struct nt_context *c,const struct nt_readback *r,const struct nt_stream *o){
 struct rp_ticket *t=admit(h);if(!t)return SA_REFUSED;
 if(!r||(r->command!=14&&r->command!=55&&r->command!=57)||!c||c->deadline>h.pool->normal_end||!o||!o->clock||!o->send||!o->receive){t->busy=0;return bad(t,SA_REFUSED);}
 struct flow f={h,*o};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};int rc=nt_readback_stream(&t->transaction,&t->ledger,&t->budget,c,r,&wrap);if(rc)bad(t,rc);if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}

int rp_carrier(struct rp_handle h,const struct nt_context *c,const struct nt_carrier *r,const struct nt_stream *o){
 struct rp_ticket *t=rp_get(h);if(!t)return SA_REFUSED;
 if(t->busy||t->ran||t->primary||t->raw_row!=5)return bad(t,SA_REPEAT);
 t->ran=1;t->busy=1;
 if(!r||!c||!o||!o->clock||!o->send||!o->receive||
    (!!t->final!=(r->command==2||r->command==61))||c->deadline>(t->final?h.pool->close_end:h.pool->normal_end)){
  t->busy=0;return bad(t,SA_REFUSED);
 }
 struct flow f={h,*o};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};
 int rc=nt_carrier_stream(&t->transaction,&t->ledger,&t->budget,c,r,&wrap);
 if(rc)bad(t,rc);
 if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}

int rp_list(struct rp_handle h,const struct nt_context *c,const struct nt_selection *r,const struct nt_stream *o){
 struct rp_ticket *t=admit(h);if(!t)return SA_REFUSED;
 if(!c||c->deadline>h.pool->normal_end||!o||!o->clock||!o->send||!o->receive){t->busy=0;return bad(t,SA_REFUSED);}
 struct flow f={h,*o};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};int rc=nt_list_stream(&t->transaction,&t->ledger,&t->budget,c,r,&wrap);if(rc)bad(t,rc);if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}

struct selection_flow {struct rp_handle target,source;struct nt_stream ops;uint64_t revision;};
static int selection_guard(struct selection_flow *f){
 struct rp_ticket *t=rp_get(f->target),*s=rp_get(f->source);if(!t)return 0;
 if(!s||s->primary||s->busy||s->persist_attempted||s->revision!=f->revision||!s->transaction.accepted||!s->transaction.selection_consumed){bad(t,SA_IDENTITY);if(!f->target.pool->primary)f->target.pool->primary=t->primary;return 0;}
 return !t->primary;
}
static uint64_t selection_clock(void *v){struct selection_flow *f=v;selection_guard(f);uint64_t now=f->ops.clock(f->ops.arg);selection_guard(f);return now;}
static int selection_send(void *v,const unsigned char *b,size_t n){struct selection_flow *f=v;if(!selection_guard(f))return -1;int rc=f->ops.send(f->ops.arg,b,n);selection_guard(f);return rc;}
static void selection_receive(void *v,size_t n,struct nt_reply *r){struct selection_flow *f=v;if(!selection_guard(f)){r->rc=-1;return;}f->ops.receive(f->ops.arg,n,r);selection_guard(f);}
int rp_selected_readback(struct rp_handle h,struct rp_handle original,const struct nt_context *c,const struct nt_readback *r,const struct nt_stream *o){
 struct rp_ticket *t=rp_get(h),*source=rp_get(original);if(!t)return SA_REFUSED;
 if(!source||h.pool!=original.pool||source==t||t->ran||t->busy||source->busy||source->primary||source->persist_attempted||!source->ran||source->transaction.request[16]!=15||!source->transaction.accepted||!source->transaction.list_done||source->transaction.matches!=1||source->transaction.selection_consumed)return bad(t,SA_IDENTITY);
 const struct nt_state *s=&source->transaction;const struct nt_readback *w=&s->selection.match;const struct nt_context *b=&s->bound;
 if(!c||!r||!o||!o->clock||!o->send||!o->receive||r->command!=14||r->handle!=s->selected_handle||!r->handle||r->peer!=w->peer||r->scope!=w->scope||r->alias!=w->alias||r->generation!=w->generation||r->direction!=w->direction||r->max_bytes!=w->max_bytes||nt_session_state(r)!=nt_session_state(w)||memcmp(r->strong_id,w->strong_id,32)||c->socket!=b->socket||c->netns!=b->netns||c->epoch!=b->epoch||c->family!=b->family||c->port!=b->port||c->seq==b->seq||c->deadline>s->selection.valid_until||s->before<s->selection.not_before||s->after>=s->selection.valid_until)return bad(t,SA_IDENTITY);
 source->transaction.selection_consumed=1;
 t->transaction.selection_id=original.id;t->transaction.selection_generation=original.generation;t->transaction.selection_before=s->before;t->transaction.selection_after=s->after;t->transaction.selection_end=s->selection.valid_until;t->transaction.last=s->after;
 struct selection_flow f={h,original,*o,source->revision};struct nt_stream wrapped={selection_clock,selection_send,selection_receive,&f};
 return rp_readback(h,c,r,&wrapped);
}

struct control_flow {struct rp_handle target,sources[3];uint64_t revisions[3];unsigned count;size_t tx,rx;struct rp_amount held;const struct sc_client *client;struct nt_stream ops;};
static int control_guard(struct control_flow *f){
 struct rp_ticket *t=rp_get(f->target);if(!t)return 0;
 if(t->tx_reserved!=f->tx||t->budget.body_bytes!=f->rx||memcmp(&t->held[0],&f->held,sizeof(f->held))){bad(t,SA_IDENTITY);return 0;}
 for(unsigned i=0;i<f->count;i++){struct rp_ticket *s=rp_get(f->sources[i]);if(!s||s->primary||s->busy||s->persist_attempted||s->revision!=f->revisions[i]||!s->transaction.accepted){bad(t,s&&s->primary?s->primary:SA_IDENTITY);return 0;}}
 struct rp_ticket *commit=rp_get(f->sources[1]);
 if(!f->client->accepted||f->client->primary||f->client->wire_length!=commit->transaction.payload_length||memcmp(f->client->wire,commit->transaction.payload,commit->transaction.payload_length)){bad(t,SA_IDENTITY);return 0;}
 return !t->primary;
}
static uint64_t control_clock(void *v){struct control_flow *f=v;control_guard(f);uint64_t now=f->ops.clock(f->ops.arg);control_guard(f);return now;}
static int control_send(void *v,const unsigned char *b,size_t n){struct control_flow *f=v;if(!control_guard(f))return -1;int rc=f->ops.send(f->ops.arg,b,n);control_guard(f);return rc;}
static void control_receive(void *v,size_t n,struct nt_reply *r){struct control_flow *f=v;if(!control_guard(f)){r->rc=-1;return;}f->ops.receive(f->ops.arg,n,r);control_guard(f);}
static int control_refuse(struct rp_handle h,struct rp_ticket *t,int error){t->busy=0;bad(t,error);if(!h.pool->primary)h.pool->primary=t->primary;return t->primary;}
int rp_control(struct rp_handle h,struct rp_handle original,struct rp_handle committed,struct rp_handle parent,const struct nt_context *c,const struct nt_control *policy,struct sb_backend *hash,const struct nt_stream *o){
 struct rp_ticket *t=admit(h);if(!t)return SA_REFUSED;
 /* Bounded typed input custody precedes authority checks; never acceptance. */
 if(c)t->transaction.bound=*c;
 if(policy)t->transaction.control=*policy;
 t->transaction.control_pre_id=original.id;t->transaction.control_pre_generation=original.generation;t->transaction.control_commit_id=committed.id;t->transaction.control_commit_generation=committed.generation;
 t->transaction.control_parent_id=parent.id;t->transaction.control_parent_generation=parent.generation;
 struct rp_ticket *pre=rp_get(original),*commit=rp_get(committed),*adj=rp_get(parent);
 if(pre&&original.pool==h.pool&&pre->transport_attempted){bad(pre,SA_REPEAT);return control_refuse(h,t,SA_REPEAT);}
 if(!pre||!commit||pre==t||commit==t||pre==commit||h.pool!=original.pool||h.pool!=committed.pool||pre->transport_attempted||!pre->commit_attempted||!pre->sign_attempted||!pre->facts||!pre->bound_client||commit->transaction.request[16]!=17||commit->transaction.commit_source_id!=original.id||commit->transaction.commit_source_generation!=original.generation||!c||!policy||!o||!o->clock||!o->send||!o->receive||c->deadline>h.pool->normal_end||c->seq==pre->transaction.bound.seq||c->seq==commit->transaction.bound.seq||c->socket!=pre->transaction.bound.socket||c->epoch!=pre->transaction.bound.epoch||c->netns!=pre->transaction.bound.netns||c->family!=pre->transaction.bound.family||c->port!=pre->transaction.bound.port||c->socket!=commit->transaction.bound.socket||c->epoch!=commit->transaction.bound.epoch||c->netns!=commit->transaction.bound.netns||c->family!=commit->transaction.bound.family||c->port!=commit->transaction.bound.port||c->deadline>commit->transaction.bound.deadline){return control_refuse(h,t,SA_IDENTITY);}
 size_t wire=pre->bound_client->wire_length;
 if((wire!=130&&wire!=172)||(policy->command!=19&&policy->command!=47)||32+((wire+(policy->command==19?54:4)+7)&~(size_t)3)>t->tx_reserved)return control_refuse(h,t,SA_REFUSED);
 pre->transport_attempted=1;
 unsigned count=2;
 if(policy->command==19){
  if(!adj||parent.pool!=h.pool||adj==t||adj==pre||adj==commit||!adj->transaction.readback_observed||adj->transaction.expected_readback.command!=14||nt_session_state(&adj->transaction.expected_readback)!=2||adj->transaction.expected_readback.scope!=1||adj->transaction.expected_readback.alias||!(adj->transaction.expected_readback.direction&2)||adj->transaction.expected_readback.peer!=policy->peer||policy->capacity>adj->transaction.expected_readback.max_bytes||c->deadline>adj->transaction.bound.deadline||c->seq==adj->transaction.bound.seq||c->socket!=adj->transaction.bound.socket||c->epoch!=adj->transaction.bound.epoch||c->netns!=adj->transaction.bound.netns||c->family!=adj->transaction.bound.family||c->port!=adj->transaction.bound.port||!policy->transfer||policy->transfer<=h.pool->transfer_high_water){return control_refuse(h,t,SA_IDENTITY);}
  h.pool->transfer_high_water=policy->transfer;count=3;t->transaction.control_parent_id=parent.id;t->transaction.control_parent_generation=parent.generation;
 }
 t->transaction.control_pre_id=original.id;t->transaction.control_pre_generation=original.generation;t->transaction.control_commit_id=committed.id;t->transaction.control_commit_generation=committed.generation;
 t->transaction.last=commit->transaction.last;if(adj&&count==3&&t->transaction.last<adj->transaction.last)t->transaction.last=adj->transaction.last;
 struct control_flow cf={h,{original,committed,parent},{pre->revision,commit->revision,adj?adj->revision:0},count,t->tx_reserved,t->budget.body_bytes,t->held[0],pre->bound_client,*o};
 struct nt_stream guarded={control_clock,control_send,control_receive,&cf};struct flow f={h,guarded};struct nt_stream wrapped={flow_clock,flow_send,flow_receive,&f};
 int rc=nt_control_stream(&t->transaction,&t->ledger,&t->budget,c,&pre->transaction.setup,pre->bound_client,policy,hash,&wrapped);if(rc)bad(t,rc);if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}

/* Injected full-frame observation: no Ethernet mapping is inferred from Netlink. */
static uint64_t capture_hash(const unsigned char *b,size_t n){uint64_t v=14695981039346656037ULL;for(size_t i=0;i<n;i++)v=(v^b[i])*1099511628211ULL;return v;}
static int capture_context_equal(const struct rp_capture_context *a,const struct rp_capture_context *b){
 return a->endpoint==b->endpoint&&a->netns==b->netns&&a->epoch==b->epoch&&a->session_generation==b->session_generation&&a->transfer==b->transfer&&a->ifindex==b->ifindex&&a->direction==b->direction&&!memcmp(a->source,b->source,6)&&!memcmp(a->destination,b->destination,6);
}
static int capture_tick(struct rp_ticket *t,uint64_t now){t->transaction.after=now;if(now<t->transaction.last||now>=t->capture_end){bad(t,SA_TIME);return 0;}t->transaction.last=now;return !t->primary;}
int rp_capture(struct rp_handle h,struct rp_handle control,const struct rp_capture_plan *plan,const struct rp_capture_ops *ops){
 struct rp_ticket *t=rp_get(h),*source=rp_get(control);
 if(!t)return SA_REFUSED;
 if(t->busy||t->ran||t->raw_row!=2)return bad(t,SA_REPEAT);
 t->ran=t->busy=1;t->capture_control=control.id;t->capture_generation=control.generation;
 if(!plan||!ops||!ops->clock||!ops->read_once||!source||control.pool!=h.pool||source==t||source->busy||source->primary||source->persist_attempted||source->capture_consumed||!source->transaction.accepted||source->transaction.control.command!=19||!plan->observation_identity||!plan->expected||plan->length<14||plan->length>1984||!plan->context.endpoint||!plan->context.netns||!plan->context.epoch||!plan->context.ifindex||plan->context.direction<1||plan->context.direction>2||plan->deadline>h.pool->normal_end||plan->deadline>source->transaction.bound.deadline||plan->not_before<source->transaction.before||plan->not_before>=plan->deadline||plan->context.transfer!=source->transaction.control.transfer){bad(t,SA_IDENTITY);goto out;}
 struct rp_handle parent={h.pool,0,source->transaction.control_parent_generation,source->transaction.control_parent_id};
 struct rp_ticket *adj=NULL;
 for(unsigned i=0;i<16;i++){parent.slot=i;adj=rp_get(parent);if(adj)break;}
 if(!adj||adj->primary||!adj->transaction.readback_observed||adj->transaction.expected_readback.generation!=plan->context.session_generation){bad(t,SA_IDENTITY);goto out;}
 for(unsigned i=0;i<16;i++)if(h.pool->tickets[i].observation_identity==plan->observation_identity){bad(t,SA_REPEAT);goto out;}
 unsigned char expected[1984];memcpy(expected,plan->expected,plan->length);
 if(memcmp(expected,plan->context.destination,6)||memcmp(expected+6,plan->context.source,6)){bad(t,SA_IDENTITY);goto out;}
 struct rp_capture_plan p=*plan;struct rp_capture_ops o=*ops;
 t->observation_identity=p.observation_identity;t->capture_expected=p.context;t->capture_expected_length=p.length;t->capture_digest=capture_hash(expected,p.length);t->capture_not_before=p.not_before;t->capture_end=p.deadline;
 source->capture_consumed=1;
 t->transaction.last=source->transaction.last;
 uint64_t revision=t->revision,srev=source->revision,arev=adj->revision;
 t->transaction.before=o.clock(o.arg);
 if(!capture_tick(t,t->transaction.before)||t->revision!=revision||source->revision!=srev||adj->revision!=arev||rp_get(control)!=source||rp_get(parent)!=adj||source->persist_attempted||adj->persist_attempted||source->busy||adj->busy||h.pool->primary){if(!t->primary)bad(t,SA_REFUSED);goto out;}
 t->capture_attempted=1;o.read_once(o.arg,1984,&t->capture_raw);
 /* Raw typed result stays owned even if callback reentered or clock fails. */
 if(t->capture_raw.rc)bad(t,SA_CALLBACK);
 uint64_t now=o.clock(o.arg);capture_tick(t,now);
 if(t->revision!=revision||source->revision!=srev||adj->revision!=arev||rp_get(control)!=source||rp_get(parent)!=adj||source->persist_attempted||adj->persist_attempted||source->busy||adj->busy||source->primary||adj->primary||h.pool->primary){if(!t->primary)bad(t,SA_REFUSED);goto out;}
 struct rp_capture_raw *r=&t->capture_raw;
 if(r->rc){bad(t,SA_CALLBACK);goto out;}
 if(r->truncated||r->lost||r->length!=p.length||r->length>1984||r->before<p.not_before||r->before<t->transaction.before||r->after<r->before||r->after>now||r->after>=p.deadline||!capture_context_equal(&r->context,&p.context)||memcmp(r->bytes,expected,p.length)){bad(t,SA_SHAPE);goto out;}
 t->capture_accepted=1;
 out:t->busy=0;if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;return t->primary;
}
static void capture_fields(struct rp_ticket *t,size_t *n,const struct rp_capture_context *c){
 field(t,n,c->endpoint);field(t,n,c->netns);field(t,n,c->epoch);field(t,n,c->session_generation);field(t,n,c->transfer);field(t,n,c->ifindex);field(t,n,c->direction);
 memcpy(t->receipt+*n,c->source,6);*n+=6;memcpy(t->receipt+*n,c->destination,6);*n+=6;
}
static int capture_encode(struct rp_ticket *t){
 memset(t->receipt,0,sizeof(t->receipt));memcpy(t->receipt,"E2REC001",8);size_t n=64;
 field(t,&n,t->id);field(t,&n,t->generation);field(t,&n,t->primary);field(t,&n,t->secondary);field(t,&n,t->capture_attempted);field(t,&n,t->capture_accepted&&!t->primary);
 field(t,&n,3);field(t,&n,t->capture_control);field(t,&n,t->capture_generation);field(t,&n,t->capture_digest);field(t,&n,t->capture_expected_length);field(t,&n,t->capture_not_before);field(t,&n,t->capture_end);field(t,&n,t->transaction.before);field(t,&n,t->transaction.after);
 capture_fields(t,&n,&t->capture_expected);capture_fields(t,&n,&t->capture_raw.context);
 field(t,&n,t->capture_raw.before);field(t,&n,t->capture_raw.after);field(t,&n,t->capture_raw.rc);field(t,&n,t->capture_raw.truncated);field(t,&n,t->capture_raw.lost);field(t,&n,t->capture_raw.length);
 size_t command=n;for(unsigned i=0;i<8;i++)field(t,&n,i==0?(uint64_t)t->primary:i==1?(uint64_t)t->secondary:0);
 size_t raw=n;unsigned records=0;
 if(t->capture_attempted){size_t kept=t->capture_raw.length>1984?1984:t->capture_raw.length;put(t->receipt+n,2);put(t->receipt+n+8,t->capture_raw.length);put(t->receipt+n+16,kept);n+=64;memcpy(t->receipt+n,t->capture_raw.bytes,kept);n+=kept;records=1;}
 put(t->receipt+8,n);put(t->receipt+16,command);put(t->receipt+24,0);put(t->receipt+32,64);put(t->receipt+40,records);put(t->receipt+48,n-raw);put(t->receipt+56,sum(t->receipt,n));t->length=n;t->sealed_revision=t->revision;return 1;
}

struct member_flow {struct rp_handle target,source;struct nt_stream ops;uint64_t revision;unsigned index;struct nt_member_observation member;};
static int member_guard(struct member_flow *f){
 struct rp_ticket *t=rp_get(f->target),*s=rp_get(f->source);if(!t)return 0;
 if(!s||s->primary||s->busy||s->revision!=f->revision||!s->transaction.accepted||s->transaction.members[f->index].handle!=f->member.handle||s->transaction.members[f->index].generation!=f->member.generation||s->transaction.members[f->index].ifindex!=f->member.ifindex||s->transaction.members[f->index].flags!=f->member.flags){bad(t,SA_IDENTITY);if(!f->target.pool->primary)f->target.pool->primary=t->primary;return 0;}
 return !t->primary;
}
static uint64_t member_clock(void *v){struct member_flow *f=v;member_guard(f);uint64_t n=f->ops.clock(f->ops.arg);member_guard(f);return n;}
static int member_send(void *v,const unsigned char *b,size_t n){struct member_flow *f=v;if(!member_guard(f))return -1;int rc=f->ops.send(f->ops.arg,b,n);member_guard(f);return rc;}
static void member_receive(void *v,size_t n,struct nt_reply *r){struct member_flow *f=v;if(!member_guard(f)){r->rc=-1;return;}f->ops.receive(f->ops.arg,n,r);member_guard(f);}
/* Source must be this pool's accepted current member-list receipt. */
int rp_member_context(struct rp_handle h,struct rp_handle source,const struct nt_context *c,unsigned index,unsigned direction,const struct nt_stream *o){
 struct rp_ticket *t=admit(h);if(!t)return SA_REFUSED;
 struct rp_ticket *from=rp_get(source);
 if(!from||h.pool!=source.pool||h.id==source.id||!from->ran||from->busy||from->primary||!from->transaction.accepted||from->transaction.carrier.command!=75||index>=from->transaction.carrier_records||index>=4||t->final||t->raw_row!=5||!c||!o||!o->clock||!o->send||!o->receive||c->deadline>h.pool->normal_end){t->busy=0;return bad(t,SA_REFUSED);}
 const struct nt_context *old=&from->transaction.bound;
 struct nt_member_observation m=from->transaction.members[index];
 if((direction!=1&&direction!=2)||(from->transaction.member_consumed[index]&direction)||!(m.flags&direction)||c->socket!=old->socket||c->netns!=old->netns||c->epoch!=old->epoch||c->family!=old->family||c->port!=old->port||c->seq<=old->seq){t->busy=0;return bad(t,SA_IDENTITY);}
 struct nt_member_context plan={m.handle,m.generation,(unsigned char)direction};
 from->transaction.member_consumed[index]|=(unsigned char)direction;
 struct member_flow mf={h,source,*o,from->revision,index,m};
 struct nt_stream guarded={member_clock,member_send,member_receive,&mf};
 struct flow f={h,guarded};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};
 int rc=nt_member_context_stream(&t->transaction,&t->ledger,&t->budget,c,&plan,&wrap);
 if(rc)bad(t,rc);
 if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}

struct expectation_flow {struct rp_handle target,source;struct nt_stream ops;uint64_t revision;unsigned cleanup;};
static int expectation_guard(struct expectation_flow *f){
 struct rp_ticket *t=rp_get(f->target),*s=rp_get(f->source);if(!t)return 0;
 if(!s||s->busy||s->revision!=f->revision||(!f->cleanup&&(s->primary||!s->transaction.accepted))){bad(t,SA_IDENTITY);return 0;}
 return !t->primary;
}
static uint64_t expectation_clock(void *v){struct expectation_flow *f=v;expectation_guard(f);uint64_t n=f->ops.clock(f->ops.arg);expectation_guard(f);return n;}
static int expectation_send(void *v,const unsigned char *b,size_t n){struct expectation_flow *f=v;if(!expectation_guard(f))return -1;int rc=f->ops.send(f->ops.arg,b,n);expectation_guard(f);return rc;}
static void expectation_receive(void *v,size_t n,struct nt_reply *r){struct expectation_flow *f=v;if(!expectation_guard(f)){r->rc=-1;return;}f->ops.receive(f->ops.arg,n,r);expectation_guard(f);}
int rp_expectation(struct rp_handle h,struct rp_handle original,const struct nt_context *c,const struct nt_readback *r,const struct nt_stream *o){
 struct rp_ticket *t=rp_get(h),*s=rp_get(original);if(!t)return SA_REFUSED;
 if(t->busy||t->ran||t->primary||t->raw_row!=5)return bad(t,SA_REPEAT);
 t->ran=t->busy=1;
 if(!s||s==t||h.pool!=original.pool||s->busy||!c||!r||!o||!o->clock||!o->send||!o->receive||!nt_readback_valid(r)||(r->command!=53&&r->command!=54)||!!t->final!=(r->command==54)||c->deadline>(t->final?h.pool->close_end:h.pool->normal_end))goto refused;
 const struct nt_context *old=&s->transaction.bound;
 if(c->socket!=old->socket||c->netns!=old->netns||c->epoch!=old->epoch||c->port!=old->port||c->seq<=old->seq)goto refused;
 if(r->command==53){
  if(s->primary||s->persist_attempted||!s->transaction.accepted||s->expectation_attempted||c->family<16)goto refused;
  if(r->scope==1){
   if(s->transaction.carrier.command!=76||!s->transaction.peer_context||r->peer!=s->transaction.peer_context||c->family==old->family)goto refused;
  }else{
   const struct nt_readback *w=&s->transaction.expected_readback;
   if(r->scope!=2||r->alias!=1||s->transaction.request[16]!=14||!s->transaction.readback_observed||w->command!=14||w->scope!=1||w->alias||nt_session_state(w)!=2||!(w->direction&2)||w->peer!=r->peer||memcmp(w->strong_id,r->strong_id,32)||c->family!=old->family||c->deadline>old->deadline)goto refused;
  }
  s->expectation_attempted=1;
 }else{
  const struct nt_readback *w=&s->transaction.expected_readback;
  if(s->transaction.request[16]!=53||!s->transaction.possible||s->expectation_delete_attempted||c->family!=old->family||w->peer!=r->peer||w->scope!=r->scope||w->alias!=r->alias||memcmp(w->strong_id,r->strong_id,32))goto refused;
  s->expectation_delete_attempted=1;
 }
 struct expectation_flow ef={h,original,*o,s->revision,t->final};
 struct nt_stream guarded={expectation_clock,expectation_send,expectation_receive,&ef};
 struct flow f={h,guarded};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&f};
 int rc=nt_readback_stream(&t->transaction,&t->ledger,&t->budget,c,r,&wrap);
 if(rc)bad(t,rc);
 if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
 refused:t->busy=0;bad(t,SA_IDENTITY);if(!h.pool->primary)h.pool->primary=t->primary;return t->primary;
}

struct session_change_flow {struct rp_handle target,source;struct nt_stream ops;uint64_t revision;unsigned source_command;};
static int change_guard(struct session_change_flow *f){
 struct rp_ticket *t=rp_get(f->target),*s=rp_get(f->source);if(!t)return 0;
 if(!s||s->busy||s->primary||s->persist_attempted||s->revision!=f->revision||!s->transaction.accepted||s->transaction.request[16]!=f->source_command||(f->source_command==14&&!s->transaction.readback_observed)){bad(t,SA_IDENTITY);return 0;}
 return !t->primary;
}
static uint64_t change_clock(void *v){struct session_change_flow *f=v;change_guard(f);uint64_t n=f->ops.clock(f->ops.arg);change_guard(f);return n;}
static int change_send(void *v,const unsigned char *b,size_t n){struct session_change_flow *f=v;if(!change_guard(f))return -1;int rc=f->ops.send(f->ops.arg,b,n);change_guard(f);return rc;}
static void change_receive(void *v,size_t n,struct nt_reply *r){struct session_change_flow *f=v;if(!change_guard(f)){r->rc=-1;return;}f->ops.receive(f->ops.arg,n,r);change_guard(f);}
int rp_session_change(struct rp_handle h,struct rp_handle original,const struct nt_context *c,unsigned command,const struct nt_readback *r,const struct nt_stream *o){
 struct rp_ticket *t=rp_get(h),*source=rp_get(original);if(!t)return SA_REFUSED;
 if(t->ran||t->busy||t->primary||t->raw_row!=5)return bad(t,SA_REPEAT);
 t->ran=t->busy=1;
 if(!source||h.pool!=original.pool||t==source||source->busy||source->primary||source->persist_attempted||!source->transaction.accepted||!source->transaction.readback_observed||source->transaction.request[16]!=14||!c||!r||!o||!o->clock||!o->send||!o->receive||!nt_readback_valid(r)||r->command!=14||!((r->scope==1&&!r->alias)||(r->scope==2&&r->alias==1))||(command!=12&&command!=13)||!!t->final!=(command==13)||c->deadline>(t->final?h.pool->close_end:h.pool->normal_end))goto refused;
 const struct nt_readback *w=&source->transaction.expected_readback;const struct nt_context *b=&source->transaction.bound;
 if(r->handle!=w->handle||r->generation!=w->generation||r->peer!=w->peer||r->scope!=w->scope||r->alias!=w->alias||r->direction!=w->direction||memcmp(r->strong_id,w->strong_id,32)||c->socket!=b->socket||c->netns!=b->netns||c->epoch!=b->epoch||c->family!=b->family||c->port!=b->port||c->seq<=b->seq)goto refused;
 if(command==12){
  if(!source->transaction.selection_id||nt_session_state(w)!=1||nt_session_state(r)!=2||w->max_bytes||r->max_bytes<2||source->activation_attempted||source->session_delete_attempted||c->deadline>b->deadline)goto refused;
  source->activation_attempted=1;
 }else{
  if(source->session_delete_attempted||r->max_bytes!=w->max_bytes||nt_session_state(r)!=nt_session_state(w))goto refused;
  source->session_delete_attempted=1;
 }
 t->transaction.selection_id=original.id;t->transaction.selection_generation=original.generation;t->transaction.last=source->transaction.after;
 struct session_change_flow f={h,original,*o,source->revision,14};struct nt_stream guarded={change_clock,change_send,change_receive,&f};
 struct flow flow={h,guarded};struct nt_stream wrap={flow_clock,flow_send,flow_receive,&flow};
 int rc=nt_session_change_stream(&t->transaction,&t->ledger,&t->budget,c,command,r,&wrap);if(rc)bad(t,rc);
 if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
 refused:t->busy=0;bad(t,SA_IDENTITY);if(!h.pool->primary)h.pool->primary=t->primary;return t->primary;
}

int rp_session_active_readback(struct rp_handle h,struct rp_handle original,const struct nt_context *c,const struct nt_readback *r,const struct nt_stream *o){
 struct rp_ticket *t=rp_get(h),*source=rp_get(original);if(!t)return SA_REFUSED;
 if(!source||h.pool!=original.pool||t==source||t->ran||t->busy||source->busy||source->primary||source->persist_attempted||source->activation_readback_attempted||!source->transaction.accepted||source->transaction.request[16]!=12||!source->transaction.selection_id||!c||!r||!o||!o->clock||!o->send||!o->receive||!nt_readback_valid(r)||r->command!=14||nt_session_state(r)!=2)return bad(t,SA_IDENTITY);
 const struct nt_readback *w=&source->transaction.expected_readback;const struct nt_context *b=&source->transaction.bound;
 if(nt_session_state(w)!=2||r->handle!=w->handle||r->generation!=w->generation||r->peer!=w->peer||r->scope!=w->scope||r->alias!=w->alias||r->direction!=w->direction||r->max_bytes!=w->max_bytes||memcmp(r->strong_id,w->strong_id,32)||c->socket!=b->socket||c->netns!=b->netns||c->epoch!=b->epoch||c->family!=b->family||c->port!=b->port||c->seq<=b->seq||c->deadline>b->deadline)return bad(t,SA_IDENTITY);
 source->activation_readback_attempted=1;
 t->transaction.selection_id=original.id;t->transaction.selection_generation=original.generation;t->transaction.selection_before=source->transaction.before;t->transaction.selection_after=source->transaction.after;t->transaction.selection_end=b->deadline;t->transaction.last=source->transaction.after;
 struct session_change_flow f={h,original,*o,source->revision,12};struct nt_stream guarded={change_clock,change_send,change_receive,&f};
 return rp_readback(h,c,r,&guarded);
}

int rp_fanout(struct rp_handle h,const struct nt_context *c,const struct nt_fanout *plan,const struct nt_stream *ops){
 struct rp_ticket *t=rp_get(h);if(!t)return SA_REFUSED;
 if(t->busy||t->ran||t->primary||t->raw_row!=5)return bad(t,t->busy?SA_REENTRY:SA_REPEAT);
 t->ran=t->busy=1;
 if(!plan||!c||!ops||c->deadline>(t->final?h.pool->close_end:h.pool->normal_end)||!!t->final!=(plan->command==2))return control_refuse(h,t,SA_IDENTITY);
 struct flow f={h,*ops};struct nt_stream wrapped={flow_clock,flow_send,flow_receive,&f};
 int rc=nt_fanout_stream(&t->transaction,&t->ledger,&t->budget,c,plan,&wrapped);if(rc)bad(t,rc);
 if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}

int rp_empty_list(struct rp_handle h,const struct nt_context *c,unsigned command,const struct nt_stream *ops){
 struct rp_ticket *t=admit(h);if(!t)return SA_REFUSED;
 if(!c||c->deadline>h.pool->normal_end||!ops||!ops->clock||!ops->send||!ops->receive){t->busy=0;return bad(t,SA_REFUSED);}
 struct flow f={h,*ops};struct nt_stream io={flow_clock,flow_send,flow_receive,&f};
 int rc=nt_empty_list_stream(&t->transaction,&t->ledger,&t->budget,c,command,&io);if(rc)bad(t,rc);
 if(t->primary&&!h.pool->primary)h.pool->primary=t->primary;
 t->busy=0;return t->primary;
}
