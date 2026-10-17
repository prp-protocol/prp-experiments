#include "session_flow.h"
#include <string.h>

static int fail(struct sf_flow *f,int rc){
 if(!f)return SA_REFUSED;
 if(!f->primary)f->primary=rc;
 else if(!f->secondary)f->secondary=rc;
 f->revision++;
 return f->primary;
}
static int same_domain(const struct nt_context *a,const struct nt_context *b){
 return a->socket==b->socket&&a->netns==b->netns&&a->epoch==b->epoch&&
        a->family==b->family&&a->port==b->port;
}
int sf_init(struct sf_flow *f,const struct sf_plan *p){
 if(!f)return SA_REFUSED;
 if(f->initialized||f->started||f->primary)return fail(f,SA_REPEAT);
 f->initialized=1;
 if(!p||!p->pool||!p->pool->initialized||p->pool->primary||
    !nt_selection_valid(&p->selection)||!((p->selection.match.scope==1&&!p->selection.match.alias)||(p->selection.match.scope==2&&p->selection.match.alias==1))||p->selection.match.handle||
    nt_session_state(&p->selection.match)!=1||p->selection.match.max_bytes||
    p->capacity<2||p->capacity>65535)return fail(f,SA_IDENTITY);
 for(unsigned i=0;i<5;i++){
  const struct nt_context *c=&p->context[i];
  if(!c->socket||!c->netns||!c->epoch||!c->port||c->family<16||!c->seq||
     !same_domain(c,&p->context[0])||
     c->deadline!=(i==4?p->pool->close_end:p->context[0].deadline)||
     c->deadline>(i==4?p->pool->close_end:p->pool->normal_end)||
     (i&&c->seq<=p->context[i-1].seq))return fail(f,SA_IDENTITY);
 }
 if(p->selection.valid_until!=p->context[0].deadline)return fail(f,SA_IDENTITY);
 f->plan=*p;
 for(unsigned i=0;i<5;i++)if(!rp_reserve(p->pool,i==4,&p->budget,&f->ticket[i]))return fail(f,SA_REFUSED);
 return 0;
}
struct guarded {struct sf_flow *f;struct nt_stream io;unsigned index;uint64_t revision;};
static int guard(struct guarded *g){
 if(g->f->revision==g->revision)return 1;
 /* Sticky refusal in the actual operation, while retaining returned raw/clock. */
 rp_readback(g->f->ticket[g->index],NULL,NULL,NULL);
 return 0;
}
static uint64_t tick(void *v){struct guarded *g=v;guard(g);uint64_t n=g->io.clock(g->io.arg);if(g->f->compact_started){if(n<g->f->compact_clock)rp_readback(g->f->ticket[g->index],NULL,NULL,NULL);else g->f->compact_clock=n;}guard(g);return n;}
static int send_one(void *v,const unsigned char *b,size_t n){
 struct guarded *g=v;if(!guard(g))return -1;
 int rc=g->io.send(g->io.arg,b,n);guard(g);return rc;
}
static void receive_one(void *v,size_t n,struct nt_reply *r){
 struct guarded *g=v;if(!guard(g)){r->rc=-1;return;}
 g->io.receive(g->io.arg,n,r);guard(g);
}
static int streams(const struct nt_stream *io){
 if(!io)return 0;
 for(unsigned i=0;i<5;i++)if(!io[i].clock||!io[i].send||!io[i].receive)return 0;
 return 1;
}
static int operation(struct sf_flow *f,unsigned i,const struct nt_stream *io){
 struct guarded g={f,io[i],i,f->revision};struct nt_stream s={tick,send_one,receive_one,&g};
 const struct nt_context *c=&f->plan.context[i];
 if(i==0)return rp_list(f->ticket[0],c,&f->plan.selection,&s);
 if(i==1)return rp_selected_readback(f->ticket[1],f->ticket[0],c,&f->pending,&s);
 if(i==2)return rp_session_change(f->ticket[2],f->ticket[1],c,12,&f->active,&s);
 if(i==3)return rp_session_active_readback(f->ticket[3],f->ticket[2],c,&f->active,&s);
 return rp_session_change(f->ticket[4],f->ticket[f->cleanup_active?3:1],c,13,f->cleanup_active?&f->active:&f->pending,&s);
}
int sf_activate(struct sf_flow *f,const struct nt_stream io[5]){
 if(!f)return SA_REFUSED;
 if(!f->initialized||f->started||f->busy||f->finished||f->primary)return fail(f,SA_REPEAT);
 f->started=f->busy=1;
 if(!streams(io)){f->busy=0;return fail(f,SA_REFUSED);}
 for(unsigned i=0;i<4&&!f->primary;i++){
  int rc=operation(f,i,io);if(rc){fail(f,rc);break;}
  if(i==0){
   struct rp_ticket *list=rp_get(f->ticket[0]);
   f->pending=f->plan.selection.match;f->pending.handle=list->transaction.selected_handle;
   f->active=f->pending;f->active.state=2;f->active.max_bytes=f->plan.capacity;
  }
 }
 f->observed=!f->primary&&rp_get(f->ticket[3])->transaction.readback_observed;
 f->busy=0;return f->primary;
}
int sf_active_ticket(const struct sf_flow *f,struct rp_handle *out){
 if(out)memset(out,0,sizeof(*out));
 if(!f||!out||!f->initialized||!f->started||f->busy||f->finished||f->archive_started||f->primary||!f->observed||!f->plan.pool||f->plan.pool->primary)return SA_REFUSED;
 struct rp_ticket *t=rp_get(f->ticket[3]);
 if(!t||t->busy||t->primary||t->persist_attempted||!t->transaction.accepted||!t->transaction.readback_observed||t->transaction.request[16]!=14)return SA_IDENTITY;
 const struct nt_readback *r=&t->transaction.expected_readback,*a=&f->active;
 if(nt_session_state(r)!=2||r->handle!=a->handle||r->generation!=a->generation||r->peer!=a->peer||r->scope!=a->scope||r->alias!=a->alias||r->direction!=a->direction||r->max_bytes!=a->max_bytes||memcmp(r->strong_id,a->strong_id,32)||!same_domain(&t->transaction.bound,&f->plan.context[3]))return SA_IDENTITY;
 *out=f->ticket[3];return 0;
}
struct checkpoint_io {struct sf_flow *flow;struct rp_store store;uint64_t revision;};
static uint64_t checkpoint_clock(void *v){
 struct checkpoint_io *c=v;uint64_t n=c->store.clock(c->store.arg);
 if(c->flow->plan.pool->primary&&!c->flow->primary)fail(c->flow,c->flow->plan.pool->primary);
 return n;
}
static void checkpoint_write(void *v,uint64_t id,const unsigned char *b,size_t n,struct rp_write_result *r){
 struct checkpoint_io *c=v;
 if(c->flow->revision!=c->revision||c->flow->primary){r->rc=SA_REENTRY;return;}
 c->store.write_once(c->store.arg,id,b,n,r);
}
int sf_checkpoint(struct sf_flow *f,const struct rp_store *store){
 struct rp_handle active;
 if(!f)return SA_REFUSED;
 if(f->checkpoint_started||sf_active_ticket(f,&active)||!store||!store->clock||!store->write_once)return fail(f,SA_REFUSED);
 f->checkpoint_started=f->busy=1;
 struct checkpoint_io c={f,*store,f->revision};struct rp_store guarded={checkpoint_clock,checkpoint_write,&c};
 unsigned indices[2]={0,2};
 for(unsigned j=0;j<2&&!f->primary;j++){
  unsigned i=indices[j];struct rp_ticket *t=rp_get(f->ticket[i]);
  if(!t||!t->ran||t->primary||t->busy||t->persist_attempted){fail(f,SA_IDENTITY);break;}
  int ok=(t->length||rp_encode(f->ticket[i],NULL))&&rp_persist(f->ticket[i],f->plan.context[3].deadline,&guarded);
  if(ok)f->archived[i]=1;
  if(!ok)fail(f,t->primary?t->primary:SA_CALLBACK);
  if(f->revision!=c.revision&&!f->primary)fail(f,SA_REENTRY);
 }
 f->busy=0;return f->primary;
}
int sf_finish(struct sf_flow *f,const struct nt_stream io[5]){
 if(!f)return SA_REFUSED;
 if(!f->initialized||!f->started||f->busy||f->finished)return fail(f,SA_REPEAT);
 f->finished=f->busy=1;
 struct rp_ticket *get=rp_get(f->ticket[f->cleanup_active?3:1]);
 if(!streams(io))fail(f,SA_REFUSED);
 else if(get&&!get->primary&&get->transaction.readback_observed){
  int rc=operation(f,4,io);if(rc)fail(f,rc);
  else f->delete_ack=1;
 }
 /* No observed incarnation means no fabricated handle or broad cleanup. */
 f->busy=0;return f->primary;
}
int sf_archive(struct sf_flow *f,uint64_t end,const struct rp_store *store){
 if(!f)return SA_REFUSED;
 if(!f->finished||f->busy||f->archive_started||!store)return fail(f,SA_REPEAT);
 f->archive_started=f->busy=1;
 for(unsigned i=0;i<5;i++){
  struct rp_ticket *t=rp_get(f->ticket[i]);if(!t||!t->ran)continue;
  if(t->persist_attempted){if(!f->primary)fail(f,t->primary?t->primary:SA_CALLBACK);continue;}
  if((!t->length&&!rp_encode(f->ticket[i],NULL))||!rp_persist(f->ticket[i],end,store))fail(f,SA_CALLBACK);
  else f->archived[i]=1;
 }
 f->busy=0;return f->primary;
}

static int same_readback(const struct nt_readback *a,const struct nt_readback *b){return a->command==b->command&&a->handle==b->handle&&a->peer==b->peer&&a->max_bytes==b->max_bytes&&a->generation==b->generation&&a->alias==b->alias&&a->scope==b->scope&&a->direction==b->direction&&a->state==b->state&&!memcmp(a->strong_id,b->strong_id,32);}
struct compact_io {struct sf_flow *f;struct rp_store store;uint64_t revision,active_revision;struct nt_readback active;struct nt_context context;};
static int compact_guard(struct compact_io *c){
 struct sf_flow *f=c->f;struct rp_ticket *active=rp_get(f->ticket[3]);
 if(f->revision!=c->revision||f->primary||f->finished||f->plan.pool->primary||!active||active->busy||active->primary||active->persist_attempted||active->revision!=c->active_revision||!active->transaction.accepted||!active->transaction.readback_observed||active->transaction.request[16]!=14||!same_readback(&active->transaction.expected_readback,&c->active)||!same_readback(&f->active,&c->active)||!same_domain(&active->transaction.bound,&c->context)||active->transaction.bound.seq!=c->context.seq||active->transaction.bound.deadline!=c->context.deadline){
  if(!f->primary)fail(f,f->plan.pool->primary?f->plan.pool->primary:SA_REENTRY);
  rp_readback(f->ticket[1],NULL,NULL,NULL);return 0;
 }
 return 1;
}
static uint64_t compact_clock(void *v){struct compact_io *c=v;compact_guard(c);uint64_t n=c->store.clock(c->store.arg);if(n>c->f->compact_clock)c->f->compact_clock=n;compact_guard(c);return n;}
static void compact_write(void *v,uint64_t id,const unsigned char *b,size_t n,struct rp_write_result *r){struct compact_io *c=v;if(!compact_guard(c)){r->rc=SA_REENTRY;return;}c->store.write_once(c->store.arg,id,b,n,r);compact_guard(c);}
int sf_compact(struct sf_flow *f,const struct rp_store *store){
 struct rp_handle active;
 if(!f)return SA_REFUSED;
 if(f->compact_started||!f->archived[0]||!f->archived[2]||sf_active_ticket(f,&active)||!store||!store->clock||!store->write_once)return fail(f,SA_REFUSED);
 f->compact_started=1;struct rp_ticket *pending=rp_get(f->ticket[1]),*a=rp_get(active);
 if(!pending||pending->busy||pending->primary||pending->persist_attempted||!pending->transaction.readback_observed||pending->transaction.request[16]!=14)return fail(f,SA_IDENTITY);
 const struct nt_readback *p=&pending->transaction.expected_readback,*r=&a->transaction.expected_readback;
 if(p->handle!=r->handle||p->generation!=r->generation||p->peer!=r->peer||p->scope!=r->scope||p->alias!=r->alias||p->direction!=r->direction||memcmp(p->strong_id,r->strong_id,32)||nt_session_state(p)!=1||nt_session_state(r)!=2)return fail(f,SA_IDENTITY);
 f->cleanup_active=1;f->compact_clock=a->transaction.after;
 f->busy=1;struct compact_io c={f,*store,f->revision,a->revision,a->transaction.expected_readback,a->transaction.bound};struct rp_store io={compact_clock,compact_write,&c};
 if((pending->length||rp_encode(f->ticket[1],NULL))&&rp_persist(f->ticket[1],f->plan.context[3].deadline,&io))f->archived[1]=1;
 else fail(f,pending->primary?pending->primary:SA_CALLBACK);
 f->busy=0;return f->primary;
}
