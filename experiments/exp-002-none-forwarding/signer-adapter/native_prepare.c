#include "native_prepare.h"
#include <string.h>
static int refuse(struct np_intent *i,int error){
 if(!i->primary)i->primary=error;
 struct rn_port *p=i->port;
 struct rp_ticket *t=p&&p->bound?rp_get(p->retained):NULL;
 if(t){t->revision++;if(!t->primary)t->primary=error;else if(!t->secondary)t->secondary=error;
  if(!t->transaction.primary)t->transaction.primary=t->primary;}
 if(p&&p->pool&&!p->pool->primary)p->pool->primary=i->primary;
 return i->primary;
}
static int bind_intent(struct np_intent *i,struct rn_port *p,const struct nt_prepare *s,const struct sa_policy *policy,const struct nt_remote_m1 *remote){
 if(!i)return SA_REFUSED;
 if(i->started)return refuse(i,SA_REPEAT);
 i->started=1;
 if(!p||!p->initialized||p->bound||p->busy||p->primary||p->transport.sent||
    !p->pool||p->pool->primary||!s||s->kind!=(remote?2:1)||!s->peer||
    !((s->scope==1&&!s->alias)||(s->scope==2&&s->alias==1))||!policy||
    !policy->fixture_authorized||!policy->provider||!policy->key_reference||
    !policy->expected.context.attempt||policy->expected.context.handle||policy->expected.prefix_len||
    policy->expected.context.endpoint!=s->peer||
    policy->expected.context.socket!=p->transport.context.socket||
    policy->expected.context.epoch!=p->transport.context.epoch||
    policy->expected.context.netns!=p->transport.context.netns||
    !policy->expected.deadline||policy->expected.deadline>p->transport.context.deadline||
    memcmp(policy->expected.public_key,s->public_key,32))return refuse(i,SA_IDENTITY);
 if(remote&&(!remote->generation||remote->peer!=s->peer||!remote->deadline||
    remote->not_before>=remote->deadline||
    remote->context.socket!=p->transport.context.socket||
    remote->context.netns!=p->transport.context.netns||
    remote->context.epoch!=p->transport.context.epoch))return refuse(i,SA_IDENTITY);
 i->port=p;i->context=p->transport.context;i->setup=*s;i->policy=*policy;
 if(remote){
  i->remote=*remote;i->remote_bound=1;
  /* Same receiving-host clock only. Carry the capture/persistence frontier
   * into the FIRST PREPARE admission, not merely the later signature check. */
  if(p->transport.last<remote->not_before)p->transport.last=remote->not_before;
  if(p->transport.operation_end>remote->deadline)p->transport.operation_end=remote->deadline;
 }
 return 0;
}
int np_bind(struct np_intent *i,struct rn_port *p,const struct nt_prepare *s,const struct sa_policy *policy){
 return bind_intent(i,p,s,policy,NULL);
}
int np_bind_m2(struct np_intent *i,struct rn_port *p,const struct nt_prepare *s,const struct sa_policy *policy,const struct nt_remote_m1 *remote){
 if(!remote){if(!i)return SA_REFUSED;i->started=1;return refuse(i,SA_IDENTITY);}
 return bind_intent(i,p,s,policy,remote);
}
static int context(const struct nt_context *a,const struct nt_context *b){
 return a->socket==b->socket&&a->epoch==b->epoch&&a->netns==b->netns&&a->deadline==b->deadline&&a->seq==b->seq&&a->port==b->port&&a->family==b->family;
}
static int sign_intent(struct np_intent *i,struct sc_client *client,const unsigned char *wire,size_t length,struct sb_backend *verifier,const struct sa_ops *ops,unsigned m2){
 if(!i)return SA_REFUSED;
 if(i->primary)return i->primary;
 if(!i->started||i->attempted)return refuse(i,SA_REPEAT);
 i->attempted=1;
 if(i->remote_bound!=m2)return refuse(i,SA_IDENTITY);
 struct rn_port *p=i->port;
 if(!p||!p->bound||p->busy||p->primary||p->pool->primary||!p->selected)return refuse(i,SA_IDENTITY);
 struct rp_handle h=*p->selected;
 if(h.pool!=p->retained.pool||h.id!=p->retained.id||h.slot!=p->retained.slot||h.generation!=p->retained.generation)return refuse(i,SA_IDENTITY);
 struct rp_ticket *t=rp_get(h);
 if(!t||t->busy||t->primary||t->final||!t->prepared||!t->ran||!t->commands||!t->facts||
    t->sign_attempted||t->persist_attempted||t->length||!t->transaction.accepted||
    !context(&i->context,&p->transport.context)||!context(&i->context,&t->transaction.bound))return refuse(i,SA_IDENTITY);
 const struct ns_port *n=&p->transport;const struct rp_socket_fact *f=&t->socket_fact;
 if(!f->present||f->primary||n->primary||!n->sent||!f->possible||f->send_errno||
    f->fd!=n->fd||f->dev!=n->dev||f->ino!=n->ino||f->send_result<=0||
    (size_t)f->send_result!=t->transaction.sent_length||f->send_result!=n->send_result||
    n->request_length>sizeof(n->request)||n->request_length!=t->transaction.sent_length||
    memcmp(n->request,t->transaction.sent,n->request_length)||
    f->calls!=n->calls||f->calls!=t->ledger.calls||!f->calls||
    f->send_before!=n->send_before||f->send_after!=n->send_after||f->receive_after!=n->receive_after||
    !t->transaction.expires_at||t->transaction.payload_length!=(m2?105u:63u))return refuse(i,SA_IDENTITY);
 /* Local prefix is not remote trust. The unchanged M2 path verifies the
  * independently admitted remote M1 signature, computes its complete binding,
  * and checks binding/generation in this prefix before signing anything. */
 struct sa_policy policy=i->policy;
 policy.expected.context.handle=t->transaction.handle;
 policy.expected.prefix_len=m2?105:63;memcpy(policy.expected.prefix,t->transaction.payload,policy.expected.prefix_len);
 if(policy.expected.deadline>t->transaction.expires_at)policy.expected.deadline=t->transaction.expires_at;
 if(m2&&policy.expected.deadline>i->remote.deadline)policy.expected.deadline=i->remote.deadline;
 int rc=m2?rp_sign_m2(h,&i->context,&i->setup,client,&policy,&i->remote,wire,length,verifier,ops):
           rp_sign(h,&i->context,&i->setup,client,&policy,NULL,0,ops);
 if(rc)return refuse(i,rc);
 return 0;
}

int np_sign(struct np_intent *i,struct sc_client *client,const struct sa_ops *ops){
 return sign_intent(i,client,NULL,0,NULL,ops,0);
}
int np_sign_m2(struct np_intent *i,struct sc_client *client,const unsigned char *wire,size_t length,struct sb_backend *verifier,const struct sa_ops *ops){
 return sign_intent(i,client,wire,length,verifier,ops,1);
}
