#include "transaction.h"
#include <string.h>
static uint16_t u16(const void *p){uint16_t v;memcpy(&v,p,2);return v;}
static uint32_t u32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static void w16(void *p,uint16_t v){memcpy(p,&v,2);}
static void w32(void *p,uint32_t v){memcpy(p,&v,4);}
static void be16(unsigned char *p,unsigned v){p[0]=v>>8;p[1]=v;}
static void be32(unsigned char *p,uint32_t v){p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;}
static int fail(struct nt_state *s,int e){if(!s->primary)s->primary=e;else if(!s->secondary)s->secondary=e;s->accepted=0;return s->primary;}
static void attr(struct nt_state *s,unsigned t,const void *v,size_t n){size_t a=s->request_length;w16(s->request+a,(uint16_t)(n+4));w16(s->request+a+2,t);memcpy(s->request+a+4,v,n);s->request_length+=(n+7)&~(size_t)3;}
static int begin(struct nt_state *s,const struct nt_context *c,unsigned cmd){
 if(!s)return 0;
 if(s->started){fail(s,s->busy?SA_REENTRY:SA_REPEAT);return 0;}
 s->started=1;s->busy=1;
 if(!c||c->family<16||!c->seq||!c->socket||!c->epoch||!c->netns||!c->deadline){fail(s,SA_IDENTITY);s->busy=0;return 0;}
 s->bound=*c;
 s->request_length=20;w16(s->request+4,c->family);w16(s->request+6,5);w32(s->request+8,c->seq);w32(s->request+12,c->port);s->request[16]=cmd;s->request[17]=1;return 1;
}
static int tick(struct nt_state *s,const struct nt_context *c,const struct nt_ops *o,uint64_t *ret){
 uint64_t t=o->clock(o->arg);*ret=t;
 if(t>=c->deadline||t<s->last){s->time_refused=1;fail(s,SA_TIME);}s->last=t;
 return !s->primary;
}
static int parse(struct nt_state *s,const struct nt_context *c,unsigned cmd,int complete){
 if(s->empty_list_command)return nt_empty_list_parse(s,c,complete);
 if(s->fanout.command)return nt_fanout_parse(s,c,complete);
 if(s->carrier.command)return nt_carrier_parse(s,c,complete);
 if(cmd==15)return nt_list_parse(s,c,complete);
 const unsigned char *b=s->raw.bytes;size_t n=s->raw.length,at=0;int ack=0,result=0;
 if(n>sizeof(s->raw.bytes)||s->raw.rc||s->raw.truncated||s->raw.sender||
 s->raw.context.socket!=c->socket||s->raw.context.epoch!=c->epoch||s->raw.context.netns!=c->netns)return fail(s,SA_IDENTITY);
 while(at<n){
  if(n-at<16)return fail(s,SA_SHAPE);
  const unsigned char *p=b+at;size_t len=u32(p),step=(len+3)&~(size_t)3;unsigned type=u16(p+4),flags=u16(p+6);
  if(len<16||len>n-at||step>n-at||u32(p+8)!=c->seq||u32(p+12)!=c->port)return fail(s,SA_SHAPE);
  for(size_t z=len;z<step;z++)if(p[z])return fail(s,SA_SHAPE);
  if(type==2){
   /* Restrictive successful ACK: errno0 + exact echoed request header, no TLVs.
    * Negative replies remain raw, including unsupported extack/body shapes. */
   if(len<20)return fail(s,SA_SHAPE);
   int32_t error;memcpy(&error,p+16,4);
   if(error)return fail(s,SA_CALLBACK);
   if(ack++||len!=36||(flags!=0&&flags!=256)||memcmp(p+20,s->request,16))return fail(s,SA_SHAPE);
  }else{
   if(type!=c->family||flags||result++||len<20||p[16]!=cmd||p[17]!=1||u16(p+18))return fail(s,SA_SHAPE);
   if(cmd==12||cmd==14||cmd==53||cmd==55||cmd==57){if(!nt_readback_attrs(s,p+20,len-20))return fail(s,SA_IDENTITY);at+=step;continue;}
   unsigned seen=0;size_t a=20;
   while(a<len){
    if(len-a<4)return fail(s,SA_SHAPE);
    unsigned l=u16(p+a),t=u16(p+a+2);size_t aligned=(l+3)&~(size_t)3;
    if(l<4||aligned>len-a)return fail(s,SA_SHAPE);
    for(size_t z=l;z<aligned;z++)if(p[a+z])return fail(s,SA_SHAPE);
    const unsigned char *v=p+a+4;size_t size=l-4;unsigned bit=0;
    if(t==19&&size==0){a+=aligned;continue;}
    if(cmd==16&&t==24&&size==8){bit=1;memcpy(&s->handle,v,8);}
    else if(cmd==16&&t==30&&size==4){bit=2;s->expires=u32(v);}
    else if((cmd==16&&t==28&&(size==63||size==105))||(cmd==17&&t==31&&(size==130||size==172))){bit=4;s->payload_length=size;memcpy(s->payload,v,size);}
    else return fail(s,SA_SHAPE);
    if(seen&bit)return fail(s,SA_SHAPE);
    seen|=bit;a+=aligned;
   }
   if(seen!=(cmd==16?7u:4u)||(cmd==16&&(!s->handle||s->expires!=5000)))return fail(s,SA_SHAPE);
  }
  at+=step;
 }
 if(ack!=1||result!=((cmd==13||cmd==18||cmd==19||cmd==47||cmd==54)?0:1))return complete?fail(s,SA_SHAPE):-1;
 return 0;
}
static int run(struct nt_state *s,const struct nt_context *c,const struct nt_ops *o,unsigned cmd){
 struct nt_context bound=*c;
 if(!o||!o->clock||!o->exchange){fail(s,SA_REFUSED);goto done;}
 struct nt_ops ops=*o;w32(s->request,(uint32_t)s->request_length);
 if(!tick(s,&bound,&ops,&s->before))goto done;
 s->sent_length=s->request_length;memcpy(s->sent,s->request,s->sent_length);
 s->possible=1;ops.exchange(ops.arg,s->request,s->request_length,&s->raw);
 /* Raw returned evidence is retained before clock/sticky rejection. */
 if(s->raw.rc)fail(s,SA_CALLBACK);
 int clock_ok=tick(s,&bound,&ops,&s->after);
 if(s->request_length!=s->sent_length||memcmp(s->sent,s->request,s->sent_length))fail(s,SA_IDENTITY);
 if(!clock_ok||s->primary)goto done;
 if(!parse(s,&bound,cmd,1))s->accepted=1;
 done:s->busy=0;return s->primary;
}
int nt_prepare(struct nt_state *s,const struct nt_context *c,const struct nt_prepare *p,const struct nt_ops *o){
 if(!begin(s,c,16))return s?s->primary:SA_REFUSED;
 if(!p||!p->peer||(p->kind!=1&&p->kind!=2)||!((p->scope==1&&!p->alias)||(p->scope==2&&p->alias==1))){s->busy=0;return fail(s,SA_REFUSED);}
 s->setup=*p;
 uint16_t suite=2,identity=1;attr(s,23,&p->peer,8);attr(s,33,&p->scope,1);if(p->alias)attr(s,4,&p->alias,2);attr(s,25,&p->kind,1);attr(s,22,&suite,2);attr(s,26,&identity,2);attr(s,27,p->public_key,32);
 return run(s,c,o,16);
}
int nt_commit(struct nt_state *s,const struct nt_context *c,uint64_t handle,const struct sc_client *signed_wire,const struct nt_ops *o){
 if(!begin(s,c,17))return s?s->primary:SA_REFUSED;
 if(!handle||!signed_wire||!signed_wire->accepted||signed_wire->primary||(signed_wire->wire_length!=130&&signed_wire->wire_length!=172)) {s->busy=0;return fail(s,SA_REFUSED);}
 if(c->deadline>signed_wire->deadline||signed_wire->context.handle!=handle||signed_wire->context.socket!=c->socket||signed_wire->context.epoch!=c->epoch||signed_wire->context.netns!=c->netns){s->busy=0;return fail(s,SA_IDENTITY);}
 s->last=signed_wire->final_time;
 unsigned char expected[172];size_t n=signed_wire->wire_length;memcpy(expected,signed_wire->wire,n);
 attr(s,24,&handle,8);attr(s,29,expected+n-64,64);
 int rc=run(s,c,o,17);
 if(!rc&&(s->payload_length!=n||memcmp(s->payload,expected,n)))return fail(s,SA_IDENTITY);
 return rc;
}
int nt_sign_prepared(struct nt_state *pre,const struct nt_context *context,const struct nt_prepare *setup,
                     struct sc_client *client,const struct sa_policy *policy,const unsigned char binding[32],uint32_t generation,const struct sa_ops *ops){
 if(!pre)return SA_REFUSED;
 if(pre->busy)return fail(pre,SA_REENTRY);
 if(pre->sign_consumed)return fail(pre,SA_REPEAT);
 pre->sign_consumed=1;
 if(!context||!setup||!client||!policy||!pre->accepted||pre->primary||
    context->socket!=pre->bound.socket||context->netns!=pre->bound.netns||context->epoch!=pre->bound.epoch||
    context->seq!=pre->bound.seq||context->family!=pre->bound.family||context->port!=pre->bound.port||context->deadline!=pre->bound.deadline||
    setup->peer!=pre->setup.peer||setup->scope!=pre->setup.scope||setup->alias!=pre->setup.alias||setup->kind!=pre->setup.kind||memcmp(setup->public_key,pre->setup.public_key,32)||
    pre->request[16]!=16||pre->payload_length!=(setup->kind==1?63u:105u)||
    pre->handle!=policy->expected.context.handle||context->socket!=policy->expected.context.socket||
    context->epoch!=policy->expected.context.epoch||context->netns!=policy->expected.context.netns||
    setup->peer!=policy->expected.context.endpoint||memcmp(setup->public_key,policy->expected.public_key,32)||
    policy->expected.deadline>context->deadline||(pre->expires_at&&policy->expected.deadline>pre->expires_at))return fail(pre,SA_IDENTITY);
 /* Independent expected prefix remains mandatory: never self-approve a nonce
  * or M1/M2 chain from a structurally valid response. Expiry mapping is external. */
 if(client->started||client->signer.started)return fail(pre,SA_REPEAT);
 client->signer.last_time=pre->last>pre->after?pre->last:pre->after;
 return sc_sign(client,policy,pre->payload,pre->payload_length,binding,generation,ops);
}
static int hash_wire(struct sb_backend *b,const struct sc_client *c,const char *domain,unsigned char out[32]){
 unsigned char input[256];size_t d=strlen(domain);
 if(!c||!c->accepted||c->primary||(c->wire_length!=130&&c->wire_length!=172)||d+4+c->wire_length>sizeof(input))return 0;
 memcpy(input,domain,d);be32(input+d,(uint32_t)c->wire_length);memcpy(input+d+4,c->wire,c->wire_length);return sb_sha256(b,input,d+4+c->wire_length,out);
}
int nt_m1_binding(struct sb_backend *b,const struct sc_client *c,unsigned char out[32]){return out&&c&&c->wire_length==130&&hash_wire(b,c,"PRP-HS2-M1-BINDING-v4",out);}
int nt_direct(struct sb_backend *b,const struct sc_client *c,uint32_t transfer,unsigned char *out,size_t cap,size_t *n){
 unsigned char digest[32];if(n)*n=0;
 if(!n||!out||!transfer||!c||cap<54+c->wire_length||!hash_wire(b,c,"PRP-HS2-FRAGMENT-v4",digest))return 0;
 be16(out,1);be16(out+2,1);out[4]=7;out[5]=0;be16(out+6,(unsigned)(46+c->wire_length));
 out[8]=2;out[9]=c->wire_length==130?1:2;be16(out+10,0);be32(out+12,transfer);be16(out+16,0);be16(out+18,(unsigned)c->wire_length);be16(out+20,2);memcpy(out+22,digest,32);memcpy(out+54,c->wire,c->wire_length);*n=54+c->wire_length;return 1;
}

struct stream_bridge {struct nt_state *s;struct nt_ledger *ledger;struct nt_budget budget;struct nt_context context;struct nt_stream ops;};
static uint64_t bridge_clock(void *v){struct stream_bridge *b=v;uint64_t t=b->ops.clock(b->ops.arg);if(b->s->expires_at&&t>=b->s->expires_at){b->s->time_refused=1;fail(b->s,SA_TIME);}return t;}
static int bridge_tick(struct stream_bridge *b,uint64_t *t){struct nt_ops ops={bridge_clock,NULL,b};return tick(b->s,&b->context,&ops,t);}
static void bridge_exchange(void *v,const unsigned char *req,size_t n,struct nt_reply *out){
 struct stream_bridge *b=v;struct nt_state *s=b->s;struct nt_ledger *l=b->ledger;
 /* The original admission clock is the expiry origin, never a reply clock. */
 if(req[16]==16){
  if(b->budget.ticks_per_ms>UINT64_MAX/5000||UINT64_MAX-s->before<5000*b->budget.ticks_per_ms){s->possible=0;fail(s,SA_TIME);return;}
  s->expires_at=s->before+5000*b->budget.ticks_per_ms;
  if(s->expires_at>b->context.deadline)s->expires_at=b->context.deadline;
  b->context.deadline=s->expires_at;
 }
 if(req[16]==15&&s->before<s->selection.not_before){s->possible=0;fail(s,SA_TIME);return;}
 if((req[16]==53||req[16]==55)&&(b->budget.ticks_per_ms>UINT64_MAX/300000||s->before>UINT64_MAX-300000*b->budget.ticks_per_ms)){s->possible=0;fail(s,SA_TIME);return;}
 l->send_called=1;l->send_rc=b->ops.send(b->ops.arg,req,n);
 if(l->send_rc)fail(s,SA_CALLBACK);
 if(!bridge_tick(b,&l->send_after))return;
 out->context=b->context;
 while(!s->primary){
  if(l->calls==b->budget.calls||l->retained==b->budget.body_bytes){l->overflow=1;fail(s,SA_REFUSED);break;}
  struct nt_record *r=&l->records[l->calls++]; /* attempted admission consumes a slot */
  if(!bridge_tick(b,&r->before))break;
  struct nt_reply raw={0};size_t room=b->budget.body_bytes-l->retained;
  r->called=1;b->ops.receive(b->ops.arg,room,&raw);
  r->offset=l->retained;r->reported=raw.length;r->context=raw.context;r->rc=raw.rc;r->truncated=raw.truncated;r->sender=raw.sender;
  size_t kept=raw.length;if(kept>room)kept=room;if(kept>sizeof(raw.bytes))kept=sizeof(raw.bytes);
  r->retained=kept;memcpy(out->bytes+l->retained,raw.bytes,kept);l->retained+=kept;out->length=l->retained;
  if(SIZE_MAX-l->reported<raw.length){l->reported=SIZE_MAX;l->overflow=1;}else l->reported+=raw.length;
  if(raw.rc)fail(s,SA_CALLBACK);
  if(raw.length>room||raw.length>sizeof(raw.bytes)){l->overflow=1;fail(s,SA_SHAPE);}
  if(raw.truncated||!raw.length)fail(s,SA_SHAPE);
  if(raw.sender||raw.context.socket!=b->context.socket||raw.context.epoch!=b->context.epoch||raw.context.netns!=b->context.netns)fail(s,SA_IDENTITY);
  if(!bridge_tick(b,&r->after))break;
  if(s->primary)break;
  /* Parse the new datagram separately to reject split/truncated nlmsg. The
   * cumulative pass detects duplicates across returns. */
  size_t at=r->offset;
  while(at<out->length){if(out->length-at<16){fail(s,SA_SHAPE);break;}size_t z=u32(out->bytes+at);if(z<16||z>out->length-at||((z+3)&~(size_t)3)>out->length-at){fail(s,SA_SHAPE);break;}at+=(z+3)&~(size_t)3;}
  if(s->primary)break;
  int result=parse(s,&b->context,req[16],0);
  if(result==0||s->primary)break;
 }
}
static int stream_init(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_stream *ops,struct stream_bridge *b){
 if(!s)return 0;
 if(s->started){fail(s,s->busy?SA_REENTRY:SA_REPEAT);return 0;}
 if(!l||l->started||l->calls||l->retained||l->reported||l->send_called||!budget||!c||!ops||!ops->clock||!ops->send||!ops->receive||!budget->calls||budget->calls>NT_RECORDS||!budget->body_bytes||budget->body_bytes>4096||budget->metadata_bytes<sizeof(struct nt_ledger)-sizeof(l->records)+budget->calls*sizeof(struct nt_record)||!budget->ticks_per_ms){s->started=1;fail(s,SA_REFUSED);return 0;}
 l->started=1;*b=(struct stream_bridge){s,l,*budget,*c,*ops};return 1;
}
int nt_prepare_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_prepare *p,const struct nt_stream *ops){struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;struct nt_ops o={bridge_clock,bridge_exchange,&b};return nt_prepare(s,c,p,&o);}
int nt_commit_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,uint64_t h,const struct sc_client *client,const struct nt_stream *ops){struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;struct nt_ops o={bridge_clock,bridge_exchange,&b};return nt_commit(s,c,h,client,&o);}
int nt_sign_m2(struct nt_state *pre,const struct nt_context *c,const struct nt_prepare *setup,struct sc_client *client,const struct sa_policy *policy,const struct nt_remote_m1 *admission,const unsigned char *wire,size_t n,struct sb_backend *verifier,const struct sa_ops *ops){
 if(!pre)return SA_REFUSED;
 if(pre->busy)return fail(pre,SA_REENTRY);
 if(pre->sign_consumed)return fail(pre,SA_REPEAT);
 pre->remote_length=n;if(wire)memcpy(pre->remote_m1,wire,n>130?130:n);
 if(!pre->accepted||pre->primary||!c||!setup||!client||!policy||!admission||!wire||n!=130||!verifier||!ops||!ops->clock||setup->kind!=2||!pre->expires_at||!admission->generation||admission->peer!=setup->peer||admission->context.socket!=c->socket||admission->context.netns!=c->netns||admission->context.epoch!=c->epoch||!admission->deadline||memcmp(wire,admission->expected_wire,130)){pre->sign_consumed=1;return fail(pre,SA_IDENTITY);}
 struct nt_remote_m1 trust=*admission;unsigned char received[130];memcpy(received,wire,130);struct nt_context bound=*c;
 if(bound.deadline>pre->expires_at)bound.deadline=pre->expires_at;
 if(bound.deadline>trust.deadline)bound.deadline=trust.deadline;
 if(policy->expected.deadline>bound.deadline){pre->sign_consumed=1;return fail(pre,SA_TIME);}
 struct nt_ops clocks={ops->clock,NULL,ops->arg};pre->busy=1;
 if(!tick(pre,&bound,&clocks,&pre->remote_before))goto rejected;
 if(pre->before<trust.not_before||pre->remote_before<trust.not_before){fail(pre,SA_TIME);goto rejected;}
 int rc=sb_verify_m1(verifier,received,trust.public_key);pre->remote_verify_rc=rc;
 if(rc!=1)fail(pre,SA_IDENTITY);
 if(!tick(pre,&bound,&clocks,&pre->remote_after))goto rejected;
 struct sc_client remote={0};remote.accepted=1;remote.wire_length=130;memcpy(remote.wire,received,130);unsigned char binding[32];
 if(!nt_m1_binding(verifier,&remote,binding))fail(pre,SA_CALLBACK);
 if(!tick(pre,&bound,&clocks,&pre->remote_hash_after))goto rejected;
 pre->busy=0;
 return nt_sign_prepared(pre,c,setup,client,policy,binding,trust.generation,ops);
 rejected:pre->busy=0;pre->sign_consumed=1;return pre->primary;
}

int nt_cancel_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,uint64_t handle,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(!begin(s,c,18))return s?s->primary:SA_REFUSED;
 if(!handle){s->busy=0;return fail(s,SA_IDENTITY);}attr(s,24,&handle,8);
 struct nt_ops o={bridge_clock,bridge_exchange,&b};return run(s,c,&o,18);
}

int nt_cancel_peer_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,uint64_t peer,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(!begin(s,c,18))return s?s->primary:SA_REFUSED;
 if(!peer){s->busy=0;return fail(s,SA_IDENTITY);}attr(s,23,&peer,8);
 struct nt_ops o={bridge_clock,bridge_exchange,&b};return run(s,c,&o,18);
}

int nt_carrier_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_carrier *plan,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(!plan||!((plan->command==1||plan->command==2||plan->command==75)?!plan->ifindex:((plan->command==60||plan->command==61||plan->command==62)&&plan->ifindex))||!plan->population||plan->population>4){s->started=1;return fail(s,SA_REFUSED);}
 s->carrier=*plan;if(!begin(s,c,plan->command))return s->primary;
 attr(s,1,"ethernet",9);if(plan->ifindex){uint32_t index=plan->ifindex;attr(s,9,&index,4);}
 struct nt_ops o={bridge_clock,bridge_exchange,&b};return run(s,c,&o,plan->command);
}

int nt_readback_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_readback *expected,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(!expected||!nt_readback_valid(expected)){s->started=1;return fail(s,SA_REFUSED);}
 struct nt_readback bound=*expected;s->expected_readback=bound;
 if(!begin(s,c,bound.command))return s?s->primary:SA_REFUSED;
 uint16_t suite=2,identity=1;
 if(bound.command==14)attr(s,20,&bound.handle,8);
 else if(bound.command==57)attr(s,22,&suite,2);
 else {attr(s,23,&bound.peer,8);attr(s,33,&bound.scope,1);attr(s,4,&bound.alias,2);attr(s,69,&identity,2);attr(s,70,bound.strong_id,32);}
 struct nt_ops o={bridge_clock,bridge_exchange,&b};int rc=run(s,c,&o,bound.command);
 if(memcmp(&bound,&s->expected_readback,sizeof(bound)))return fail(s,SA_IDENTITY);
 if(!rc&&(bound.command==53||bound.command==55)){
  if(budget->ticks_per_ms>UINT64_MAX/s->expires||s->before>UINT64_MAX-budget->ticks_per_ms*s->expires)return fail(s,SA_TIME);
  s->expires_at=s->before+budget->ticks_per_ms*s->expires;if(s->expires_at>c->deadline)s->expires_at=c->deadline;
  if(s->last>=s->expires_at)return fail(s,SA_TIME);
 }
 s->readback_observed=!rc&&s->accepted;return rc;
}

int nt_list_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_selection *selection,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(!nt_selection_valid(selection)||c->deadline>selection->valid_until){s->started=1;return fail(s,SA_REFUSED);}
 struct nt_selection pinned=*selection;s->selection=pinned;
 if(!begin(s,c,15))return s->primary;
 /* Request ACK to retain errors; a successful dump completes with DONE,
  * since the Linux dump machinery suppresses a separate successful ACK. */
 w16(s->request+6,0x305);
 struct nt_ops o={bridge_clock,bridge_exchange,&b};int rc=run(s,c,&o,15);
 if(memcmp(&pinned,&s->selection,sizeof(pinned)))return fail(s,SA_IDENTITY);
 return rc;
}

int nt_control_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_prepare *setup,const struct sc_client *client,const struct nt_control *policy,struct sb_backend *hash,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(policy)s->control=*policy;
 if(!setup||!policy||!client||!client->accepted||client->primary||(client->wire_length!=130&&client->wire_length!=172)||policy->peer!=setup->peer||!policy->peer||!policy->capacity||policy->capacity>65535||c->deadline>client->deadline||client->context.socket!=c->socket||client->context.epoch!=c->epoch||client->context.netns!=c->netns||client->context.endpoint!=policy->peer||!((policy->command==47&&setup->scope==1&&!setup->alias&&!policy->transfer)||(policy->command==19&&setup->scope==2&&setup->alias==1&&policy->transfer&&hash))){s->started=1;return fail(s,SA_IDENTITY);}
 s->control=*policy;struct nt_control pinned=*policy;
 if(!begin(s,c,pinned.command))return s->primary;
 size_t wire=client->wire_length,body=wire+(pinned.command==19?54:4);memcpy(s->payload,client->wire,wire);s->payload_length=wire;
 /* Whole-segment geometry only; reservation is enforced by the owning port. */
 if(body>pinned.capacity||body>226||20+12+((body+7)&~(size_t)3)>sizeof(s->request)){s->busy=0;return fail(s,SA_SHAPE);}
 if(s->last<client->final_time)s->last=client->final_time;
 struct nt_ops o={bridge_clock,bridge_exchange,&b};
 if(!tick(s,c,&o,&s->control_hash_before)){s->busy=0;return s->primary;}
 unsigned char frame[226];size_t n=body;
 if(pinned.command==19){struct sc_client copy=*client;copy.wire_length=wire;memcpy(copy.wire,s->payload,wire);if(!nt_direct(hash,&copy,pinned.transfer,frame,sizeof(frame),&n))fail(s,SA_CALLBACK);}
 else {struct sc_client copy=*client;copy.wire_length=wire;memcpy(copy.wire,s->payload,wire);if(!sc_adjacent_public(&copy,frame,sizeof(frame),&n))fail(s,SA_CALLBACK);}
 if(!s->primary){attr(s,23,&pinned.peer,8);attr(s,pinned.command==19?32:232,frame,n);}
 if(!tick(s,c,&o,&s->control_hash_after)){s->busy=0;return s->primary;}
 int rc=run(s,c,&o,pinned.command);
 if(client->wire_length!=wire||memcmp(client->wire,s->payload,wire)||memcmp(&s->control,&pinned,sizeof(pinned)))return fail(s,SA_IDENTITY);
 return rc;
}

/* CTX_GET can materialize state: a lost reply is not rollback. */
int nt_member_context_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_member_context *plan,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(!plan||!plan->handle||!plan->generation||(plan->direction!=1&&plan->direction!=2)){s->started=1;return fail(s,SA_REFUSED);}
 s->member_context=*plan;s->carrier=(struct nt_carrier){76,0,1};
 if(!begin(s,c,76))return s->primary;
 attr(s,1,"ethernet",9);attr(s,256,&plan->handle,4);attr(s,261,&plan->generation,8);attr(s,275,&plan->direction,1);
 struct nt_ops o={bridge_clock,bridge_exchange,&b};return run(s,c,&o,76);
}

/* Existing observed session only. No allocation request, rekey or new identity. */
int nt_session_change_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *b,const struct nt_context *c,unsigned command,const struct nt_readback *r,const struct nt_stream *o){
 struct stream_bridge bridge;if(!stream_init(s,l,b,c,o,&bridge))return s?s->primary:SA_REFUSED;
 if(!r||!nt_readback_valid(r)||r->command!=14||!((r->scope==1&&!r->alias)||(r->scope==2&&r->alias==1))||(command!=12&&command!=13)||(command==12&&(nt_session_state(r)!=2||r->max_bytes<2))){s->started=1;return fail(s,SA_REFUSED);}
 s->expected_readback=*r;
 if(!begin(s,c,command))return s->primary;
 attr(s,20,&r->handle,8);attr(s,7,&r->generation,4);
 if(command==12){
  uint16_t suite=2;unsigned char version=4,state=2;
  attr(s,23,&r->peer,8);attr(s,33,&r->scope,1);if(r->scope==2)attr(s,4,&r->alias,2);attr(s,22,&suite,2);attr(s,21,&version,1);attr(s,9,&r->direction,1);attr(s,10,&state,1);attr(s,13,&r->max_bytes,8);
 }
 struct nt_ops ops={bridge_clock,bridge_exchange,&bridge};return run(s,c,&ops,command);
}

int nt_fanout_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,const struct nt_fanout *plan,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(!plan||plan->command<1||plan->command>4||((plan->command==2||plan->command==3)&&!plan->handle)||(plan->command==1&&plan->handle)||!plan->peer||!plan->generation||!plan->max_members)return fail(s,SA_IDENTITY);
 struct nt_ops o={bridge_clock,bridge_exchange,&b};if(!begin(s,c,plan->command))return s->primary;
 s->fanout=*plan;uint16_t alias=2100,level=1;uint32_t capability=100;unsigned char state=2;
 if(plan->command==4)w16(s->request+6,0x305);
 else if(plan->command==1){
  attr(s,7,&plan->generation,4);attr(s,4,&alias,2);attr(s,23,&plan->peer,8);attr(s,5,&capability,4);
  attr(s,12,&plan->max_members,4);attr(s,10,&state,1);attr(s,341,&level,2);
  attr(s,13,&plan->max_bytes,8);attr(s,8,&plan->lease_ms,8);attr(s,11,&plan->flags,4);
 }else {attr(s,1,&plan->handle,8);if(plan->command==2)attr(s,7,&plan->generation,4);}
 return run(s,c,&o,plan->command);
}

int nt_empty_list_stream(struct nt_state *s,struct nt_ledger *l,const struct nt_budget *budget,const struct nt_context *c,unsigned cmd,const struct nt_stream *ops){
 struct stream_bridge b;if(!stream_init(s,l,budget,c,ops,&b))return s?s->primary:SA_REFUSED;
 if(cmd!=40&&cmd!=72)return fail(s,SA_REFUSED);
 if(!begin(s,c,cmd))return s->primary;
 s->empty_list_command=cmd;w16(s->request+6,0x305);
 struct nt_ops o={bridge_clock,bridge_exchange,&b};return run(s,c,&o,cmd);
}
