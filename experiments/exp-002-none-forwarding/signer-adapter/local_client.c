#include "local_client.h"
#include <string.h>
static unsigned be16(const unsigned char *p){return ((unsigned)p[0]<<8)|p[1];}
static uint32_t be32(const unsigned char *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static int reject(struct sc_client *c,int error){
 if(!c->primary)c->primary=error;
 c->accepted=0;
 if(c->signer.started){
  if(!c->signer.primary)c->signer.primary=error;
  else if(!c->signer.secondary && c->signer.primary!=error)c->signer.secondary=error;
  c->signer.failure_revision++;c->signer.verified=0;
 }
 return c->primary;
}
static int prefix(const unsigned char *p,size_t n,const unsigned char pub[32],const unsigned char *binding,uint32_t generation){
 if((n!=63 && n!=105)||p[0]!=4||be16(p+1)!=2||p[3]!=(n==63?1:2))return 0;
 /* Exact sorted TLVs; no optional extension or silent suite switch. */
 if(p[4]!=1||be16(p+5)!=16||p[23]!=5||be16(p+24)!=2||be16(p+26)!=1||
    p[28]!=6||be16(p+29)!=32||memcmp(p+31,pub,32))return 0;
 if(n==63)return generation==0 && binding==NULL;
 return binding && generation && p[63]==7&&be16(p+64)==32&&!memcmp(p+66,binding,32)&&
        p[98]==8&&be16(p+99)==4&&be32(p+101)==generation;
}
static int cipher_prefix(const unsigned char *p,size_t n,const unsigned char pub[32],const unsigned char *binding,uint32_t generation){
 if((n!=98 && n!=140)||p[0]!=4||(be16(p+1)!=0x0101&&be16(p+1)!=0x0102)||p[3]!=(n==98?1:2))return 0;
 /* Nonce16, X25519 public32, identity1, Ed25519 public32, then M2 joins.
  * Private ephemeral material stays with the session owner, never this signer. */
 if(p[4]!=1||be16(p+5)!=16||p[23]!=2||be16(p+24)!=32||
    p[58]!=5||be16(p+59)!=2||be16(p+61)!=1||p[63]!=6||
    be16(p+64)!=32||memcmp(p+66,pub,32))return 0;
 if(n==98)return !generation && !binding;
 return binding && generation && p[98]==7&&be16(p+99)==32&&!memcmp(p+101,binding,32)&&
        p[133]==8&&be16(p+134)==4&&be32(p+136)==generation;
}
static int sign_profile(int cipher,struct sc_client *c,const struct sa_policy *p,const unsigned char *raw,size_t n,const unsigned char binding[32],uint32_t generation,const struct sa_ops *ops){
 struct sa_request r;uint64_t end;
 if(!c)return SA_REFUSED;
 if(c->busy)return reject(c,SA_REENTRY);
 if(c->started)return reject(c,SA_REPEAT);
 c->started=1;c->busy=1;c->received_length=n;
 if(raw){c->retained_length=n>sizeof(c->received)?sizeof(c->received):n;memcpy(c->received,raw,c->retained_length);}
 if(!p||!raw||!ops||!ops->clock||!(cipher?cipher_prefix(c->received,n,p->expected.public_key,binding,generation):prefix(c->received,n,p->expected.public_key,binding,generation))){
  reject(c,SA_SHAPE);goto done;
 }
 r=p->expected;r.prefix_len=n;memcpy(r.prefix,c->received,n);
 if(sa_run(&c->signer,p,&r,ops)!=SA_OK){reject(c,c->signer.primary);goto done;}
 if(c->primary)goto done;
 memcpy(c->wire,c->received,n);c->wire[n]=9;c->wire[n+1]=0;c->wire[n+2]=64;
 memcpy(c->wire+n+3,c->signer.receipt[SA_SIGN].raw.bytes,64);
 /* Serialization may finish late; no accepted wire until final clock check. */
 end=ops->clock(ops->arg);c->final_time=end;
 if(end>=r.deadline || end<c->signer.last_time){c->signer.time_refused=1;reject(c,SA_TIME);goto done;}
 if(c->primary)goto done;
 c->deadline=r.deadline;c->context=r.context;c->wire_length=n+67;c->accepted=1;
 done:c->busy=0;return c->primary;
}
int sc_sign(struct sc_client *c,const struct sa_policy *p,const unsigned char *raw,size_t n,const unsigned char binding[32],uint32_t generation,const struct sa_ops *ops){return sign_profile(0,c,p,raw,n,binding,generation,ops);}
int sc_sign_cipher(struct sc_client *c,const struct sa_policy *p,const unsigned char *raw,size_t n,const unsigned char binding[32],uint32_t generation,const struct sa_ops *ops){return sign_profile(1,c,p,raw,n,binding,generation,ops);}
int sc_match_reply(const struct sc_client *c,const unsigned char *wire,size_t n){return c&&c->accepted&&!c->primary&&wire&&n==c->wire_length&&!memcmp(wire,c->wire,n);}
int sc_adjacent_public(const struct sc_client *c,unsigned char *out,size_t capacity,size_t *n){
 if(n)*n=0;
 if(!c||!c->accepted||c->primary||!out||!n||capacity<c->wire_length+4)return 0;
 out[0]=2;out[1]=1;out[2]=255;out[3]=255;memcpy(out+4,c->wire,c->wire_length);*n=c->wire_length+4;return 1;
}
