#include "provider_backend.h"
#include "public-blake3/blake3.h"
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <string.h>
static int error(struct sb_backend *b) {b->failed=1;if(!b->openssl_error)b->openssl_error=ERR_peek_last_error();return 0;}
static int context_matches(struct sb_backend *b,EVP_PKEY_CTX *p) {
 const char *q=p?EVP_PKEY_CTX_get0_propq(p):NULL;
 return p && EVP_PKEY_CTX_get0_libctx(p)==b->libctx && q && !strcmp(q,b->properties);
}
static EVP_PKEY *import_key(struct sb_backend *b,const unsigned char *bytes,int private) {
 EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_from_name(b->libctx,"ED25519",b->properties);
 EVP_PKEY *key=NULL;OSSL_PARAM params[2];
 params[0]=OSSL_PARAM_construct_octet_string(private?OSSL_PKEY_PARAM_PRIV_KEY:OSSL_PKEY_PARAM_PUB_KEY,(void *)bytes,32);
 params[1]=OSSL_PARAM_construct_end();
 if(!context_matches(b,ctx) || EVP_PKEY_fromdata_init(ctx)!=1 ||
    EVP_PKEY_fromdata(ctx,&key,private?EVP_PKEY_KEYPAIR:EVP_PKEY_PUBLIC_KEY,params)!=1 ||
    !key || EVP_PKEY_get0_provider(key)!=b->provider || !EVP_PKEY_is_a(key,"ED25519")) {
  EVP_PKEY_free(key);key=NULL;error(b);
 }
 EVP_PKEY_CTX_free(ctx);return key;
}
int sb_init(struct sb_backend *b,const struct sb_policy *p) {
 if(!b || b->initialized || !p || !p->libctx || !p->provider || !p->properties ||
    !p->properties[0] || strlen(p->properties)>=sizeof(b->properties) || !p->seed || p->seed_len!=32 || !p->clock)return 0;
 b->initialized=1;b->libctx=p->libctx;b->provider=p->provider;
 memcpy(b->properties,p->properties,strlen(p->properties)+1);memcpy(b->seed,p->seed,32);
 b->clock=p->clock;b->clock_arg=p->clock_arg;return 1;
}
static uint64_t clock_forward(void *arg) {struct sb_backend *b=arg;return b->clock(b->clock_arg);}
static void step(void *arg,const struct sa_input *in,struct sa_output *out) {
 struct sb_backend *b=arg;EVP_PKEY_CTX *pctx=NULL;
 memset(out,0,sizeof(*out));
 if(!b->initialized || b->closed || !in) {error(b);return;}
 if(in->stage==SA_CLOSE) {
  if(in->key!=b->key || in->md!=b->md || in->provider!=b->provider) {error(b);return;}
  EVP_MD_CTX_free(b->md);EVP_PKEY_free(b->key);b->md=NULL;b->key=NULL;
  OPENSSL_cleanse(b->seed,32);b->closed=1;out->rc=1;return;
 }
 if(b->failed || (int)in->stage!=b->next_stage || in->provider!=b->provider || !in->request) {error(b);return;}
 ++b->next_stage; /* no operation retry even on an OpenSSL error */
 switch(in->stage) {
 case SA_HASH: {
  blake3_hasher h;
  if(!in->data || (in->length!=82 && in->length!=124 && in->length!=117 && in->length!=159) || memcmp(in->data,"PRP-HS2-ID-PROOF-v4",19))break;
  blake3_hasher_init(&h);blake3_hasher_update(&h,in->data,in->length);blake3_hasher_finalize(&h,out->bytes,32);
  OPENSSL_cleanse(&h,sizeof(h));out->length=32;out->rc=1;return;
 }
 case SA_IMPORT:
  if(in->key_reference!=b)break;
  b->key=import_key(b,b->seed,1);out->key=b->key;out->provider=b->key?EVP_PKEY_get0_provider(b->key):NULL;
  if(b->key){out->rc=1;return;}break;
 case SA_PUBLIC:
  if(in->key!=b->key || !b->key)break;
  out->length=32;
  if(EVP_PKEY_get_raw_public_key(b->key,out->bytes,&out->length)==1 && out->length==32 &&
      !memcmp(out->bytes,in->request->public_key,32)){out->rc=1;return;}break;
 case SA_INIT:
  if(in->key!=b->key || !b->key)break;
  b->md=EVP_MD_CTX_new();out->md=b->md;
  if(b->md && EVP_DigestSignInit_ex(b->md,&pctx,NULL,b->libctx,b->properties,b->key,NULL)==1 && context_matches(b,pctx)) {
   out->provider=EVP_PKEY_CTX_get0_provider(pctx);
   if(out->provider==b->provider){out->rc=1;return;}
  }break;
 case SA_SIGN:
  if(in->key!=b->key || in->md!=b->md || !b->md || !in->data || in->length!=32 || b->sign_attempted)break;
  b->sign_attempted=1;out->length=64;
  if(EVP_DigestSign(b->md,out->bytes,&out->length,in->data,32)==1 && out->length==64){out->rc=1;return;}break;
 case SA_VERIFY: {
  EVP_PKEY *pub=NULL;EVP_MD_CTX *md=NULL;int ok=0;
  if(!in->data || in->length!=64 || !in->digest)break;
  pub=import_key(b,in->request->public_key,0);md=EVP_MD_CTX_new();
  if(pub && md && EVP_DigestVerifyInit_ex(md,&pctx,NULL,b->libctx,b->properties,pub,NULL)==1 &&
     context_matches(b,pctx) && EVP_PKEY_CTX_get0_provider(pctx)==b->provider)
   ok=EVP_DigestVerify(md,in->data,64,in->digest,32);
  EVP_MD_CTX_free(md);EVP_PKEY_free(pub);out->verified=ok;
  out->rc=ok;
  if(ok==1){out->rc=1;return;}break;
 }
 default:break;
 }
 error(b);
}
struct sa_ops sb_operations(struct sb_backend *b) {struct sa_ops o={clock_forward,step,b};return o;}
int sb_destroy(struct sb_backend *b) {
 if(!b || !b->initialized || b->key || b->md)return 0;
 OPENSSL_cleanse(b->seed,32);b->closed=1;return 1;
}
int sb_sha256(struct sb_backend *b,const unsigned char *data,size_t len,unsigned char out[32]) {
 EVP_MD *md=NULL;EVP_MD_CTX *ctx=NULL;unsigned int n=0;int ok=0;
 if(!b || !b->initialized || b->failed || b->closed || !data || !out || len>4096)return 0;
 md=EVP_MD_fetch(b->libctx,"SHA256",b->properties);ctx=EVP_MD_CTX_new();
 if(md && ctx && EVP_MD_get0_provider(md)==b->provider && EVP_MD_get_size(md)==32 &&
    EVP_DigestInit_ex2(ctx,md,NULL)==1 && EVP_DigestUpdate(ctx,data,len)==1 && EVP_DigestFinal_ex(ctx,out,&n)==1 && n==32)ok=1;
 EVP_MD_CTX_free(ctx);EVP_MD_free(md);if(!ok)error(b);return ok;
}
/* Public-only HS2 M1 verification. The caller independently binds expected wire,
 * identity and lifetime; valid signature alone does not establish trust. */
int sb_verify_m1(struct sb_backend *b,const unsigned char wire[130],const unsigned char public_key[32]){
 if(!b||!b->initialized||b->closed||b->failed||!wire||!public_key)return 0;
 if(wire[0]!=4||wire[1]!=0||wire[2]!=2||wire[3]!=1||wire[4]!=1||wire[5]!=0||wire[6]!=16||wire[23]!=5||wire[24]!=0||wire[25]!=2||wire[26]!=0||wire[27]!=1||wire[28]!=6||wire[29]!=0||wire[30]!=32||memcmp(wire+31,public_key,32)||wire[63]!=9||wire[64]!=0||wire[65]!=64)return 0;
 unsigned char digest[32];blake3_hasher h;blake3_hasher_init(&h);blake3_hasher_update(&h,"PRP-HS2-ID-PROOF-v4",19);blake3_hasher_update(&h,wire,63);blake3_hasher_finalize(&h,digest,32);OPENSSL_cleanse(&h,sizeof(h));
 EVP_PKEY *key=import_key(b,public_key,0);EVP_MD_CTX *md=EVP_MD_CTX_new();EVP_PKEY_CTX *pctx=NULL;int rc=0;
 if(key&&md&&EVP_DigestVerifyInit_ex(md,&pctx,NULL,b->libctx,b->properties,key,NULL)==1&&context_matches(b,pctx)&&EVP_PKEY_CTX_get0_provider(pctx)==b->provider)rc=EVP_DigestVerify(md,wire+66,64,digest,32);
 EVP_MD_CTX_free(md);EVP_PKEY_free(key);OPENSSL_cleanse(digest,sizeof(digest));return rc;
}
/* Finite encrypted-profile M1 proof + complete-wire binding. No session key
 * extraction, peer trust, freshness, admission or network effect is supplied. */
int sb_verify_cipher_m1(struct sb_backend *b,const unsigned char *wire,size_t n,unsigned suite,const unsigned char public_key[32],unsigned char binding[32]){
 if(binding)memset(binding,0,32);
 if(!b||!b->initialized||b->closed||b->failed||!wire||!public_key||!binding||n!=165||(suite!=0x0101&&suite!=0x0102))return 0;
 if(wire[0]!=4||wire[1]!=(unsigned char)(suite>>8)||wire[2]!=(unsigned char)suite||wire[3]!=1||
    wire[4]!=1||wire[5]!=0||wire[6]!=16||wire[23]!=2||wire[24]!=0||wire[25]!=32||
    wire[58]!=5||wire[59]!=0||wire[60]!=2||wire[61]!=0||wire[62]!=1||
    wire[63]!=6||wire[64]!=0||wire[65]!=32||memcmp(wire+66,public_key,32)||
    wire[98]!=9||wire[99]!=0||wire[100]!=64)return 0;
 unsigned char digest[32];blake3_hasher h;blake3_hasher_init(&h);blake3_hasher_update(&h,"PRP-HS2-ID-PROOF-v4",19);blake3_hasher_update(&h,wire,98);blake3_hasher_finalize(&h,digest,32);OPENSSL_cleanse(&h,sizeof(h));
 EVP_PKEY *key=import_key(b,public_key,0);EVP_MD_CTX *md=EVP_MD_CTX_new();EVP_PKEY_CTX *pctx=NULL;int rc=0;
 if(key&&md&&EVP_DigestVerifyInit_ex(md,&pctx,NULL,b->libctx,b->properties,key,NULL)==1&&context_matches(b,pctx)&&EVP_PKEY_CTX_get0_provider(pctx)==b->provider)rc=EVP_DigestVerify(md,wire+101,64,digest,32);
 EVP_MD_CTX_free(md);EVP_PKEY_free(key);OPENSSL_cleanse(digest,sizeof(digest));
 if(rc==1){blake3_hasher_init(&h);blake3_hasher_update(&h,wire,n);blake3_hasher_finalize(&h,binding,32);OPENSSL_cleanse(&h,sizeof(h));}
 return rc;
}
