#include "payload_geometry.h"
#include "member_catalogue.h"
#include <errno.h>
#include <string.h>
static void be16(unsigned char *p,unsigned n){p[0]=(unsigned char)(n>>8);p[1]=(unsigned char)n;}
static void be32(unsigned char *p,uint32_t n){for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(n>>(24-8*i));}
static void be64(unsigned char *p,uint64_t n){for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(n>>(56-8*i));}
static void layer(unsigned char *p,const unsigned char hash[32],uint32_t branch,unsigned child){be16(p,32);memcpy(p+2,hash,32);be16(p+34,1);be32(p+36,branch);be16(p+40,child);}
static void header(unsigned char *p,unsigned alias,unsigned bytes,unsigned layers){be16(p,1);be16(p+2,alias);p[4]=2;p[5]=0;be16(p+6,bytes-8);be16(p+8,layers);}
int ec_prepare(struct em_preparation *p,struct em_storage *storage,unsigned pair,const struct ew_tx *tx,const struct ew_link *link,const EVP_MD *md){
 if(!p)return -EINVAL;
 int rc=em_prepare_begin(p,storage,link,tx);if(rc)return rc;
 if(pair>=4||!md||!EVP_MD_is_a(md,"SHA256")||EVP_MD_get_size(md)!=32){rc=-EINVAL;goto failed;}
 EVP_MD_CTX *ctx=EVP_MD_CTX_new();if(!ctx){rc=-ENOMEM;goto failed;}
 unsigned char input[EG_INPUT],expected[EG_OUTPUT],hash[32];
 for(unsigned i=0;i<EP_COUNT;i++){
  memset(input,0,sizeof(input));header(input,1,sizeof(input),84);
  unsigned char *annex=input+94;be16(annex,17);be16(annex+2,3);be64(annex+4,30+(uint64_t)pair*EP_COUNT+i);be16(annex+12,EG_PAYLOAD);
  for(unsigned j=0;j<EG_PAYLOAD;j++)annex[14+j]=(unsigned char)j;
  unsigned n=0;
  if(EVP_DigestInit_ex2(ctx,md,NULL)!=1||EVP_DigestUpdate(ctx,annex,EG_ANNEX)!=1||EVP_DigestFinal_ex(ctx,hash,&n)!=1||n!=32){rc=-EIO;break;}
  layer(input+10,hash,100,42);layer(input+52,hash,UINT32_MAX,0);
  header(expected,2100,sizeof(expected),42);layer(expected+10,hash,UINT32_MAX,0);memcpy(expected+52,annex,EG_ANNEX);
  rc=em_prepare_record(p,i,input,sizeof(input),expected,sizeof(expected));if(rc)break;
 }
 EVP_MD_CTX_free(ctx);
 if(!rc)return em_prepare_finish(p);
failed:
 /* Ignore no generator error: existing preparation/backend sticky state owns it. */
 if(!p->primary)p->primary=rc;
 if(storage&&!storage->backend.primary)storage->backend.primary=p->primary;
 return p->primary;
}
