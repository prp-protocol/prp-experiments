/* Seed through stdin only. Stdout contains public material, never secret bytes.
 * Existing OpenSSL configuration is loaded unchanged; no provider override. */
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include "blake3.h"
static void hex(const unsigned char *p,size_t n){for(size_t i=0;i<n;i++)printf("%02x",p[i]);}
int main(void){
 unsigned char seed[32]={0},pub[32]={0},strong[32]={0},sig[64]={0};
 size_t pub_n=32,sig_n=64;int rc=1;
 OSSL_LIB_CTX *lib=NULL;EVP_PKEY_CTX *import=NULL,*sign_ctx=NULL,*verify_ctx=NULL;
 EVP_PKEY *key=NULL;EVP_MD_CTX *sign=NULL,*verify=NULL;
 if(fread(seed,1,32,stdin)!=32||fgetc(stdin)!=EOF||ferror(stdin))goto done;
 lib=OSSL_LIB_CTX_new();if(!lib||OSSL_LIB_CTX_load_config(lib,NULL)!=1)goto done;
 import=EVP_PKEY_CTX_new_from_name(lib,"ED25519",NULL);
 OSSL_PARAM params[]={OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,seed,32),OSSL_PARAM_construct_end()};
 if(!import||EVP_PKEY_CTX_get0_libctx(import)!=lib||EVP_PKEY_fromdata_init(import)!=1||EVP_PKEY_fromdata(import,&key,EVP_PKEY_KEYPAIR,params)!=1||!key)goto done;
 const OSSL_PROVIDER *provider=EVP_PKEY_get0_provider(key);
 if(!provider||!EVP_PKEY_is_a(key,"ED25519")||EVP_PKEY_get_raw_public_key(key,pub,&pub_n)!=1||pub_n!=32)goto done;
 /* Public consistency check, not an HS2 proof or target qualification. */
 static const unsigned char check[]="EXP002-disposable-key-self-check-v1";
 sign=EVP_MD_CTX_new();verify=EVP_MD_CTX_new();
 if(!sign||!verify||EVP_DigestSignInit_ex(sign,&sign_ctx,NULL,lib,NULL,key,NULL)!=1||EVP_PKEY_CTX_get0_provider(sign_ctx)!=provider||EVP_DigestSign(sign,sig,&sig_n,check,sizeof(check)-1)!=1||sig_n!=64||EVP_DigestVerifyInit_ex(verify,&verify_ctx,NULL,lib,NULL,key,NULL)!=1||EVP_PKEY_CTX_get0_provider(verify_ctx)!=provider||EVP_DigestVerify(verify,sig,64,check,sizeof(check)-1)!=1)goto done;
 const char *name=OSSL_PROVIDER_get0_name(provider);if(!name||strlen(name)>64)goto done;
 for(const char *p=name;*p;p++)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||*p=='_'||*p=='-'))goto done;
 blake3_hasher h;const unsigned char identity[]={0,1};blake3_hasher_init(&h);
 blake3_hasher_update(&h,"PRP-STRONG-ID-v4",sizeof("PRP-STRONG-ID-v4")-1);blake3_hasher_update(&h,identity,2);blake3_hasher_update(&h,pub,32);blake3_hasher_finalize(&h,strong,32);OPENSSL_cleanse(&h,sizeof(h));
 printf("{\"identity_suite\":1,\"public_key\":\"");hex(pub,32);printf("\",\"strong_id\":\"");hex(strong,32);
 printf("\",\"provider\":\"%s\",\"fips_default\":%s,\"self_check\":true",name,EVP_default_properties_is_fips_enabled(lib)?"true":"false");
#ifdef EXP_GUEST_QUALIFICATION
 printf(",\"openssl_version_number\":%lu",OpenSSL_version_num());
#endif
 puts("}");rc=ferror(stdout)?1:0;
 done:
 EVP_MD_CTX_free(verify);EVP_MD_CTX_free(sign);EVP_PKEY_free(key);EVP_PKEY_CTX_free(import);OSSL_LIB_CTX_free(lib);
 OPENSSL_cleanse(seed,sizeof(seed));OPENSSL_cleanse(sig,sizeof(sig));
 if(rc)fputs("Identity derivation refused\n",stderr);
 return rc;
}
