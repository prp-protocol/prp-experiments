#ifndef EXP_PROVIDER_BACKEND_H
#define EXP_PROVIDER_BACKEND_H
#include "signer.h"
#include <openssl/evp.h>
#include <openssl/provider.h>
/* Caller-owned, explicit already-approved HOST test policy. This interface does
 * not load config/providers, provision identity or infer target authorization. */
struct sb_policy {
 OSSL_LIB_CTX *libctx; const OSSL_PROVIDER *provider; const char *properties;
 const unsigned char *seed; size_t seed_len;
 uint64_t (*clock)(void *); void *clock_arg;
};
struct sb_backend {
 OSSL_LIB_CTX *libctx; const OSSL_PROVIDER *provider; char properties[128];
 unsigned char seed[32]; EVP_PKEY *key; EVP_MD_CTX *md;
 uint64_t (*clock)(void *); void *clock_arg;
 unsigned long openssl_error;
 int initialized, next_stage, failed, closed, sign_attempted;
};
int sb_init(struct sb_backend *,const struct sb_policy *);
struct sa_ops sb_operations(struct sb_backend *);
/* Only succeeds after resource-free completion; never secretly frees live work. */
int sb_destroy(struct sb_backend *);
int sb_sha256(struct sb_backend *,const unsigned char *,size_t,unsigned char [32]);
int sb_verify_m1(struct sb_backend *,const unsigned char [130],const unsigned char [32]);
/* Exact suite0101/0102 M1 only; failed proof clears output binding. The caller
 * must independently bind peer identity, exact bytes, context and deadlines. */
int sb_verify_cipher_m1(struct sb_backend *,const unsigned char *,size_t,unsigned,
                       const unsigned char [32],unsigned char [32]);
#endif
