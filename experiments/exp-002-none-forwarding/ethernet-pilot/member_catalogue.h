/* Pre-timing public catalogue generation into existing member storage. */
#ifndef EXP_MEMBER_CATALOGUE_H
#define EXP_MEMBER_CATALOGUE_H
#include "member_prepare.h"
#include <openssl/evp.h>
/* Caller supplies approved SHA256 policy, fresh exclusive storage, exact link
 * and transaction identity. No sockets, keys, timing or session authority. */
int ec_prepare(struct em_preparation *, struct em_storage *, unsigned, const struct ew_tx *,
               const struct ew_link *, const EVP_MD *);
#endif
