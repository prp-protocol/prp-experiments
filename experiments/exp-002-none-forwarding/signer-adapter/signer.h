#ifndef EXP_SIGNER_H
#define EXP_SIGNER_H
#include <stddef.h>
#include <stdint.h>
/* HOST injection boundary only. No OpenSSL, keys, transport or kernel imports. */
enum sa_stage { SA_HASH, SA_IMPORT, SA_PUBLIC, SA_INIT, SA_SIGN, SA_VERIFY, SA_CLOSE, SA_STAGES };
enum sa_error { SA_OK, SA_REFUSED, SA_REPEAT, SA_TIME, SA_CALLBACK, SA_SHAPE, SA_IDENTITY, SA_REENTRY };
struct sa_context { uint64_t attempt, epoch, endpoint, netns, socket, handle; };
struct sa_request { struct sa_context context; unsigned char prefix[140]; size_t prefix_len; unsigned char public_key[32]; uint64_t deadline; };
struct sa_policy { struct sa_request expected; const void *provider; const void *key_reference; int fixture_authorized; };
struct sa_output {
    int rc; const void *key; const void *md; const void *provider;
    unsigned char bytes[64]; size_t length; int verified;
};
struct sa_input {
    enum sa_stage stage; const struct sa_request *request; const void *key_reference;
    const void *key; const void *md; const void *provider;
    const unsigned char *data; size_t length; const unsigned char *digest;
};
struct sa_ops { uint64_t (*clock)(void *); void (*step)(void *, const struct sa_input *, struct sa_output *); void *arg; };
struct sa_receipt { int called; uint64_t before, after; struct sa_output raw; };
struct sa_state {
    int started, busy, primary, secondary, callback_error, sign_possible, verified;
    int time_refused; /* sticky temporal barrier; never reset within lifetime */
    uint64_t last_time, failure_revision; const void *owned_key; const void *owned_md;
    struct sa_receipt receipt[SA_STAGES];
};
/* State starts zeroed, has one lifetime, and may never be reset for retry.
 * Ops are trusted synchronous HOST fixtures; no ownership is inferred from IDs.
 * Output bytes are not cryptographic proof. Policy/key_reference are injected.
 */
int sa_run(struct sa_state *, const struct sa_policy *, const struct sa_request *, const struct sa_ops *);
int sa_native(void); /* always refuses, does not invoke anything */
#endif
