#ifndef EXP_LOCAL_CLIENT_H
#define EXP_LOCAL_CLIENT_H
#include "signer.h"
struct sc_client {
    int started, busy, primary, accepted;
    size_t received_length, retained_length, wire_length;
    uint64_t final_time, deadline;
    unsigned char received[140], wire[207];
    struct sa_context context; /* accepted independent signing context */
    struct sa_state signer;
};
/* Strict identity1/session0002 profile only, no private SDK dependency.
 * m1_binding is independently approved complete-M1 SHA256 binding for M2.
 * No send/COMMIT is performed. EXPECTED retains independent full context/prefix.
 */
int sc_sign(struct sc_client *, const struct sa_policy *, const unsigned char *, size_t,
            const unsigned char m1_binding[32], uint32_t generation, const struct sa_ops *);
/* Opt-in identity1 / X25519 suites0101 and0102 only. This signs a kernel
 * supplied prefix, not a traffic key, handshake admission or transport result.
 * M2 binding must independently cover the COMPLETE signed M1 with BLAKE3.
 * Legacy sc_sign remains strictly suite0002; no automatic suite fallback. */
int sc_sign_cipher(struct sc_client *, const struct sa_policy *, const unsigned char *, size_t,
                   const unsigned char m1_binding[32], uint32_t generation, const struct sa_ops *);
int sc_match_reply(const struct sc_client *, const unsigned char *, size_t);
int sc_adjacent_public(const struct sc_client *, unsigned char *, size_t, size_t *);
#endif
