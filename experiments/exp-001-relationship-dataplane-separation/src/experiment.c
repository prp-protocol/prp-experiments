/* EXP-001: one C process, two independent libprp endpoint handles.
 * PRP means Participant Relationship Protocol; HS2 is its two-message handshake.
 * All calls are serialized. Communication consists of passing the exact output
 * bytes of one endpoint to the other endpoint's API: there are no sockets.
 * The library owns session secrets, packet authentication and replay protection.
 * This file supplies identities, caller policy, message transport and assertions.
 * CHECK terminates the run on failure, including in optimized builds. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include "prp_application_session_v1.h"
#include "prp_ed25519ctx.h"

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)
/* dispatch requires this output capacity for a complete copied event. */
#define CAP 65649u
/* Local application identifier chosen for this fixture, not a network address. */
#define ALIAS 733u
void exp_observer_begin(void);
void exp_observer_end(void);
unsigned exp_observer_overflow(void);
unsigned exp_observer_capacity(void);
uintptr_t exp_observer_address(unsigned);
uint64_t exp_observer_count(unsigned);

struct identity { prp_ed25519ctx_keypair_t *key; uint8_t public_key[32]; };
struct fixture {
    struct identity identities[16]; unsigned identities_used;
    uint64_t handles[32]; unsigned handles_used;
};
struct message { uint8_t bytes[CAP]; int32_t size; };
struct packet { uint8_t item[128], wire[256]; uint32_t item_size, wire_size; uint64_t now; };

/* Obtain fresh operating-system entropy; handle interrupted and partial reads. */
static void random_bytes(uint8_t *out, size_t length)
{
    while (length) {
        ssize_t n = getrandom(out, length, 0);
        if (n < 0 && errno == EINTR) continue;
        CHECK(n > 0); out += n; length -= (size_t)n;
    }
}

/* A small caller trust-policy fixture, not a model of relationship discovery. */
static int authorize(const uint8_t public_key[32], const uint8_t expected[32], int allowed)
{
    return allowed && memcmp(public_key, expected, 32) == 0;
}

/* Create an independent signing identity and retain it only for test cleanup.
 * Export the public key for peer pinning; erase the temporary private seed. */
static struct identity *identity(struct fixture *f)
{
    CHECK(f->identities_used < 16);
    struct identity *id = &f->identities[f->identities_used++];
    uint8_t seed[32]; size_t written = 0;
    random_bytes(seed, sizeof(seed));
    CHECK(prp_ed25519ctx_keypair_from_seed(&id->key, seed) == 0);
    explicit_bzero(seed, sizeof(seed));
    CHECK(prp_ed25519ctx_public_key_export(id->key, id->public_key, 32, &written) == 0);
    CHECK(written == 32); return id;
}

/* BEGIN SESSION API EXAMPLE */
/* Role 1 initiates, role 2 responds. Identity suite 2 is Ed25519ctx/SHA-256;
 * session suite 0x0202 combines X25519, ML-KEM-1024, ChaCha20-Poly1305 and BLAKE3. */
static uint64_t create_session(struct fixture *f, uint32_t role,
                              const struct identity *local, const struct identity *peer)
{
    /* Fresh randomness lets libprp generate its own ephemeral session material.
     * The caller supplies public-key pins, never precomputed traffic keys. */
    uint8_t entropy[116];
    random_bytes(entropy, sizeof(entropy));
    uint64_t session = prp_app_session_v1_create(
        role, 0x0202, 2, local->public_key, 32, 2, peer->public_key, 32, entropy, 0);
    /* The returned handle identifies library-owned state within this process.
     * Time 0 is a logical setup timestamp, not a wall-clock measurement. */
    explicit_bzero(entropy, sizeof(entropy));
    CHECK(session != 0 && f->handles_used < 32);
    f->handles[f->handles_used++] = session;
    return session;
}

static struct message signed_handshake(uint64_t session, const struct identity *local)
{
    /* Ask libprp for the exact handshake bytes to sign. External identity
     * signing is required by this API; session secrets remain inside libprp. */
    uint8_t prefix[CAP], signature[64]; size_t written = 0;
    int32_t length = prp_app_session_v1_prefix(session, prefix, sizeof(prefix));
    CHECK(length > 0);
    CHECK(prp_ed25519ctx_sign(local->key, prefix, (size_t)length,
                             signature, sizeof(signature), &written) == 0);
    CHECK(written == sizeof(signature));
    /* Submit the signature. libprp verifies it and emits the handshake message
     * to be transported to the peer. Positive return values are byte lengths. */
    struct message wire;
    wire.size = prp_app_session_v1_proof(session, signature, sizeof(signature),
                                        1, wire.bytes, sizeof(wire.bytes));
    CHECK(wire.size > 0);
    return wire;
}

static void establish_pair(struct fixture *f, uint64_t *a, uint64_t *b,
                           struct message *m2, int wrong_peer)
{
    /* The fixture approves both known identities before creating sessions.
     * This models a caller trust decision, not relationship discovery. */
    struct identity *alice = identity(f), *bob = identity(f);
    CHECK(authorize(alice->public_key, alice->public_key, 1));
    CHECK(authorize(bob->public_key, bob->public_key, 1));
    /* A initiates; B responds. The wrong-peer test deliberately gives B an
     * unrelated public-key pin, so the first handshake message must fail. */
    *a = create_session(f, 1, alice, bob);
    *b = create_session(f, 2, bob, wrong_peer ? identity(f) : alice);
    /* A -> B: passing M1 bytes directly is our in-memory transport.
     * B must accept M1 before it can produce its own handshake response. */
    struct message m1 = signed_handshake(*a, alice);
    int32_t rc = prp_app_session_v1_peer_hs2(*b, m1.bytes, m1.size, 1);
    if (wrong_peer) { CHECK(rc < 0); return; }
    CHECK(rc == 0);
    /* B -> A: acceptance of M2 completes the two-message exchange.
     * The endpoints now hold separately managed, compatible session state. */
    *m2 = signed_handshake(*b, bob);
    CHECK(prp_app_session_v1_peer_hs2(*a, m2->bytes, m2->size, 1) == 0);
}
/* END SESSION API EXAMPLE */

/* Big-endian fields used only to construct canonical test inputs. */
static void put_be(uint8_t *out, uint64_t value, unsigned bytes)
{
    for (unsigned i = bytes; i > 0; --i) { out[i-1] = (uint8_t)value; value >>= 8; }
}

/* BEGIN AGREEMENT API EXAMPLE */
/* An established session is not yet permission to send application-bound data.
 * OPEN/ACCEPT/CONFIRM installs a mutually confirmed application agreement. */
static void agree(uint64_t a, uint64_t b, uint8_t agreement[113])
{
    /* Build the canonical OPEN_APP test input for the supported POST name.
     * Attempt 1 identifies this negotiation. The context bytes remain zero:
     * libprp derives the session binding instead of trusting a caller value.
     * POST here is an agreement label; no POST application is activated. */
    uint8_t offer[65] = {7, 1, 1}, wire[CAP], reply[CAP], other[CAP];
    put_be(offer + 3, 1, 8); put_be(offer + 43, 4, 2);
    memcpy(offer + 45, "POST", 4);
    put_be(offer + 49, 1, 2); put_be(offer + 51, 1, 2);
    put_be(offer + 61, 1000, 4);
    /* A -> B: protect and transmit OPEN. A -2 receive result means a new
     * offer awaits a local decision, not a malformed packet. */
    int32_t n = prp_app_session_v1_offer(a, offer, sizeof(offer), 2, wire, CAP);
    CHECK(n > 0);
    CHECK(prp_app_session_v1_receive(b, wire, n, 2, reply, CAP) == -2);
    CHECK(prp_app_session_v1_pending(b, 1, 1, 2, reply, CAP) > 0);
    /* B accepts using alias 733 and generation 1. A processes ACCEPT and
     * produces CONFIRM, which must still be handed to the transport. */
    n = prp_app_session_v1_decide(b, 1, 1, ALIAS, 1, 0, 2, wire, CAP);
    CHECK(n > 0);
    n = prp_app_session_v1_receive(a, wire, n, 2, reply, CAP);
    CHECK(n > 0);
    /* Neither endpoint may expose an active agreement before these final
     * steps: A records handoff, then B receives and verifies CONFIRM. */
    CHECK(prp_app_session_v1_agreement(a, ALIAS, 1, 2, other, CAP) < 0);
    CHECK(prp_app_session_v1_agreement(b, ALIAS, 1, 2, other, CAP) < 0);
    CHECK(prp_app_session_v1_handed(a, 1, 3) == 0);
    CHECK(prp_app_session_v1_receive(b, reply, n, 3, wire, CAP) == 0);
    /* Compare the complete 113-byte acceptance records. Matching records
     * prove this fixture negotiated the same agreement at both endpoints. */
    CHECK(prp_app_session_v1_agreement(a, ALIAS, 1, 3, agreement, 113) == 113);
    CHECK(prp_app_session_v1_agreement(b, ALIAS, 1, 3, other, CAP) == 113);
    CHECK(memcmp(agreement, other, 113) == 0);
}

/* END AGREEMENT API EXAMPLE */

/* BEGIN SENDER API EXAMPLE */
static struct packet seal(uint64_t session, uint64_t index, uint64_t now)
{
    /* Construct a canonical plaintext item addressed to the admitted alias.
     * The index distinguishes payloads; libprp manages cryptographic nonces.
     * The fixed buffers are sized for this small fixture, not arbitrary data. */
    static const char text[] = "EXP001 real-session payload";
    struct packet p = { .now = now };
    uint32_t payload_size = 8 + sizeof(text) - 1;
    put_be(p.item, ALIAS, 2); put_be(p.item + 12, payload_size, 2);
    put_be(p.item + 14, index, 8); memcpy(p.item + 22, text, sizeof(text)-1);
    p.item_size = 14 + payload_size;
    /* The session API checks admission and encrypts/authenticates the item.
     * Only the resulting wire bytes cross our in-memory transport boundary. */
    int32_t n = prp_app_session_v1_seal_item(session, p.item, p.item_size,
                                           now, p.wire, sizeof(p.wire));
    CHECK(n > 0 && (uint32_t)n <= sizeof(p.wire)); p.wire_size = (uint32_t)n;
    return p;
}

/* END SENDER API EXAMPLE */

/* BEGIN PACKET API EXAMPLE */
/* The receive component keeps only an opaque session handle. */
struct receiver { uint64_t session; };

static int32_t receive_packet(const struct receiver *receiver,
                              const uint8_t *wire, uint32_t wire_size,
                              uint64_t now, uint8_t event[CAP])
{
    /* Authenticate the packet, reject replays and check application admission
     * using the installed session. Do not repeat policy or handshake here.
     * The result is a copied event; this API does not provide zero-copy I/O. */
    return prp_app_session_v1_dispatch(receiver->session, wire, wire_size,
                                       now, event, CAP);
}

/* Test assertion: the returned bound-data event must contain the exact
 * negotiated agreement and the original canonical item, byte for byte. */
static void deliver(const struct receiver *receiver, const struct packet *packet,
                    const uint8_t agreement[113])
{
    uint8_t event[CAP];
    int32_t n = receive_packet(receiver, packet->wire, packet->wire_size,
                               packet->now, event);
    /* Event layout: tag 3 (one byte), acceptance record (113 bytes), item.
     * These assertions belong to the test; returning an event is transport
     * evidence, not proof of application delivery or durable storage. */
    CHECK(n == (int32_t)(114 + packet->item_size));
    CHECK(event[0] == 3);
    CHECK(memcmp(event + 1, agreement, 113) == 0);
    CHECK(memcmp(event + 114, packet->item, packet->item_size) == 0);
}
/* END PACKET API EXAMPLE */

/* Release handles and signing keys between cases so no session leaks into
 * another workload. Cleanup is excluded from the observation intervals. */
static void cleanup(struct fixture *f)
{
    exp_observer_end();
    for (unsigned i = 0; i < f->handles_used; ++i) prp_app_session_v1_invalidate(f->handles[i]);
    for (unsigned i = 0; i < f->identities_used; ++i) prp_ed25519ctx_keypair_destroy(f->identities[i].key);
    memset(f, 0, sizeof(*f));
}

/* Preserve address offsets, independently resolved against nm symbol tables
 * by the runner. No API counters are incremented by the experiment itself. */
static void observations(FILE *out)
{
    exp_observer_end(); CHECK(!exp_observer_overflow());
    Dl_info library; CHECK(dladdr((void *)prp_app_session_v1_create, &library));
    int comma = 0;
    fputc('{', out);
    for (unsigned i = 0; i < exp_observer_capacity(); ++i) {
        uintptr_t address = exp_observer_address(i);
        if (!address) continue;
        Dl_info info; CHECK(dladdr((void *)address, &info));
        fprintf(out, "%s\"%s:%" PRIxPTR "\":%" PRIu64, comma ? "," : "",
                info.dli_fbase == library.dli_fbase ? "libprp" : "experiment",
                address - (uintptr_t)info.dli_fbase, exp_observer_count(i));
        comma = 1;
    }
    fputc('}', out);
}

static void workload(FILE *out, unsigned count, const char *mode)
{
    struct fixture f = {0}; uint64_t a, b; struct message m2; uint8_t agreement[113];
    fprintf(out, "{\"case\":\"%s\",\"packets\":%u,\"setup_raw\":", mode, count);
    /* Measure setup separately so its cost cannot be confused with reception. */
    exp_observer_begin();
    establish_pair(&f, &a, &b, &m2, 0); agree(a, b, agreement);
    exp_observer_end();
    observations(out);
    struct receiver receiver = { b };
    struct packet *packets = calloc(count ? count : 1, sizeof(*packets)); CHECK(packets);
    /* Prepare and encrypt every packet outside the receive observation.
     * Advance logical time by 10 ms per packet to respect the provider budget.
     * No elapsed time, throughput or latency is measured. */
    for (unsigned i = 0; i < count; ++i) packets[i] = seal(a, i, 1000 + (uint64_t)i * 10);
    fputs(",\"packet_raw\":", out);
    exp_observer_begin();
    /* These two deliberately incorrect paths test observer sensitivity.
     * Their detection is required for PASS; they are not accepted workloads. */
    if (strcmp(mode, "repeat-policy") == 0) {
        CHECK(authorize(f.identities[0].public_key, f.identities[0].public_key, 1));
    } else if (strcmp(mode, "repeat-handshake") == 0) {
        struct identity *alice = identity(&f), *bob = identity(&f);
        create_session(&f, 1, alice, bob);
    }
    /* A -> B: hand the previously produced ciphertext to B, then compare
     * the returned event with the original item and negotiated agreement. */
    for (unsigned i = 0; i < count; ++i) deliver(&receiver, &packets[i], agreement);
    exp_observer_end();
    observations(out);
    fprintf(out, ",\"delivered\":%u,\"observed_bound_data\":true}", count);
    free(packets); cleanup(&f);
    printf("Completed C workload: %s, %u packets; observer validation follows.\n", mode, count);
    fflush(stdout);
}

static void adversarial(FILE *out)
{
    struct fixture f = {0}; uint64_t a, b; struct message m2;
    uint8_t agreement[113], event[CAP];
    fputs("{\"case\":\"adversarial\",\"classification\":\"PASS\",\"checks\":[", out);
    establish_pair(&f, &a, &b, &m2, 0); agree(a, b, agreement);
    struct packet p = seal(a, 1, 1000), bad = p;
    /* Damage authentication, then retry the intact packet: rejection must
     * not consume the valid packet as though it had been authenticated. */
    bad.wire[bad.wire_size-1] ^= 1;
    CHECK(receive_packet(&(struct receiver){b}, bad.wire, bad.wire_size, 1000, event) < 0);
    deliver(&(struct receiver){b}, &p, agreement);
    fputs("\"tampered packet rejected; original accepted afterwards\",", out);
    /* The intact packet has now succeeded once; a second use is a replay. */
    CHECK(receive_packet(&(struct receiver){b}, p.wire, p.wire_size, 1000, event) < 0);
    fputs("\"replayed packet rejected\",", out);
    /* Exercise binding and session revocation independently. Neither a closed
     * application nor an invalid handle may admit the next encrypted item. */
    struct packet old = seal(a, 2, 1010);
    CHECK(prp_app_session_v1_close(b, ALIAS, 1, 1010) == 0);
    CHECK(receive_packet(&(struct receiver){b}, old.wire, old.wire_size, 1010, event) < 0);
    fputs("\"closed application binding rejected\",", out);
    CHECK(prp_app_session_v1_invalidate(b) == 0);
    CHECK(receive_packet(&(struct receiver){b}, old.wire, old.wire_size, 1020, event) < 0);
    fputs("\"invalidated session rejected\",", out);
    /* A fresh handshake must reject old-session ciphertext while admitting
     * newly sealed data in both directions. This is replacement, not rekey. */
    CHECK(prp_app_session_v1_invalidate(a) == 0);
    establish_pair(&f, &a, &b, &m2, 0); agree(a, b, agreement);
    CHECK(receive_packet(&(struct receiver){b}, old.wire, old.wire_size, 1000, event) < 0);
    p = seal(a, 3, 1000); deliver(&(struct receiver){b}, &p, agreement);
    p = seal(b, 4, 1010); deliver(&(struct receiver){a}, &p, agreement);
    fputs("\"replacement HS2: old ciphertext rejected; new traffic accepted in both directions\",", out);
    cleanup(&f);
    /* Start isolated cases for incorrect peer pins and repeated handshake. */
    establish_pair(&f, &a, &b, &m2, 1);
    fputs("\"wrong pinned peer identity rejected during HS2\",", out); cleanup(&f);
    establish_pair(&f, &a, &b, &m2, 0);
    CHECK(prp_app_session_v1_peer_hs2(a, m2.bytes, m2.size, 2) < 0);
    fputs("\"repeated HS2 message rejected\",", out); cleanup(&f);
    struct identity *alice = identity(&f), *bob = identity(&f);
    a = create_session(&f, 1, alice, bob); b = create_session(&f, 2, bob, alice);
    /* Corrupt a handshake identity proof before the responder sees it. */
    struct message m1 = signed_handshake(a, alice); m1.bytes[m1.size-1] ^= 1;
    CHECK(prp_app_session_v1_peer_hs2(b, m1.bytes, m1.size, 1) < 0);
    fputs("\"corrupted HS2 identity proof rejected\",", out); cleanup(&f);
    /* A caller-policy denial must stop before any native session creation.
     * The observer independently checks one policy call and zero creations. */
    uint8_t peer[32] = {0};
    exp_observer_begin();
    if (authorize(peer, peer, 0)) { identity(&f); CHECK(0); }
    fputs("\"relationship policy denial creates no session\"],\"denied_policy_raw\":", out);
    exp_observer_end();
    observations(out); fputc('}', out); cleanup(&f);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    FILE *out = fopen(argv[1], "w"); CHECK(out);
    /* Include an empty receive phase and increasing workloads. The separate
     * runner resolves native addresses and checks all phase-count assertions. */
    const unsigned counts[] = {0, 1, 10, 1000, 100000};
    fputc('[', out);
    for (unsigned i = 0; i < sizeof(counts)/sizeof(counts[0]); ++i) {
        if (i) fputc(',', out);
        workload(out, counts[i], "normal");
    }
    fputc(',', out); workload(out, 10, "repeat-policy");
    fputc(',', out); workload(out, 10, "repeat-handshake");
    fputc(',', out); adversarial(out);
    fputs("]\n", out); CHECK(fclose(out) == 0);
    puts("PASS C adversarial checks: 9");
    return 0;
}
