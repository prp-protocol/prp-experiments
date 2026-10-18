#define _POSIX_C_SOURCE 200809L
#include "m1_query.h"
#include "session_query.h"
#include "public-blake3/blake3.h"
#include <poll.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
static uint64_t clock_ns(void *unused)
{
    (void)unused;
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0)
        return UINT64_MAX;
    return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}
struct parent_guard {
    struct sf_flow *parent;
    struct rp_handle active, target;
    uint64_t revision;
    struct nt_stream io;
};
static int parent_check(struct parent_guard *g)
{
    if (!g->parent)
        return 1;
    struct rp_handle h;
    if (sf_active_ticket(g->parent, &h) || g->parent->revision != g->revision ||
        h.pool != g->active.pool || h.id != g->active.id || h.slot != g->active.slot ||
        h.generation != g->active.generation) {
        rp_readback(g->target, NULL, NULL, NULL);
        return 0;
    }
    return 1;
}
static uint64_t parent_clock(void *v)
{
    struct parent_guard *g = v;
    parent_check(g);
    uint64_t n = g->io.clock(g->io.arg);
    parent_check(g);
    return n;
}
static uint64_t parent_sign_clock(void *v)
{
    struct parent_guard *g = v;
    parent_check(g);
    uint64_t n = clock_ns(NULL);
    parent_check(g);
    return n;
}
static int parent_send(void *v, const unsigned char *b, size_t n)
{
    struct parent_guard *g = v;
    if (!parent_check(g))
        return -1;
    int rc = g->io.send(g->io.arg, b, n);
    parent_check(g);
    return rc;
}
static void parent_receive(void *v, size_t n, struct nt_reply *r)
{
    struct parent_guard *g = v;
    if (!parent_check(g)) {
        r->rc = -1;
        return;
    }
    g->io.receive(g->io.arg, n, r);
    parent_check(g);
}
static struct nt_stream guarded_stream(struct parent_guard *g)
{
    return (struct nt_stream){parent_clock, parent_send, parent_receive, g};
}
static int exchange(struct rp_pool *pool, struct so_owner *owner, uint16_t family, uint32_t *seq,
                    struct rp_handle source, struct nq_store *store, struct mq_identity *identity,
                    const struct nt_remote_m1 *remote, struct mq_result *result,
                    const struct nt_selection *selection, struct sf_flow *parent, uint32_t transfer,
                    struct sq_query *held)
{
    if (!pool || !owner || !seq || !identity || !store || !owner->ready || owner->closed ||
        owner->primary)
        return SA_IDENTITY;
    uint64_t normal_end = pool->normal_end;
    if (remote && remote->deadline && remote->deadline < normal_end)
        normal_end = remote->deadline;
    unsigned char session_failure[4096];
    size_t session_failure_length = 0;
    unsigned session_failure_stage = 0;
    struct rp_handle parent_ticket = {0};
    if (parent && (sf_active_ticket(parent, &parent_ticket) || parent_ticket.pool != pool ||
                   !transfer || transfer <= pool->transfer_high_water))
        return SA_IDENTITY;
    if (parent) {
        const struct rp_ticket *a = rp_get(parent_ticket);
        const struct nt_context *c = &a->transaction.bound;
        const struct nt_readback *r = &a->transaction.expected_readback;
        if (r->scope != 1 || r->alias || !(r->direction & 2) ||
            r->max_bytes < (remote ? 226u : 184u) || c->socket != owner->expected.ino ||
            c->netns != owner->plan.netns_ino || c->epoch != owner->plan.epoch ||
            c->family != family || c->port != owner->plan.binding || c->seq >= *seq)
            return SA_IDENTITY;
        if (normal_end > c->deadline)
            normal_end = c->deadline;
    }
    struct parent_guard guards[4] = {0};
    struct rp_handle h[4] = {{0}};
    struct rn_port ports[4] = {0};
    struct nt_context ctx[4];
    struct nt_budget budget = {1024, sizeof(struct nt_ledger), 4, 1000000};
    struct sc_client client = {0};
    struct sb_backend backend = {0}, fragment_hash = {0};
    struct np_intent intent = {0};
    OSSL_LIB_CTX *lib = NULL;
    EVP_PKEY_CTX *import = NULL;
    EVP_PKEY *key = NULL;
    const OSSL_PROVIDER *provider = NULL;
    unsigned char pub[32];
    size_t pubn = 32;
    struct rp_ticket *from = rp_get(source);
    int primary = 0, secondary = 0, committed = 0, cancelled = 0;
    unsigned emitted = 0;
    uint64_t peer = 0;
    if (!from || !from->ran || from->busy || from->persist_attempted || from->primary ||
        from->transaction.request[16] != 76 || !from->transaction.accepted ||
        !from->transaction.peer_context || from->transaction.member_context.direction != 1 ||
        source.pool != pool || !identity || !store || *seq > UINT32_MAX - 4)
        primary = SA_IDENTITY;
    if (!primary) {
        const struct nt_context *c = &from->transaction.bound;
        if (c->socket != owner->expected.ino || c->netns != owner->plan.netns_ino ||
            c->epoch != owner->plan.epoch || c->port != owner->plan.binding || c->family == family)
            primary = SA_IDENTITY;
        else
            peer = from->transaction.peer_context;
        if (parent && rp_get(parent_ticket)->transaction.expected_readback.peer != peer)
            primary = SA_IDENTITY;
    }
    lib = OSSL_LIB_CTX_new();
    if ((!lib || OSSL_LIB_CTX_load_config(lib, NULL) != 1 ||
         EVP_default_properties_is_fips_enabled(lib)) &&
        !primary)
        primary = SA_REFUSED;
    if (!primary) {
        import = EVP_PKEY_CTX_new_from_name(lib, "ED25519", NULL);
        OSSL_PARAM p[] = {
            OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, identity->seed, 32),
            OSSL_PARAM_construct_end()};
        if (!import || EVP_PKEY_fromdata_init(import) != 1 ||
            EVP_PKEY_fromdata(import, &key, EVP_PKEY_KEYPAIR, p) != 1 || !key)
            primary = SA_REFUSED;
        else {
            provider = EVP_PKEY_get0_provider(key);
            if (!provider || strcmp(OSSL_PROVIDER_get0_name(provider), "default") ||
                EVP_PKEY_get_raw_public_key(key, pub, &pubn) != 1 || pubn != 32 ||
                memcmp(pub, identity->public_key, 32))
                primary = SA_IDENTITY;
        }
    }
    struct nt_prepare setup = {peer, parent ? 2 : 1, remote ? 2 : 1, parent ? 1 : 0, {0}};
    memcpy(setup.public_key, identity->public_key, 32);
    struct sa_policy policy = {0};
    policy.expected.context = (struct sa_context){
        1, owner->plan.epoch, peer, owner->plan.netns_ino, owner->expected.ino, 0};
    policy.expected.deadline = normal_end;
    memcpy(policy.expected.public_key, identity->public_key, 32);
    policy.provider = provider;
    policy.key_reference = &backend;
    policy.fixture_authorized = 1;
    for (unsigned i = 0; i < 4 && !primary; i++) {
        ctx[i] = (struct nt_context){owner->expected.ino,
                                     owner->plan.epoch,
                                     owner->plan.netns_ino,
                                     i == 2 ? pool->close_end : normal_end,
                                     ++*seq,
                                     owner->plan.binding,
                                     family};
        if (!rp_reserve_tx(pool, i == 2, &budget, parent && i == 3 ? 264 : 256, &h[i]) ||
            ((i == 0 || i == 2) && !rn_init(&ports[i], pool, &h[i], owner->fd, owner->expected.dev,
                                            owner->expected.ino, &ctx[i], &budget)))
            primary = SA_REFUSED;
    }
    for (unsigned i = 0; i < 4; i++)
        guards[i] = (struct parent_guard){i == 2 ? NULL : parent, parent_ticket, h[i],
                                          parent ? parent->revision : 0, rn_stream(&ports[i])};
    if (!primary) {
        struct sb_policy bp = {lib,
                               provider,
                               "provider=default",
                               identity->seed,
                               32,
                               parent ? parent_sign_clock : clock_ns,
                               parent ? &guards[0] : NULL};
        if (!sb_init(&backend, &bp) || (parent && !sb_init(&fragment_hash, &bp)))
            primary = SA_REFUSED;
        else
            primary = remote ? np_bind_m2(&intent, &ports[0], &setup, &policy, remote)
                             : np_bind(&intent, &ports[0], &setup, &policy);
    }
    OPENSSL_cleanse(identity->seed, 32);
    if (!primary) {
        struct nt_stream io = guarded_stream(&guards[0]);
        primary = rp_prepare(h[0], &ctx[0], &setup, &io);
    }
    if (!primary) {
        struct sa_ops ops = sb_operations(&backend);
        primary = remote ? np_sign_m2(&intent, &client, remote->expected_wire, 130, &backend, &ops)
                         : np_sign(&intent, &client, &ops);
    }
    /* PREPARE may expire earlier than the phase. Bind untouched COMMIT/TX ports
  * once, using the already accepted absolute signer expiry; never refresh it. */
    if (!primary) {
        if (!client.deadline || client.deadline > normal_end)
            primary = SA_TIME;
        for (unsigned i = 1; i < 4 && !primary; i += 2) {
            ctx[i].deadline = client.deadline;
            if (!rn_init(&ports[i], pool, &h[i], owner->fd, owner->expected.dev,
                         owner->expected.ino, &ctx[i], &budget))
                primary = SA_REFUSED;
        }
    }
    if (!primary) {
        struct nt_stream io = guarded_stream(&guards[1]);
        primary = rp_commit_prepared(h[1], h[0], &ctx[1], &io);
        committed = !primary;
    }
    int submitted = 0;
    if (!primary) {
        struct nt_control cp = {parent ? 19 : 47, peer, parent ? transfer : 0,
                                parent ? (remote ? 226 : 184) : (remote ? 176 : 134)};
        struct nt_stream io = guarded_stream(&guards[3]);
        primary = rp_control(h[3], h[0], h[1], parent_ticket, &ctx[3], &cp,
                             parent ? &fragment_hash : &backend, &io);
        submitted = !primary;
    }
    if (result) {
        struct rp_ticket *commit = rp_get(h[1]);
        result->commit_possible = commit && commit->transaction.possible;
        result->submitted = submitted;
        result->session_possible = result->commit_possible;
        result->peer = peer;
    }
    if (held && submitted && !primary) {
        struct rp_store persistence = rf_operations(&store->files);
        unsigned retire[3] = {2, 1, 3}, count = parent ? 3 : 2, start = parent ? 0 : 1;
        if (parent)
            primary = rp_cancel_not_run(h[2], h[0], h[1], &ctx[2]);
        for (unsigned i = start; i < start + count && !primary; i++) {
            struct rp_ticket *t = rp_get(h[retire[i]]);
            uint64_t before = clock_ns(NULL);
            if (!t || t->primary || before >= normal_end)
                primary = SA_TIME;
            else if (!rp_encode(h[retire[i]], NULL) ||
                     !rp_persist(h[retire[i]], normal_end, &persistence))
                primary = t->primary ? t->primary : SA_CALLBACK;
            uint64_t after = clock_ns(NULL);
            if (!primary && (after < before || after >= normal_end))
                primary = SA_TIME;
            if (!primary && pool->primary)
                primary = pool->primary;
            if (!primary && parent && !parent_check(&guards[0]))
                primary = SA_IDENTITY;
            if (!primary && result)
                result->handshake_retired++;
        }
    }
    if (selection && submitted && !primary) {
        /* A finite observation delay, NOT proof the remote peer has completed.
   * No LIST retry: absence/ambiguity at the observation remains incomplete. */
        uint64_t before = clock_ns(NULL);
        if (!remote) {
            if (before >= normal_end || normal_end - before <= 1000000000ULL)
                primary = SA_TIME;
            else {
                int waited = poll(NULL, 0, 1000);
                uint64_t after = clock_ns(NULL);
                if (waited || after < before || after >= normal_end)
                    primary = SA_TIME;
            }
        }
        if (!primary) {
            struct nt_selection chosen = *selection;
            if (chosen.valid_until > normal_end)
                chosen.valid_until = normal_end;
            struct sq_query local = {0};
            struct sq_query *query = held ? held : &local;
            primary = parent
                          ? sq_open_parent(query, pool, owner, family, seq, &chosen, 4096, parent)
                          : sq_open(query, pool, owner, family, seq, &chosen, 4096);
            if (primary) {
                for (unsigned j = 0; j < 5; j++) {
                    struct rp_ticket *bad = rp_get(query->flow.ticket[j]);
                    if (bad && bad->ran && bad->primary) {
                        session_failure_stage = j + 1;
                        session_failure_length = bad->transaction.raw.length;
                        if (session_failure_length > sizeof(session_failure))
                            session_failure_length = sizeof(session_failure);
                        memcpy(session_failure, bad->transaction.raw.bytes, session_failure_length);
                        break;
                    }
                }
            }
            if (result)
                result->session_observed = query->flow.observed;
            if (!primary)
                primary = sq_checkpoint(query, store);
            if (!primary && held)
                primary = sq_compact(query, store);
            if (!primary && parent && !parent_check(&guards[0]))
                primary = SA_IDENTITY;
            if (result)
                result->session_setup_retired =
                    query->flow.archived[0] + query->flow.archived[1] + query->flow.archived[2];
            int closed = (!held || primary) ? sq_close(query, store) : 0;
            if (closed) {
                if (!primary)
                    primary = closed;
                else if (!secondary)
                    secondary = closed;
            }
            if (result)
                result->session_delete_ack = query->flow.delete_ack;
        }
    }
    struct rp_ticket *pre = rp_get(h[0]);
    if (pre && pre->prepared && h[2].pool && (!parent || !pre->commit_attempted)) {
        struct nt_stream io = rn_stream(&ports[2]);
        int rc = parent ? rp_cancel(h[2], h[0], &ctx[2], &io)
                        : rp_cancel_adjacent(h[2], h[0], &ctx[2], &io);
        cancelled = !rc;
        if (rc) {
            if (!primary)
                primary = rc;
            else
                secondary = rc;
        }
    }
    printf("{\"scope\":%u,\"peer\":%llu,\"public_key\":\"", parent ? 2u : 1u,
           (unsigned long long)peer);
    for (unsigned j = 0; j < 32; j++)
        printf("%02x", identity->public_key[j]);
    printf(
        "\",\"signature_verified_locally\":%s,\"commit_accepted\":%s,\"adjacent_cancel_ack\":%s,\"session_proven\":false,\"openssl_version\":%lu,\"operations\":[",
        client.accepted ? "true" : "false", committed ? "true" : "false",
        cancelled && !parent ? "true" : "false", OpenSSL_version_num());
    for (unsigned i = 0; i < 4; i++) {
        struct rp_ticket *t = rp_get(h[i]);
        if (!t || !t->ran)
            continue;
        if (emitted++)
            putchar(',');
        int encoded = rp_encode(h[i], i == 0 && t->sign_attempted ? &client : NULL);
        printf("{\"command\":%u,\"rc\":%d,\"receipt\":\"",
               i == 0   ? 16
               : i == 1 ? 17
               : i == 2 ? 18
               : parent ? 19
                        : 47,
               t->primary);
        for (size_t j = 0; j < t->length; j++)
            printf("%02x", t->receipt[j]);
        printf("\"}");
        if (!encoded || !nq_archive(store, h[i])) {
            if (!primary)
                primary = -EIO;
            else if (!secondary)
                secondary = -EIO;
        }
    }
    printf("],\"session_failure_stage\":%u,\"session_failure_raw\":\"", session_failure_stage);
    for (size_t j = 0; j < session_failure_length; j++)
        printf("%02x", session_failure[j]);
    printf("\",\"completion\":[");
    int hash_closed = !fragment_hash.initialized || sb_destroy(&fragment_hash);
    int closed = (!backend.initialized || sb_destroy(&backend)) && hash_closed;
    if (!closed && !secondary)
        secondary = -EBUSY;
    printf(
        "],\"direct_control_submitted\":%s,\"known_request_cancel_ack\":%s,\"public_control_submitted\":%s,\"primary\":%d,\"secondary\":%d,\"provider_closed\":%s}",
        submitted && parent ? "true" : "false", cancelled && parent ? "true" : "false",
        submitted && !parent ? "true" : "false", primary, secondary, closed ? "true" : "false");
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(import);
    /* A temporal barrier can retain signer resources. Do not fabricate CLOSE.
  * This command process then exits; outer private VM containment is separate. */
    if (closed)
        OSSL_LIB_CTX_free(lib);
    if (result) {
        result->primary = primary;
        result->secondary = secondary;
        result->cancel_ack = cancelled;
        result->provider_closed = closed;
    }
    return primary ? primary : secondary;
}

int mq_run(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
           struct rp_handle source, struct nq_store *store, struct mq_identity *identity)
{
    return exchange(p, o, family, seq, source, store, identity, NULL, NULL, NULL, NULL, 0, NULL);
}
int mq_respond(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
               struct rp_handle source, struct nq_store *store, struct mq_identity *identity,
               const struct cm_m1 *captured, struct mq_result *result)
{
    if (!result)
        return SA_REFUSED;
    if (result->started)
        return SA_REPEAT;
    result->started = 1;
    if (!captured || captured->scope != 1 || !captured->receipt_id ||
        !captured->receipt_generation || captured->after < captured->before ||
        captured->remote.not_before < captured->after) {
        result->primary = SA_IDENTITY;
        return result->primary;
    }
    /* Bounded owned copy, not an authentication flag. np_sign_m2 verifies the
  * admitted M1 and exact kernel prefix binding before any local signature. */
    struct nt_remote_m1 remote = captured->remote;
    result->capture_id = captured->receipt_id;
    result->capture_generation = captured->receipt_generation;
    int rc =
        exchange(p, o, family, seq, source, store, identity, &remote, result, NULL, NULL, 0, NULL);
    if (rc && !result->primary)
        result->primary = rc;
    return rc;
}

static int pair_exchange(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
                         struct rp_handle source, struct nq_store *store,
                         struct mq_identity *identity, const struct cm_m1 *captured,
                         const struct nt_selection *selection, struct mq_result *result,
                         struct sq_query *held)
{
    if (!result)
        return SA_REFUSED;
    if (result->started)
        return SA_REPEAT;
    result->started = 1;
    if (!selection || !nt_selection_valid(selection) ||
        (captured &&
         (captured->scope != 1 || !captured->receipt_id || !captured->receipt_generation ||
          captured->after < captured->before || captured->remote.not_before < captured->after))) {
        result->primary = SA_IDENTITY;
        return result->primary;
    }
    struct nt_remote_m1 remote = {0};
    if (captured) {
        remote = captured->remote;
        result->capture_id = captured->receipt_id;
        result->capture_generation = captured->receipt_generation;
    }
    int rc = exchange(p, o, family, seq, source, store, identity, captured ? &remote : NULL, result,
                      selection, NULL, 0, held);
    if (rc && !result->primary)
        result->primary = rc;
    return rc;
}

/* remote is an independently admitted DIRECT M1 operand, not an adjacent frame.
 * The signature/prefix join is still performed by np_sign_m2. No capture or
 * remote acceptance is manufactured here. No post-COMMIT recursive abort exists. */
int mq_direct(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
              struct rp_handle source, struct nq_store *store, struct mq_identity *identity,
              struct sf_flow *parent, uint32_t transfer, const struct nt_remote_m1 *remote,
              struct mq_result *result)
{
    if (!result)
        return SA_REFUSED;
    if (result->started)
        return SA_REPEAT;
    result->started = 1;
    if (!parent || !transfer) {
        result->primary = SA_IDENTITY;
        return result->primary;
    }
    int rc = exchange(p, o, family, seq, source, store, identity, remote, result, NULL, parent,
                      transfer, NULL);
    if (rc && !result->primary)
        result->primary = rc;
    return rc;
}

int mq_direct_respond(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
                      struct rp_handle source, struct nq_store *store, struct mq_identity *identity,
                      struct sf_flow *parent, uint32_t transfer, const struct cm_m1 *captured,
                      struct mq_result *result)
{
    if (!result)
        return SA_REFUSED;
    if (result->started)
        return SA_REPEAT;
    struct rp_handle h;
    if (!captured || captured->scope != 2 || !captured->transfer || !captured->receipt_id ||
        !captured->receipt_generation || captured->after < captured->before ||
        captured->remote.not_before < captured->after || sf_active_ticket(parent, &h) ||
        h.id != captured->parent_id || h.generation != captured->parent_generation) {
        result->started = 1;
        result->primary = SA_IDENTITY;
        return result->primary;
    }
    result->capture_id = captured->receipt_id;
    result->capture_generation = captured->receipt_generation;
    return mq_direct(p, o, family, seq, source, store, identity, parent, transfer,
                     &captured->remote, result);
}

int mq_pair(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
            struct rp_handle source, struct nq_store *store, struct mq_identity *identity,
            const struct cm_m1 *captured, const struct nt_selection *selection,
            struct mq_result *result)
{
    return pair_exchange(p, o, family, seq, source, store, identity, captured, selection, result,
                         NULL);
}
int mq_pair_hold(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
                 struct rp_handle source, struct nq_store *store, struct mq_identity *identity,
                 const struct cm_m1 *captured, const struct nt_selection *selection,
                 struct sq_query *held, struct mq_result *result)
{
    if (!held || held->flow.initialized || held->flow.started)
        return SA_REFUSED;
    return pair_exchange(p, o, family, seq, source, store, identity, captured, selection, result,
                         held);
}

int mq_direct_hold(struct rp_pool *p, struct so_owner *o, uint16_t family, uint32_t *seq,
                   struct rp_handle source, struct nq_store *store, struct mq_identity *identity,
                   struct sf_flow *parent, uint32_t transfer, const struct cm_m1 *captured,
                   const struct nt_selection *selection, struct sq_query *held,
                   struct mq_result *result)
{
    if (!result)
        return SA_REFUSED;
    if (result->started)
        return SA_REPEAT;
    result->started = 1;
    struct rp_handle h;
    if (!held || held->flow.initialized || held->flow.started || !parent || !transfer ||
        !selection || !nt_selection_valid(selection) || selection->match.scope != 2 ||
        selection->match.alias != 1 || sf_active_ticket(parent, &h) ||
        selection->match.peer != parent->active.peer ||
        (captured &&
         (captured->scope != 2 || !captured->transfer || !captured->receipt_id ||
          !captured->receipt_generation || captured->after < captured->before ||
          captured->remote.not_before < captured->after || h.id != captured->parent_id ||
          h.generation != captured->parent_generation))) {
        result->primary = SA_IDENTITY;
        return result->primary;
    }
    /* Four handshake reservations, then three stable retirements, then five
  * session reservations: six additional slots at the successful peak.
  * This admission is not permission to cancel failed/uncertain custody. */
    unsigned available = 0;
    if (p && p->initialized && !p->primary)
        for (unsigned i = 0; i < RP_TICKETS; i++)
            if (!p->tickets[i].active && !p->tickets[i].observation_identity &&
                p->tickets[i].generation != UINT64_MAX)
                available++;
    if (available < 6) {
        result->primary = SA_REFUSED;
        return result->primary;
    }
    if (memcmp(selection->match.strong_id, parent->active.strong_id, 32)) {
        result->primary = SA_IDENTITY;
        return result->primary;
    }
    if (captured) {
        unsigned char expected[32], suite[2] = {0, 1};
        blake3_hasher hash;
        blake3_hasher_init(&hash);
        blake3_hasher_update(&hash, "PRP-STRONG-ID-v4", 16);
        blake3_hasher_update(&hash, suite, 2);
        blake3_hasher_update(&hash, captured->remote.public_key, 32);
        blake3_hasher_finalize(&hash, expected, 32);
        if (memcmp(expected, selection->match.strong_id, 32)) {
            result->primary = SA_IDENTITY;
            return result->primary;
        }
    }
    struct nt_remote_m1 remote = {0};
    if (captured) {
        remote = captured->remote;
        result->capture_id = captured->receipt_id;
        result->capture_generation = captured->receipt_generation;
    }
    int rc = exchange(p, o, family, seq, source, store, identity, captured ? &remote : NULL, result,
                      selection, parent, transfer, held);
    if (rc && !result->primary)
        result->primary = rc;
    return rc;
}
