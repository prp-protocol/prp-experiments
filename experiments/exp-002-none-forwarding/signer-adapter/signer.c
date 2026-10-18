#include "signer.h"
#include <string.h>
static int fail(struct sa_state *s, int e)
{
    s->failure_revision++;
    s->verified = 0;
    if (!s->primary)
        s->primary = e;
    else if (!s->secondary && s->primary != e)
        s->secondary = e;
    return 0;
}
static int same(const struct sa_request *a, const struct sa_request *b)
{
    return a->context.attempt == b->context.attempt && a->context.epoch == b->context.epoch &&
           a->context.endpoint == b->context.endpoint && a->context.netns == b->context.netns &&
           a->context.socket == b->context.socket && a->context.handle == b->context.handle &&
           a->prefix_len == b->prefix_len && a->deadline == b->deadline &&
           !memcmp(a->prefix, b->prefix, a->prefix_len) &&
           !memcmp(a->public_key, b->public_key, 32);
}
static int now(struct sa_state *s, const struct sa_ops *o, uint64_t end, uint64_t *raw, int closing)
{
    uint64_t revision = s->failure_revision;
    *raw = o->clock(o->arg);
    /* A caught reentry must not hide the returned clock. Temporal refusal
     * is irreversible, including for cleanup under an earlier primary. */
    if (*raw < s->last_time || *raw >= end) {
        s->time_refused = 1;
        fail(s, SA_TIME);
    }
    if (*raw > s->last_time)
        s->last_time = *raw;
    if (s->time_refused || s->failure_revision != revision)
        return 0;
    return closing || !s->primary;
}
int sa_native(void)
{
    return SA_REFUSED;
}
int sa_run(struct sa_state *s, const struct sa_policy *p, const struct sa_request *r,
           const struct sa_ops *o)
{
    struct sa_request req;
    struct sa_ops ops;
    const void *provider, *reference;
    unsigned char preimage[159], digest[32], proof[64];
    size_t n;
    int stage;
    if (!s)
        return SA_REFUSED;
    if (s->busy) {
        fail(s, SA_REENTRY);
        return s->primary;
    }
    if (s->started) {
        fail(s, SA_REPEAT);
        return s->primary;
    }
    s->started = 1;
    s->busy = 1;
    if (!p || !r || !o || !o->clock || !o->step || p->fixture_authorized != 1 || !p->provider ||
        !p->key_reference ||
        (r->prefix_len != 63 && r->prefix_len != 105 && r->prefix_len != 98 &&
         r->prefix_len != 140) ||
        p->expected.prefix_len != r->prefix_len || !r->deadline || !same(r, &p->expected)) {
        fail(s, SA_REFUSED);
        s->busy = 0;
        return s->primary;
    }
    /* Snapshot before injected callbacks. No mutable caller policy consulted later. */
    req = *r;
    ops = *o;
    provider = p->provider;
    reference = p->key_reference;
    memcpy(preimage, "PRP-HS2-ID-PROOF-v4", 19);
    memcpy(preimage + 19, req.prefix, req.prefix_len);
    for (stage = SA_HASH; stage <= SA_VERIFY; stage++) {
        struct sa_receipt *rec = &s->receipt[stage];
        struct sa_input in = {0};
        struct sa_output raw = {0};
        if (s->primary || !now(s, &ops, req.deadline, &rec->before, 0))
            break;
        in.stage = (enum sa_stage)stage;
        in.request = &req;
        in.key_reference = reference;
        in.key = s->owned_key;
        in.md = s->owned_md;
        in.provider = provider;
        if (stage == SA_HASH) {
            in.data = preimage;
            in.length = 19 + req.prefix_len;
        }
        if (stage == SA_SIGN) {
            in.data = digest;
            in.length = 32;
        }
        if (stage == SA_VERIFY) {
            in.data = proof;
            in.length = 64;
            in.digest = digest;
        }
        rec->called = 1;
        if (stage == SA_SIGN)
            s->sign_possible = 1;
        ops.step(ops.arg, &in, &raw);
        rec->raw = raw; /* Raw custody precedes guards. */
        /* Only designated creation stages can transfer exact fixture resources. */
        if (stage == SA_IMPORT && raw.key)
            s->owned_key = raw.key;
        if (stage == SA_INIT && raw.md)
            s->owned_md = raw.md;
        if (raw.rc != 1) {
            s->callback_error = raw.rc;
            fail(s, SA_CALLBACK);
        }
        if (!now(s, &ops, req.deadline, &rec->after, 0))
            break;
        if (s->primary)
            break;
        if (stage == SA_HASH) {
            if (raw.length != 32) {
                fail(s, SA_SHAPE);
                break;
            }
            memcpy(digest, raw.bytes, 32);
        } else if (stage == SA_IMPORT) {
            if (!raw.key || raw.provider != provider) {
                fail(s, SA_IDENTITY);
                break;
            }
        } else if (stage == SA_PUBLIC) {
            if (raw.length != 32 || memcmp(raw.bytes, req.public_key, 32)) {
                fail(s, SA_IDENTITY);
                break;
            }
        } else if (stage == SA_INIT) {
            if (!raw.md || raw.provider != provider) {
                fail(s, SA_IDENTITY);
                break;
            }
        } else if (stage == SA_SIGN) {
            if (raw.length != 64) {
                fail(s, SA_SHAPE);
                break;
            }
            memcpy(proof, raw.bytes, 64);
        } else if (raw.verified != 1) {
            fail(s, SA_IDENTITY);
            break;
        }
    }
    n = (size_t)stage;
    /* Cleanup observes same bound; expiry never fabricates release/settlement.
     * Receipt keeps original resource identity if cleanup cannot run or fails.
     */
    if (s->owned_key || s->owned_md) {
        struct sa_receipt *rec = &s->receipt[SA_CLOSE];
        struct sa_input in = {0};
        struct sa_output raw = {0};
        if (now(s, &ops, req.deadline, &rec->before, 1)) {
            in.stage = SA_CLOSE;
            in.key = s->owned_key;
            in.md = s->owned_md;
            in.provider = provider;
            in.request = &req;
            rec->called = 1;
            ops.step(ops.arg, &in, &raw);
            rec->raw = raw;
            if (raw.rc != 1) {
                if (!s->callback_error)
                    s->callback_error = raw.rc;
                fail(s, SA_CALLBACK);
            }
            if (now(s, &ops, req.deadline, &rec->after, 1) && raw.rc == 1) {
                s->owned_key = 0;
                s->owned_md = 0;
            }
        }
    }
    s->verified = n == SA_CLOSE && !s->primary;
    s->busy = 0;
    return s->primary;
}
