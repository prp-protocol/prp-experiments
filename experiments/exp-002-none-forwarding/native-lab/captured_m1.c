#include "captured_m1.h"
#include <string.h>
static int reject(struct rp_handle h, struct rp_ticket *t, int rc)
{
    if (t) {
        t->revision++;
        if (!t->primary)
            t->primary = rc;
        else if (!t->secondary)
            t->secondary = rc;
        rc = t->primary;
    }
    if (h.pool && !h.pool->primary)
        h.pool->primary = rc;
    return rc;
}
static int unicast(const unsigned char p[6])
{
    unsigned any = 0;
    for (unsigned i = 0; i < 6; i++)
        any |= p[i];
    return any && !(p[0] & 1);
}
static int admit(struct rp_handle h, const struct cm_path *p, uint64_t now,
                 const struct cm_direct_path *direct, struct sb_backend *hash, struct cm_m1 *out)
{
    struct rp_ticket *t = rp_get(h);
    if (out)
        memset(out, 0, sizeof(*out));
    if (!t)
        return SA_IDENTITY;
    if (t->capture_consumed)
        return reject(h, t, SA_REPEAT);
    t->capture_consumed = 1;
    if (!out || !p || h.pool->primary || t->primary || t->busy || t->final || t->raw_row != 2 ||
        !t->ran || !t->capture_attempted || t->persist_attempted || t->length || !t->commands ||
        !t->facts)
        return reject(h, t, SA_REFUSED);
    const struct rp_capture_raw *r = &t->capture_raw;
    size_t size = direct ? 198 : 148, offset = direct ? 68 : 18;
    if (!p->peer || !p->generation || !p->ifindex || !p->context.socket || !p->context.netns ||
        !p->context.epoch || !p->context.seq || p->context.family < 16 || !p->context.port ||
        !p->not_before || p->not_before >= p->end || p->end > p->context.deadline ||
        p->end > h.pool->normal_end || !unicast(p->source) || !unicast(p->destination) ||
        !memcmp(p->source, p->destination, 6))
        return reject(h, t, SA_IDENTITY);
    if (r->before < p->not_before || r->before < t->capture_not_before ||
        r->before != t->transaction.before || r->after != t->transaction.after ||
        r->after < r->before || now < r->after || now >= p->end || r->after >= t->capture_end ||
        t->capture_end > h.pool->normal_end)
        return reject(h, t, SA_TIME);
    if (r->rc || r->truncated || r->lost || r->length != size ||
        r->context.netns != p->context.netns || r->context.epoch != p->context.epoch ||
        r->context.ifindex != p->ifindex || r->context.direction != 2 ||
        memcmp(r->context.source, p->source, 6) ||
        memcmp(r->context.destination, p->destination, 6) || memcmp(r->bytes, p->destination, 6) ||
        memcmp(r->bytes + 6, p->source, 6) || memcmp(r->bytes + 12, "\x88\xfb", 2) ||
        memcmp(r->bytes + offset, "\x04\x00\x02\x01", 4))
        return reject(h, t, SA_IDENTITY);
    if (!direct) {
        if (memcmp(r->bytes + 14, "\x02\x01\xff\xff", 4))
            return reject(h, t, SA_IDENTITY);
    } else {
        struct rp_handle parent;
        uint64_t revision = direct->parent ? direct->parent->revision : 0;
        if (!hash || !direct->transfer || sf_active_ticket(direct->parent, &parent) ||
            parent.pool != h.pool)
            return reject(h, t, SA_IDENTITY);
        const struct rp_ticket *pt = rp_get(parent);
        const struct nt_context *c = &pt->transaction.bound;
        const struct nt_readback *a = &pt->transaction.expected_readback;
        if (a->scope != 1 || a->alias || !(a->direction & 1) || a->peer != p->peer ||
            a->max_bytes < 184 || c->socket != p->context.socket || c->epoch != p->context.epoch ||
            c->netns != p->context.netns || c->family != p->context.family ||
            c->port != p->context.port || p->end > c->deadline || r->before < pt->transaction.after)
            return reject(h, t, SA_IDENTITY);
        const unsigned char *b = r->bytes + 14;
        uint32_t transfer =
            ((uint32_t)b[12] << 24) | ((uint32_t)b[13] << 16) | ((uint32_t)b[14] << 8) | b[15];
        if (memcmp(b, "\0\1\0\1\7\0\0\xb0\2\1\0\0", 12) || transfer != direct->transfer ||
            memcmp(b + 16, "\0\0\0\x82\0\2", 6))
            return reject(h, t, SA_SHAPE);
        unsigned char saved[198], input[160], digest[32];
        const char domain[] = "PRP-HS2-FRAGMENT-v4";
        size_t d = sizeof(domain) - 1;
        memcpy(saved, r->bytes, sizeof(saved));
        memcpy(input, domain, d);
        memset(input + d, 0, 4);
        input[d + 3] = 130;
        memcpy(input + d + 4, b + 54, 130);
        if (!sb_sha256(hash, input, d + 4 + 130, digest) || memcmp(digest, b + 22, 32) ||
            memcmp(saved, r->bytes, sizeof(saved)))
            return reject(h, t, SA_IDENTITY);
        struct rp_handle after;
        if (h.pool->primary || t->primary || t->busy || direct->parent->revision != revision ||
            sf_active_ticket(direct->parent, &after) || after.id != parent.id ||
            after.generation != parent.generation || after.slot != parent.slot ||
            after.pool != parent.pool)
            return reject(h, t, SA_IDENTITY);
    }
    /* Public key comparison is not proof verification. np_sign_m2 still verifies
  * canonical shape/signature, complete-M1 binding and returned M2 generation. */
    if (memcmp(r->bytes + offset + 31, p->public_key, 32))
        return reject(h, t, SA_IDENTITY);
    out->remote.not_before = now;
    out->remote.context = p->context;
    out->remote.peer = p->peer;
    out->remote.deadline = p->end;
    out->remote.generation = p->generation;
    memcpy(out->remote.public_key, p->public_key, 32);
    memcpy(out->remote.expected_wire, r->bytes + offset, 130);
    out->scope = direct ? 2 : 1;
    if (direct) {
        struct rp_handle parent;
        if (sf_active_ticket(direct->parent, &parent))
            return reject(h, t, SA_IDENTITY);
        out->transfer = direct->transfer;
        out->parent_id = parent.id;
        out->parent_generation = parent.generation;
    }
    out->receipt_id = h.id;
    out->receipt_generation = h.generation;
    out->before = r->before;
    out->after = r->after;
    return 0;
}

int cm_admit(struct rp_handle h, const struct cm_path *p, uint64_t now, struct cm_m1 *out)
{
    return admit(h, p, now, NULL, NULL, out);
}
int cm_admit_direct(struct rp_handle h, const struct cm_direct_path *p, uint64_t now,
                    struct sb_backend *hash, struct cm_m1 *out)
{
    if (!p) {
        if (out)
            memset(out, 0, sizeof(*out));
        return reject(h, rp_get(h), SA_IDENTITY);
    }
    return admit(h, &p->path, now, p, hash, out);
}
