#include "transaction.h"
#include <string.h>
static uint64_t scalar(const unsigned char *p, size_t n)
{
    uint64_t v = 0;
    if (n == 1)
        v = *p;
    else if (n == 2) {
        uint16_t x;
        memcpy(&x, p, 2);
        v = x;
    } else if (n == 4) {
        uint32_t x;
        memcpy(&x, p, 4);
        v = x;
    } else if (n == 8)
        memcpy(&v, p, 8);
    return v;
}
static const struct {
    unsigned id, width, zero, adjacent;
} diagnostics[] = {
    {11, 4, 0, 0},  /* FLAGS */
    {12, 4, 0, 0},  /* MAX_MEMBERS */
    {14, 4, 0, 0},  /* MEMBER_COUNT */
    {8, 8, 0, 0},   /* LEASE_MS */
    {15, 8, 0, 0},  /* QUEUED_BYTES */
    {16, 8, 0, 0},  /* DROP_COUNT */
    {344, 8, 0, 0}, /* PROTECT_ONCE_COUNT */
    {345, 8, 0, 0}, /* REPLICATION_ATTEMPTS */
    {346, 8, 0, 0}, /* REPLICATION_SUCCESSES */
    {347, 8, 0, 0}, /* REPLICATION_FAILURES */
    {348, 8, 0, 0}, /* CARRIER_COPY_COUNT */
    {384, 4, 0, 0}, /* SESSION_OBJECT_BYTES */
    {399, 8, 0, 0}, /* PERSISTENT_STATE_BYTES */
    {400, 8, 0, 0}, /* KEY_MATERIAL_BYTES */
    {401, 8, 0, 0}, /* PROTOCOL_ROUND_TRIP_COMPLETIONS */
    {402, 1, 1, 0}, /* KEY_MATERIAL_EXPORTED */
    {389, 8, 0, 0}, /* SESSION_SERIALIZATION_ATTEMPTS */
    {390, 8, 0, 0}, /* SESSION_SERIALIZATION_WAITS */
    {391, 8, 0, 0}, /* SESSION_SERIALIZATION_WAIT_NS */
    {392, 8, 0, 0}, /* SESSION_SERIALIZATION_HOLD_NS */
    {393, 8, 0, 0}, /* ADJACENCY_CONTENTION_ATTEMPTS */
    {394, 8, 0, 0}, /* ADJACENCY_CONTENTION_WAITS */
    {395, 8, 0, 0}, /* ADJACENCY_CONTENTION_WAIT_NS */
    {397, 8, 0, 0}, /* REPLAY_PROBE_ATTEMPTS */
    {398, 8, 0, 0}, /* REPLAY_PROBE_REJECTIONS */
    {88, 8, 0, 0},  /* CRYPTO_TX_OPERATIONS */
    {89, 8, 0, 0},  /* CRYPTO_RX_OPERATIONS */
    {90, 8, 0, 0},  /* CRYPTO_TX_BYTES */
    {91, 8, 0, 0},  /* CRYPTO_RX_BYTES */
    {96, 8, 0, 0},  /* CRYPTO_TX_NS */
    {97, 8, 0, 0},  /* CRYPTO_RX_NS */
    {215, 4, 0, 0}, /* KEY_POLICY_GENERATION */
    {217, 8, 0, 0}, /* MAX_ACTIVE_KEY_AGE_MS */
    {218, 8, 0, 0}, /* MAX_ENCRYPTED_BYTES */
    {219, 8, 0, 0}, /* MAX_ENCRYPTED_ITEMS */
    {220, 8, 0, 0}, /* IDLE_KEY_RETENTION_MS */
    {221, 4, 0, 0}, /* OLD_GENERATION_OVERLAP_MS */
    {222, 8, 0, 0}, /* KEY_GENERATION_BORN_NS */
    {223, 8, 0, 0}, /* LAST_AUTHENTICATED_ACTIVITY_NS */
    {224, 8, 0, 0}, /* GENERATION_CRYPTO_TX_OPERATIONS */
    {225, 8, 0, 0}, /* GENERATION_CRYPTO_RX_OPERATIONS */
    {226, 8, 0, 0}, /* GENERATION_CRYPTO_TX_BYTES */
    {227, 8, 0, 0}, /* GENERATION_CRYPTO_RX_BYTES */
    {303, 8, 0, 0}, /* GENERATION_PROTECTED_TX_BYTES */
    {304, 8, 0, 0}, /* GENERATION_PROTECTED_RX_BYTES */
    {228, 1, 0, 0}, /* KEY_LIMIT_REASON */
    {229, 1, 0, 0}, /* KEY_TRANSITION_STATE */
    {230, 8, 0, 0}, /* OLD_GENERATION_EXPIRES_NS */
    {231, 1, 0, 0}, /* KEY_MATERIAL_PRESENT */
    {98, 8, 0, 0},  /* TX_ALLOCATIONS */
    {106, 8, 0, 0}, /* E2E_TX_NS */
    {34, 1, 1, 0},  /* REKEY_READY */
    {35, 1, 1, 0},  /* REKEY_ACTIVE */
    {92, 8, 0, 1},  /* ADJ_TX_SEGMENTS */
    {93, 8, 0, 1},  /* ADJ_RX_SEGMENTS */
    {94, 8, 0, 1},  /* ADJ_TX_CARRIER_BYTES */
    {95, 8, 0, 1},  /* ADJ_RX_CARRIER_BYTES */
    {99, 8, 0, 1},  /* ADJ_FRAGMENT_TX_TRANSFERS */
    {100, 8, 0, 1}, /* ADJ_FRAGMENT_BUILD_NS */
    {101, 8, 0, 1}, /* ADJ_CARRIER_PREPARE_NS */
    {102, 8, 0, 1}, /* ADJ_CARRIER_SUBMIT_NS */
    {107, 8, 0, 1}, /* ADJ_CARRIER_TX_BATCHES */
    {108, 8, 0, 1}, /* ADJ_CARRIER_TX_BATCH_UNITS */
    {109, 8, 0, 1}, /* ADJ_CARRIER_TX_FALLBACK_UNITS */
    {110, 8, 0, 1}, /* ADJ_CARRIER_TX_PARTIAL_BATCHES */
    {111, 8, 0, 1}, /* ADJ_CARRIER_BATCH_BUILD_NS */
    {71, 8, 0, 1},  /* ADJ_ACK_TX_RANGES */
    {72, 8, 0, 1},  /* ADJ_ACK_RX_RANGES */
    {73, 8, 0, 1},  /* ADJ_NACK_TX_RANGES */
    {74, 8, 0, 1},  /* ADJ_NACK_RX_RANGES */
    {75, 8, 0, 1},  /* ADJ_RECOVERY_TX_BYTES */
    {76, 8, 0, 1},  /* ADJ_RECOVERED_TRANSFERS */
    {77, 8, 0, 1},  /* ADJ_FRAGMENT_EXPIRED */
    {78, 4, 0, 1},  /* ADJ_FRAGMENT_RX_TIMEOUT_MS */
    {79, 4, 0, 1},  /* ADJ_FRAGMENT_TX_TIMEOUT_MS */
    {80, 4, 0, 1},  /* ADJ_FRAGMENT_MAX_QUEUED_BYTES */
    {81, 4, 0, 1},  /* ADJ_FRAGMENT_RX_QUEUED_BYTES */
    {82, 4, 0, 1},  /* ADJ_FRAGMENT_TX_QUEUED_BYTES */
};
unsigned nt_session_state(const struct nt_readback *r)
{
    return r->state ? r->state : 2;
}
int nt_readback_valid(const struct nt_readback *r)
{
    if (!r)
        return 0;
    if (r->command == 57)
        return !r->state;
    if (r->state && (r->command != 14 || (r->state != 1 && r->state != 2)))
        return 0;
    unsigned any = 0;
    for (unsigned i = 0; i < 32; i++)
        any |= r->strong_id[i];
    if ((r->command != 14 && r->command != 53 && r->command != 54 && r->command != 55) ||
        !r->peer || !any || !((r->scope == 1 && !r->alias) || (r->scope == 2 && r->alias == 1)))
        return 0;
    return (r->command == 53 || r->command == 54 || r->command == 55) ||
           (r->handle && r->generation && (r->max_bytes || nt_session_state(r) == 1) &&
            r->max_bytes <= 65535 && r->direction >= 1 && r->direction <= 3);
}
int nt_readback_attrs(struct nt_state *s, const unsigned char *p, size_t n)
{
    const struct nt_readback *r = &s->expected_readback;
    unsigned seen = 0;
    unsigned char seen_diag[sizeof(diagnostics) / sizeof(diagnostics[0])] = {0};
    /* Conservative finite grammar. Unknown diagnostics remain raw and refuse;
  * no native full SESSION_GET shape is inferred from this core projection. */
    while (n) {
        if (n < 4)
            return 0;
        size_t len = scalar(p, 2), step = (len + 3) & ~(size_t)3;
        unsigned type = (unsigned)scalar(p + 2, 2);
        if (len < 4 || step > n)
            return 0;
        for (size_t z = len; z < step; z++)
            if (p[z])
                return 0;
        size_t k = len - 4;
        const unsigned char *v = p + 4;
        unsigned bit = 0;
        uint64_t wanted = 0;
        size_t width = 0;
        if (type == 19 && k == 0) {
            p += step;
            n -= step;
            continue;
        }
        if (type == 22 && (r->command == 14 || r->command == 57)) {
            bit = 1;
            width = 2;
            wanted = 2;
        } else if (type == 305 && r->command == 57) {
            bit = 2;
            width = 1;
            wanted = 1;
        } else if (type == 23 && r->command != 57) {
            bit = 2;
            width = 8;
            wanted = r->peer;
        } else if (type == 33 && r->command != 57) {
            bit = 4;
            width = 1;
            wanted = r->scope;
        } else if (type == 4 && r->command != 57) {
            bit = 8;
            width = 2;
            wanted = r->alias;
        } else if (type == 69 && r->command != 57) {
            bit = 16;
            width = 2;
            wanted = 1;
        } else if (type == 70 && r->command != 57) {
            bit = 32;
            if (k != 32 || memcmp(v, r->strong_id, 32))
                return 0;
        } else if (type == 30 && (r->command == 53 || r->command == 55)) {
            bit = 64;
            if (k != 4 || !scalar(v, 4) || scalar(v, 4) > 300000)
                return 0;
            s->expires = (uint32_t)scalar(v, 4);
        } else if (type == 20 && r->command == 14) {
            bit = 64;
            width = 8;
            wanted = r->handle;
        } else if (type == 7 && r->command == 14) {
            bit = 128;
            width = 4;
            wanted = r->generation;
        } else if (type == 21 && r->command == 14) {
            bit = 256;
            width = 1;
            wanted = 4;
        } else if (type == 9 && r->command == 14) {
            bit = 512;
            width = 1;
            wanted = r->direction;
        } else if (type == 10 && r->command == 14) {
            bit = 1024;
            width = 1;
            wanted = nt_session_state(r);
        } else if (type == 13 && r->command == 14) {
            bit = 2048;
            width = 8;
            wanted = r->max_bytes;
        } else {
            if (r->command != 14)
                return 0;
            unsigned i;
            for (i = 0; i < sizeof(diagnostics) / sizeof(diagnostics[0]); i++)
                if (diagnostics[i].id == type)
                    break;
            if (i == sizeof(diagnostics) / sizeof(diagnostics[0]) || seen_diag[i] ||
                (diagnostics[i].adjacent && r->scope != 1) || k != diagnostics[i].width ||
                (diagnostics[i].zero && scalar(v, k)))
                return 0;
            seen_diag[i] = 1;
            p += step;
            n -= step;
            continue;
        }
        if (seen & bit)
            return 0;
        seen |= bit;
        if (width && (k != width || scalar(v, k) != wanted))
            return 0;
        p += step;
        n -= step;
    }
    unsigned required = r->command == 57 ? 3 : (r->command == 53 || r->command == 55) ? 126 : 4095;
    if (r->command == 14 && r->scope == 1)
        required &= ~8u; /* source omits alias0 */
    return seen == required;
}

int nt_selection_valid(const struct nt_selection *x)
{
    if (!x || !x->population || x->population > NT_LIST_MAX || x->not_before >= x->valid_until ||
        x->match.command != 14 || x->match.handle)
        return 0;
    struct nt_readback r = x->match;
    r.handle = 1;
    return nt_readback_valid(&r);
}
static int list_fail(struct nt_state *s, int error)
{
    if (!s->primary)
        s->primary = error;
    else if (!s->secondary)
        s->secondary = error;
    s->accepted = 0;
    return s->primary;
}
/* Extract only the typed core, then run the same complete strict GET grammar.
 * Diagnostic fields remain bounded by the original raw arena. */
static int object(const unsigned char *p, size_t n, struct nt_readback *r)
{
    *r = (struct nt_readback){.command = 14};
    const unsigned char *start = p;
    size_t total = n;
    while (n) {
        if (n < 4)
            return 0;
        size_t len = scalar(p, 2), step = (len + 3) & ~(size_t)3;
        unsigned t = (unsigned)scalar(p + 2, 2);
        if (len < 4 || step > n)
            return 0;
        size_t k = len - 4;
        const unsigned char *v = p + 4;
        if (t == 20 && k == 8)
            r->handle = scalar(v, k);
        if (t == 23 && k == 8)
            r->peer = scalar(v, k);
        if (t == 13 && k == 8)
            r->max_bytes = scalar(v, k);
        if (t == 7 && k == 4)
            r->generation = (uint32_t)scalar(v, k);
        if (t == 4 && k == 2)
            r->alias = (uint16_t)scalar(v, k);
        if (t == 33 && k == 1)
            r->scope = *v;
        if (t == 9 && k == 1)
            r->direction = *v;
        if (t == 10 && k == 1)
            r->state = *v;
        if (t == 70 && k == 32)
            memcpy(r->strong_id, v, 32);
        p += step;
        n -= step;
    }
    if (r->state != 1 && r->state != 2)
        return 0;
    struct nt_state check = {0};
    check.expected_readback = *r;
    return nt_readback_valid(r) && nt_readback_attrs(&check, start, total);
}
int nt_list_parse(struct nt_state *s, const struct nt_context *c, int complete)
{
    size_t at = 0, n = s->raw.length;
    uint64_t handles[NT_LIST_MAX] = {0};
    unsigned count = 0, matches = 0, done = 0, ack = 0;
    uint64_t selected = 0;
    s->population = s->matches = s->list_done = 0;
    s->selected_handle = 0;
    if (!nt_selection_valid(&s->selection) || n > sizeof(s->raw.bytes) || s->raw.rc ||
        s->raw.truncated || s->raw.sender || s->raw.context.socket != c->socket ||
        s->raw.context.netns != c->netns || s->raw.context.epoch != c->epoch)
        return list_fail(s, SA_IDENTITY);
    while (at < n) {
        const unsigned char *p = s->raw.bytes + at;
        if (n - at < 16)
            return list_fail(s, SA_SHAPE);
        size_t len = scalar(p, 4), step = (len + 3) & ~(size_t)3;
        unsigned type = (unsigned)scalar(p + 4, 2), flags = (unsigned)scalar(p + 6, 2);
        if (len < 16 || step > n - at || scalar(p + 8, 4) != c->seq || scalar(p + 12, 4) != c->port)
            return list_fail(s, SA_SHAPE);
        for (size_t i = len; i < step; i++)
            if (p[i])
                return list_fail(s, SA_SHAPE);
        if (type == 2) {
            if (len != 36 || (flags != 0 && flags != 256) || scalar(p + 16, 4) || ack++ ||
                memcmp(p + 20, s->request, 16))
                return list_fail(s, SA_CALLBACK);
        } else if (type == 3) {
            if (done || len != 20 || flags != 2 || scalar(p + 16, 4))
                return list_fail(s, SA_SHAPE);
            done = 1;
            s->list_done = 1;
        } else {
            if (done || type != c->family || flags != 2 || len < 20 || p[16] != 15 || p[17] != 1 ||
                scalar(p + 18, 2) || count >= s->selection.population)
                return list_fail(s, SA_SHAPE);
            struct nt_readback r;
            if (!object(p + 20, len - 20, &r))
                return list_fail(s, SA_IDENTITY);
            for (unsigned i = 0; i < count; i++)
                if (handles[i] == r.handle)
                    return list_fail(s, SA_IDENTITY);
            handles[count++] = r.handle;
            s->population = count;
            const struct nt_readback *w = &s->selection.match;
            if (r.peer == w->peer && r.scope == w->scope && r.alias == w->alias &&
                r.generation == w->generation && r.direction == w->direction &&
                r.max_bytes == w->max_bytes && nt_session_state(&r) == nt_session_state(w) &&
                !memcmp(r.strong_id, w->strong_id, 32)) {
                matches++;
                selected = r.handle;
                s->matches = matches;
            }
        }
        at += step;
    }
    /* Successful dump startup suppresses a separate ACK in Linux. DONE is
  * mandatory; any ACK present is still fully validated above. */
    if (!done)
        return complete ? list_fail(s, SA_SHAPE) : -1;
    if (matches != 1)
        return list_fail(s, SA_IDENTITY);
    s->selected_handle = selected;
    return 0;
}

/* Count-terminated core enumerations deliberately do not use SESSION_LIST's
 * multipart/DONE grammar. Source contract a2918b99, core Ethernet slice only. */
static int core_fail(struct nt_state *s, int code)
{
    if (!s->primary)
        s->primary = code;
    else if (!s->secondary)
        s->secondary = code;
    s->accepted = 0;
    return code;
}
static int core_object(struct nt_state *s, const unsigned char *p, size_t n, uint32_t *handle,
                       unsigned record)
{
    unsigned char seen[282] = {0};
    unsigned attributes = 0;
    int count = -1;
    uint64_t value[282] = {0};
    while (n) {
        if (n < 4)
            return 0;
        unsigned len = scalar(p, 2), kind = scalar(p + 2, 2);
        size_t step = (len + 3u) & ~3u;
        if (len < 4 || step > n || kind >= 282)
            return 0;
        for (size_t i = len; i < step; i++)
            if (p[i])
                return 0;
        if (!kind && len == 4) {
            p += step;
            n -= step;
            continue;
        }
        if (seen[kind]++)
            return 0;
        attributes++;
        size_t z = len - 4;
        const unsigned char *v = p + 4;
        unsigned width = 0;
        if (kind == 1) {
            if (z != 9 || memcmp(v, "ethernet", 9))
                return 0;
        } else if (kind == 5 && s->carrier.command == 62) {
            if (z < 2 || z > 16 || v[z - 1] || memchr(v, 0, z - 1))
                return 0;
        } else if (kind == 259 && s->carrier.command == 75) {
            if (!z || z > 128)
                return 0;
        } else if (kind == 277 && s->carrier.command == 75) {
            if (z != 16)
                return 0;
        } else {
            if (kind == 9 || kind == 23)
                width = 4;
            if (s->carrier.command == 62) {
                if (kind == 6)
                    width = 2;
                if (kind == 219)
                    width = 1;
            }
            if (s->carrier.command == 76) {
                if (kind == 256)
                    width = 4;
                if (kind == 261 || kind == 276)
                    width = 8;
                if (kind == 275)
                    width = 1;
            }
            if (s->carrier.command == 75) {
                if (kind == 256 || kind == 260)
                    width = 4;
                if (kind == 257 || kind == 258 || kind == 274 || kind == 279)
                    width = 1;
                if (kind == 261 || kind == 278 || kind == 280 || kind == 281)
                    width = 8;
            }
            if (!width || width != z)
                return 0;
            value[kind] = scalar(v, z);
            if (kind == 23 && s->carrier.command == 75) {
                if (value[kind] > s->carrier.population)
                    return 0;
                count = (int)value[kind];
            }
        }
        p += step;
        n -= step;
    }
    if (s->carrier.command == 62)
        return seen[1] && seen[9] && seen[219] && seen[5] && seen[6] && seen[23] &&
                       attributes == 6 && value[9] == s->carrier.ifindex && value[219] == 1 &&
                       value[6] >= 68
                   ? 1
                   : 0;
    if (s->carrier.command == 76) {
        const struct nt_member_context *m = &s->member_context;
        if (attributes != 5 || !seen[1] || !seen[256] || !seen[261] || !seen[275] || !seen[276] ||
            value[256] != m->handle || value[261] != m->generation || value[275] != m->direction ||
            !value[276])
            return 0;
        s->peer_context = value[276];
        return 1;
    }
    if (count >= 0)
        return attributes == 1 ? 2 + count : 0;
    const unsigned required[] = {1, 256, 257, 258, 274, 259, 260, 261, 9};
    for (unsigned i = 0; i < sizeof(required) / sizeof(required[0]); i++)
        if (!seen[required[i]])
            return 0;
    if (!value[256] || !value[261] || !value[9] || !value[260])
        return 0;
    /* Only complete declared optional groups; never infer a missing generation. */
    if (seen[277] != seen[278] || seen[277] != seen[279] || seen[280] != seen[281])
        return 0;
    if (record >= 4)
        return 0;
    s->members[record] = (struct nt_member_observation){(uint32_t)value[256], (uint32_t)value[9],
                                                        value[261], (unsigned char)value[274]};
    *handle = (uint32_t)value[256];
    return 1;
}
int nt_carrier_parse(struct nt_state *s, const struct nt_context *c, int complete)
{
    const unsigned char *b = s->raw.bytes;
    size_t n = s->raw.length, at = 0;
    unsigned ack = 0, records = 0, count_seen = 0, count = 0;
    uint32_t handles[4] = {0};
    unsigned cmd = s->carrier.command;
    memset(s->members, 0, sizeof(s->members));
    s->peer_context = 0;
    if (n > 4096 || s->raw.rc || s->raw.truncated || s->raw.sender)
        return core_fail(s, SA_SHAPE);
    while (at < n) {
        if (n - at < 16)
            return core_fail(s, SA_SHAPE);
        const unsigned char *p = b + at;
        size_t len = scalar(p, 4), step = (len + 3) & ~(size_t)3;
        unsigned type = scalar(p + 4, 2), flags = scalar(p + 6, 2);
        if (len < 16 || step > n - at || scalar(p + 8, 4) != c->seq || scalar(p + 12, 4) != c->port)
            return core_fail(s, SA_IDENTITY);
        for (size_t z = len; z < step; z++)
            if (p[z])
                return core_fail(s, SA_SHAPE);
        if (type == 2) {
            if (len < 20)
                return core_fail(s, SA_SHAPE);
            if (scalar(p + 16, 4))
                return core_fail(s, SA_CALLBACK);
            if (ack++ || len != 36 || (flags && flags != 256) || memcmp(p + 20, s->request, 16))
                return core_fail(s, SA_SHAPE);
        } else {
            if (type != c->family || flags || len < 20 || p[16] != cmd || p[17] != 1 ||
                scalar(p + 18, 2) || (cmd != 62 && cmd != 75 && cmd != 76))
                return core_fail(s, SA_SHAPE);
            uint32_t handle = 0;
            int parsed = core_object(s, p + 20, len - 20, &handle, records);
            if (!parsed)
                return core_fail(s, SA_SHAPE);
            if (parsed >= 2) {
                if (count_seen++ || cmd != 75)
                    return core_fail(s, SA_SHAPE);
                count = (unsigned)parsed - 2;
            } else {
                if (count_seen || records >= s->carrier.population ||
                    ((cmd == 62 || cmd == 76) && records))
                    return core_fail(s, SA_SHAPE);
                for (unsigned i = 0; i < records; i++)
                    if (handle && handles[i] == handle)
                        return core_fail(s, SA_IDENTITY);
                handles[records++] = handle;
            }
        }
        at += step;
    }
    s->carrier_records = records;
    s->carrier_count_seen = count_seen;
    if (count_seen && count != records)
        return core_fail(s, SA_SHAPE);
    if (ack != 1 || ((cmd == 62 || cmd == 76) && records != 1) || (cmd == 75 && !count_seen))
        return complete ? core_fail(s, SA_SHAPE) : -1;
    return 0;
}

/* Restrictive complete FANOUT grammar for the selected empty/one-object domain.
 * Extra objects or unsupported attributes are raw evidence and refuse. */
static int fanout_attrs(struct nt_state *s, const unsigned char *p, size_t n)
{
    static const unsigned ids[] = {1, 7,  10, 4,  5,   23,  341, 11,  12, 14,
                                   8, 13, 15, 16, 344, 345, 346, 347, 348};
    static const unsigned widths[] = {8, 4, 1, 2, 4, 8, 2, 4, 4, 4, 8, 8, 8, 8, 8, 8, 8, 8, 8};
    const struct nt_fanout *f = &s->fanout;
    unsigned seen = 0;
    uint64_t handle = 0;
    uint64_t wants[] = {f->handle,
                        f->generation,
                        2,
                        2100,
                        100,
                        f->peer,
                        1,
                        f->flags,
                        f->max_members,
                        0,
                        f->lease_ms,
                        f->max_bytes,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0,
                        0};
    while (n) {
        if (n < 4)
            return 0;
        size_t len = scalar(p, 2), step = (len + 3) & ~(size_t)3;
        unsigned id = (unsigned)scalar(p + 2, 2);
        if (len < 4 || step > n)
            return 0;
        for (size_t j = len; j < step; j++)
            if (p[j])
                return 0;
        if (id == 19 && len == 4) {
            p += step;
            n -= step;
            continue;
        }
        unsigned i;
        for (i = 0; i < 19 && ids[i] != id; i++)
            ;
        if (i == 19 || seen & (1u << i) || len != widths[i] + 4)
            return 0;
        uint64_t v = scalar(p + 4, widths[i]);
        if (!i) {
            if (!v || (f->handle && v != f->handle))
                return 0;
            handle = v;
        } else if (i < 12 && v != wants[i])
            return 0;
        seen |= 1u << i;
        p += step;
        n -= step;
    }
    if (seen != ((1u << 19) - 1))
        return 0;
    s->handle = handle;
    return 1;
}
int nt_fanout_parse(struct nt_state *s, const struct nt_context *c, int complete)
{
    const unsigned char *b = s->raw.bytes;
    size_t n = s->raw.length, at = 0;
    unsigned ack = 0, objects = 0, done = 0;
    unsigned cmd = s->fanout.command;
    if (n > sizeof(s->raw.bytes) || s->raw.rc || s->raw.truncated || s->raw.sender ||
        s->raw.context.socket != c->socket || s->raw.context.epoch != c->epoch ||
        s->raw.context.netns != c->netns)
        return list_fail(s, SA_IDENTITY);
    while (at < n) {
        if (n - at < 16)
            return list_fail(s, SA_SHAPE);
        const unsigned char *p = b + at;
        size_t len = scalar(p, 4), step = (len + 3) & ~(size_t)3;
        unsigned type = (unsigned)scalar(p + 4, 2), flags = (unsigned)scalar(p + 6, 2);
        if (len < 16 || step > n - at || scalar(p + 8, 4) != c->seq || scalar(p + 12, 4) != c->port)
            return list_fail(s, SA_SHAPE);
        for (size_t j = len; j < step; j++)
            if (p[j])
                return list_fail(s, SA_SHAPE);
        if (type == 2) {
            if (len < 20)
                return list_fail(s, SA_SHAPE);
            if (scalar(p + 16, 4))
                return list_fail(s, SA_CALLBACK);
            if (ack++ || len != 36 || (flags != 0 && flags != 256) ||
                memcmp(p + 20, s->request, 16))
                return list_fail(s, SA_SHAPE);
        } else if (type == 3) {
            if (cmd != 4 || done++ || flags != 2 || len != 20 || scalar(p + 16, 4))
                return list_fail(s, SA_SHAPE);
        } else {
            if (done || cmd == 2 || type != c->family || flags != (cmd == 4 ? 2u : 0u) ||
                len < 20 || p[16] != cmd || p[17] != 1 || scalar(p + 18, 2) || objects++ ||
                !fanout_attrs(s, p + 20, len - 20))
                return list_fail(s, SA_IDENTITY);
        }
        at += step;
    }
    if (cmd == 4 && !s->fanout.handle && objects)
        return list_fail(s, SA_IDENTITY);
    unsigned expected = cmd == 2 ? 0 : cmd == 4 && !s->fanout.handle ? 0 : 1;
    if ((cmd != 4 && ack != 1) || objects != expected || done != (cmd == 4))
        return complete ? list_fail(s, SA_SHAPE) : -1;
    s->list_done = done;
    s->readback_observed = 1;
    return 0;
}

/* Empty whole-table baseline only. No filtering of unparsed foreign objects. */
int nt_empty_list_parse(struct nt_state *s, const struct nt_context *c, int complete)
{
    const unsigned char *b = s->raw.bytes;
    size_t n = s->raw.length, at = 0;
    unsigned ack = 0, done = 0;
    if (n > sizeof(s->raw.bytes) || s->raw.rc || s->raw.truncated || s->raw.sender ||
        s->raw.context.socket != c->socket || s->raw.context.epoch != c->epoch ||
        s->raw.context.netns != c->netns)
        return list_fail(s, SA_IDENTITY);
    while (at < n) {
        if (n - at < 16)
            return list_fail(s, SA_SHAPE);
        const unsigned char *p = b + at;
        size_t len = scalar(p, 4), step = (len + 3) & ~(size_t)3;
        unsigned type = (unsigned)scalar(p + 4, 2), flags = (unsigned)scalar(p + 6, 2);
        if (len < 16 || step > n - at || scalar(p + 8, 4) != c->seq || scalar(p + 12, 4) != c->port)
            return list_fail(s, SA_SHAPE);
        for (size_t j = len; j < step; j++)
            if (p[j])
                return list_fail(s, SA_SHAPE);
        if (type == 2) {
            if (len < 20)
                return list_fail(s, SA_SHAPE);
            if (scalar(p + 16, 4))
                return list_fail(s, SA_CALLBACK);
            if (ack++ || len != 36 || (flags != 0 && flags != 256) ||
                memcmp(p + 20, s->request, 16))
                return list_fail(s, SA_SHAPE);
        } else if (type == 3) {
            if (done++ || flags != 2 || len != 20 || scalar(p + 16, 4))
                return list_fail(s, SA_SHAPE);
        } else
            return list_fail(s, SA_IDENTITY);
        at += step;
    }
    if (done != 1)
        return complete ? list_fail(s, SA_SHAPE) : -1;
    s->list_done = s->readback_observed = 1;
    return 0;
}
