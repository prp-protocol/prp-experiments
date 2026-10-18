#include "payload_geometry.h"
#include "wire_adapter.h"
#include <errno.h>
#include <string.h>
static void u16(unsigned char *b, uint16_t v)
{
    memcpy(b, &v, 2);
}
static void u32(unsigned char *b, uint32_t v)
{
    memcpy(b, &v, 4);
}
static int link_valid(const struct ew_link *p)
{
    return p && p->netns && p->epoch && p->ifindex && (p->direction == 1 || p->direction == 2);
}
int ew_request(const struct ew_tx *p, const unsigned char *rrl, size_t n, unsigned char *out,
               size_t cap)
{
    if (!p || p->family < 16 || !p->sequence || !p->port || !p->peer || !rrl || !out ||
        n != EG_INPUT)
        return -EINVAL;
    if (cap < EG_REQUEST)
        return -EMSGSIZE;
    memset(out, 0, EG_REQUEST);
    u32(out, EG_REQUEST);
    u16(out + 4, p->family);
    u16(out + 6, 5);
    u32(out + 8, p->sequence);
    u32(out + 12, p->port);
    out[16] = 19;
    out[17] = 1;
    u16(out + 20, 12);
    u16(out + 22, 23);
    memcpy(out + 24, &p->peer, 8);
    u16(out + 32, (EG_INPUT + 4));
    u16(out + 34, 32);
    memcpy(out + 36, rrl, n);
    return EG_REQUEST;
}
int ew_expected(const struct ew_link *p, const unsigned char *rrl, size_t n, unsigned char *out,
                size_t cap)
{
    if (!link_valid(p) || !rrl || !out || n != EG_OUTPUT)
        return -EINVAL;
    if (cap < EG_FRAME)
        return -EMSGSIZE;
    memcpy(out, p->destination, 6);
    memcpy(out + 6, p->source, 6);
    out[12] = 0x88;
    out[13] = 0xfb;
    memcpy(out + 14, rrl, n);
    return EG_FRAME;
}
static int envelope(const struct ew_link *expected, const struct ew_link *observed,
                    const unsigned char *frame, size_t n, int truncated, int lost, size_t exact)
{
    if (!link_valid(expected) || !link_valid(observed) || !frame)
        return -EINVAL;
    if (truncated || lost || n != exact)
        return -EMSGSIZE;
    if (expected->netns != observed->netns || expected->epoch != observed->epoch ||
        expected->ifindex != observed->ifindex || expected->direction != observed->direction ||
        memcmp(expected->source, observed->source, 6) ||
        memcmp(expected->destination, observed->destination, 6) ||
        memcmp(frame, expected->destination, 6) || memcmp(frame + 6, expected->source, 6) ||
        frame[12] != 0x88 || frame[13] != 0xfb)
        return -EPROTO;
    return 0;
}

int ew_envelope(const struct ew_link *e, const struct ew_link *o, const unsigned char *f, size_t n,
                int t, int l)
{
    return envelope(e, o, f, n, t, l, EG_FRAME);
}
int ew_ingress_envelope(const struct ew_link *e, const struct ew_link *o, const unsigned char *f,
                        size_t n, int t, int l)
{
    return envelope(e, o, f, n, t, l, EG_INGRESS);
}
