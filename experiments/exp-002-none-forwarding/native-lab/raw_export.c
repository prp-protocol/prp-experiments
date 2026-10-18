#include "raw_export.h"
#include <errno.h>
#include <string.h>
#include <stdint.h>
static voidpf allocate(voidpf opaque, uInt items, uInt size)
{
    struct rx_export *r = opaque;
    size_t alignment = _Alignof(max_align_t);
    if (size && items > SIZE_MAX / size)
        return NULL;
    size_t n = (size_t)items * size;
    size_t pad = (alignment - ((uintptr_t)(r->work + r->used) % alignment)) % alignment;
    size_t at = r->used + pad;
    if (at > r->capacity || n > r->capacity - at)
        return NULL;
    r->used = at + n;
    return r->work + at;
}
static void release(voidpf opaque, voidpf address)
{
    (void)opaque;
    (void)address;
}
int rx_begin(struct rx_export *r, void *work, size_t capacity)
{
    memset(r, 0, sizeof(*r));
    if (!work || capacity < 327680 + RX_PACKED_MAX)
        return r->error = -EINVAL;
    r->work = work;
    r->capacity = 327680;
    r->bytes = r->work + 327680;
    r->z.zalloc = allocate;
    r->z.zfree = release;
    r->z.opaque = r;
    int e = deflateInit(&r->z, 6);
    if (e != Z_OK)
        return r->error = -ENOMEM;
    r->active = 1;
    r->z.next_out = r->bytes;
    r->z.avail_out = RX_PACKED_MAX;
    return 0;
}
static int part(struct rx_export *r, const unsigned char *b, size_t n)
{
    if (!n)
        return 0;
    r->z.next_in = (Bytef *)b;
    r->z.avail_in = (uInt)n;
    int e = deflate(&r->z, Z_NO_FLUSH);
    if (e != Z_OK || r->z.avail_in || !r->z.avail_out)
        return r->error = -ENOSPC;
    return 0;
}
int rx_add(struct rx_export *r, const unsigned char h[64], const unsigned char *b, size_t n)
{
    if (r->error)
        return r->error;
    if (!r->active || !h || !b || n > RX_BODY_MAX || r->count >= RX_RECORD_MAX)
        return r->error = -EINVAL;
    unsigned char length[2] = {(unsigned char)(n >> 8), (unsigned char)n};
    int e = part(r, length, 2);
    if (!e)
        e = part(r, h, 64);
    if (!e)
        e = part(r, b, n);
    if (!e)
        r->count++;
    return e;
}
int rx_end(struct rx_export *r, size_t *n)
{
    *n = 0;
    if (!r->active)
        return r->error ? r->error : -EINVAL;
    if (!r->error && deflate(&r->z, Z_FINISH) != Z_STREAM_END)
        r->error = -ENOSPC;
    size_t used = RX_PACKED_MAX - r->z.avail_out;
    int e = deflateEnd(&r->z);
    r->active = 0;
    if (e != Z_OK && !r->error)
        r->error = -EIO;
    if (!r->error)
        *n = used;
    return r->error;
}
