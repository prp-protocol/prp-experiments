#ifndef EXP002_RAW_EXPORT_H
#define EXP002_RAW_EXPORT_H
#include <stddef.h>
#include <zlib.h>
/* Post-timing lossless export only. Overflow never licenses discarded records. */
#define RX_PACKED_MAX 28672u
#define RX_RECORD_MAX 512u
#define RX_BODY_MAX 1168u
struct rx_export {
    z_stream z;
    unsigned char *bytes;
    unsigned char *work;
    size_t capacity;
    size_t used;
    unsigned count;
    int active, error;
};
int rx_begin(struct rx_export *r, void *work, size_t capacity);
int rx_add(struct rx_export *r, const unsigned char header[64], const unsigned char *body,
           size_t n);
int rx_end(struct rx_export *r, size_t *n);
#endif
