/* Experiment-owned injected batch engine; no native transport or launch API. */
#ifndef EXP002_MEASURE_H
#define EXP002_MEASURE_H
#include <stddef.h>
#include <stdint.h>
#define EP_COUNT 1056u
#define EP_WARMUP 32u
#define EP_SLOT 1200u
struct ep_packet { const unsigned char *bytes; size_t len; };
struct ep_result {
    int primary, cleanup_error, clock_error, valid;
    unsigned attempted, received, index;
    const char *stage;
    uint64_t start_ns, observed_end_ns, end_ns, last_clock_ns;
};
struct ep_io {
    void *ctx;
    uint64_t (*now)(void *);
    int (*send)(void *, const unsigned char *, size_t, uint64_t);
    int (*receive)(void *, unsigned char *, size_t, uint64_t);
    /* 0: no extra data for the entire supplied interval; negative: error. */
    int (*quiet)(void *, uint64_t);
    int (*cleanup)(void *);
};
int ep_run(const struct ep_io *, const struct ep_packet *, const struct ep_packet *,
           unsigned char [EP_COUNT][EP_SLOT], size_t [EP_COUNT],
           uint64_t hard_end, uint64_t response_ns, uint64_t quiet_ns,
           struct ep_result *);
/* Opt-in exact two-slice oracle. Suffix borrows immutable input bytes; callers
 * establish equality with their independent oracle before admission. */
struct ep_split { size_t offset,length; };
int ep_run_split(const struct ep_io *,const struct ep_packet *,const struct ep_packet *,
                 unsigned char *,size_t,const struct ep_split *,size_t *,
                 uint64_t,uint64_t,uint64_t,struct ep_result *);
#endif
