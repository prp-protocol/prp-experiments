#ifndef EXP_PAIR_PLAN_H
#define EXP_PAIR_PLAN_H
#include <stdint.h>
#include <stddef.h>
struct pair_plan {
    unsigned role, links;
    uint32_t generation;
    unsigned char local[6], remote[6], local_second[6], remote_second[6], public_key[32],
        public_key_second[32];
};
/* Exactly60 public bytes after the existing64 private-input bytes. */
int pair_decode(struct pair_plan *, const unsigned char[60], unsigned);
/* Version2 binds both links explicitly; never infer a second MAC. */
int pair_decode_route(struct pair_plan *, const unsigned char *, size_t, unsigned);
#endif
