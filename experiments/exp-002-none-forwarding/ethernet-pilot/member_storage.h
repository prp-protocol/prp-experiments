#ifndef EXP002_MEMBER_STORAGE_H
#define EXP002_MEMBER_STORAGE_H
#include "payload_ledger.h"
/* Conditional HOST layout. This is named consumer data, not allocator/RSS or
 * target ABI proof. Inputs borrow the body within the request array. */
struct em_storage {
    unsigned char requests[EP_COUNT][1168];
#ifdef PILOT_FLOW
    /* One immutable Ethernet/RRL prefix; each record must prove equality. */
    unsigned char expected[1][24];
    unsigned char received[EP_COUNT][1104];
    /* Dedicated independent ingress custody, not aliases of transmitted bytes.
  * Allocated here; capture integration and context/settlement are still pending. */
    unsigned char ingress[EP_COUNT][1146];
    unsigned char ingress_metadata[EP_COUNT][64];
#else
    unsigned char expected[EP_COUNT][1104];
    unsigned char received[EP_COUNT][EP_SLOT];
#endif
    struct ep_packet inputs[EP_COUNT], tx[EP_COUNT], expected_packets[EP_COUNT];
    size_t lengths[EP_COUNT];
    struct rp_pool pool;
    struct el_ledger ledger;
    struct es_backend backend;
    unsigned char custody[EL_COMPACT_BYTES];
};
#define EM_SCRATCH_RESERVE 16384u
_Static_assert(sizeof(struct em_storage) + EM_SCRATCH_RESERVE <= 4311232u,
               "named memory must fit the approved conditional ceiling");
#endif
