#ifndef EXP_ABSENCE_QUERY_H
#define EXP_ABSENCE_QUERY_H
#include "carrier_query.h"
struct aq_result {
    unsigned started, observed, archived;
    int primary, secondary;
    struct nt_context context[2];
    struct rp_handle ticket[2];
    uint64_t before, after;
};
/* Strict empty whole-table baseline. The caller supplies exclusive writers;
 * sampling is not a guarantee that state cannot change after the observation. */
int aq_run(struct aq_result *, struct rp_pool *, struct so_owner *, uint16_t, uint32_t *,
           struct nq_store *);
#endif
