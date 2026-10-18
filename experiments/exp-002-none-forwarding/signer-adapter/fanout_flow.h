#ifndef EXP_FANOUT_FLOW_H
#define EXP_FANOUT_FLOW_H
#include "session_flow.h"
struct ff_plan {
    struct sf_flow *egress;
    struct nt_fanout mapping;
    struct nt_context context[5];
    struct nt_budget budget;
};
struct ff_flow {
    struct ff_plan plan;
    struct rp_handle ticket[5], parent;
    uint64_t parent_revision, revision, handle;
    int primary, secondary;
    unsigned started, busy, finished, ready, delete_ack, archive_started, checkpoint_started,
        archived[5];
};
/* Exclusive namespace administration is a caller prerequisite, not inferred
 * from the empty LIST. This port does not execute module/namespace setup. */
int ff_open(struct ff_flow *, const struct ff_plan *, const struct nt_stream[5]);
/* Retain the exact GET and final DEL reservation; persist LIST/SET/LIST once.
 * A returned mapping ticket is a bounded observation, not continued liveness. */
int ff_mapping_ticket(const struct ff_flow *, struct rp_handle *);
int ff_checkpoint(struct ff_flow *, const struct rp_store *);
int ff_close(struct ff_flow *, const struct nt_stream[5]);
int ff_archive(struct ff_flow *, uint64_t, const struct rp_store *);
#endif
