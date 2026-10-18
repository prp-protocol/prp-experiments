#ifndef EXP_RESERVATIONS_H
#define EXP_RESERVATIONS_H
#include "transaction.h"
#define RP_TICKETS 16
#define RP_RECEIPT 8192
struct rp_limit {
    uint64_t count, body, header;
};
extern const struct rp_limit rp_limits[13];
struct rp_amount {
    uint64_t slots, body, encoded;
};
struct rp_capture_context {
    uint64_t endpoint, netns, epoch, session_generation, transfer;
    unsigned ifindex, direction;
    unsigned char source[6], destination[6];
};
struct rp_capture_plan {
    struct rp_capture_context context;
    uint64_t not_before, deadline;
    const void *observation_identity;
    const unsigned char *expected;
    size_t length;
};
struct rp_capture_raw {
    struct rp_capture_context context;
    uint64_t before, after;
    size_t length;
    int rc, truncated, lost;
    unsigned char bytes[1984];
};
struct rp_capture_ops {
    uint64_t (*clock)(void *);
    void (*read_once)(void *, size_t, struct rp_capture_raw *);
    void *arg;
};
struct rp_socket_fact {
    unsigned present;
    int fd, primary, secondary, send_errno, possible;
    long send_result;
    uint64_t dev, ino, send_before, send_after, receive_after, calls;
};
struct rp_ticket {
    struct rp_socket_fact socket_fact;
    unsigned raw_row, capture_attempted, capture_accepted, capture_consumed;
    const void *observation_identity;
    struct rp_capture_context capture_expected;
    struct rp_capture_raw capture_raw;
    size_t capture_expected_length;
    uint64_t capture_control, capture_generation, capture_not_before, capture_end, capture_digest;

    size_t tx_reserved;
    unsigned cancel_not_run;
    uint64_t cancel_pre_id, cancel_pre_generation, cancel_commit_id, cancel_commit_generation;
    unsigned transport_attempted, activation_attempted, activation_readback_attempted,
        session_delete_attempted;
    unsigned expectation_attempted, expectation_delete_attempted;
    unsigned cancel_attempted, prepared, commit_attempted, active, final, ran, unsettled,
        sign_attempted, persist_attempted, persisted, busy;
    uint64_t generation, id;
    int primary, secondary;
    uint64_t revision, sealed_revision;
    struct rp_amount held[3];
    unsigned commands, facts;
    const struct sc_client *bound_client;
    struct nt_state transaction;
    struct nt_ledger ledger;
    struct nt_budget budget;
    unsigned char receipt[RP_RECEIPT];
    size_t length;
    uint64_t persist_before, persist_after;
    size_t written, read_length;
    int write_rc, writer_settled;
};
struct rp_pool {
    uint64_t captures[2];
    uint32_t transfer_high_water;
    uint64_t normal_end, close_end;
    int initialized;
    struct rp_amount used[13];
    uint64_t commands[2], facts[2], setup[2], next_id;
    int primary;
    struct rp_ticket tickets[RP_TICKETS];
};
struct rp_handle {
    struct rp_pool *pool;
    unsigned slot;
    uint64_t generation, id;
};
/* init requires new zeroed caller-owned storage. Used includes live reservations.
 * Final partition never borrows normal capacity; 40 terminal records protected. */
int rp_init(struct rp_pool *, uint64_t normal_end, uint64_t close_end);
int rp_reserve_tx(struct rp_pool *, unsigned final, const struct nt_budget *, size_t tx_bytes,
                  struct rp_handle *);
int rp_reserve(struct rp_pool *, unsigned final, const struct nt_budget *, struct rp_handle *);
/* Local socket setup/close: metadata and terminal only, no invented datagrams.
 * Both tickets are reserved atomically within existing command/fact partitions. */
int rp_reserve_local_pair(struct rp_pool *, unsigned final_close, struct rp_handle[2]);
int rp_reserve_capture(struct rp_pool *, unsigned final, struct rp_handle *);
int rp_capture(struct rp_handle, struct rp_handle, const struct rp_capture_plan *,
               const struct rp_capture_ops *);
struct rp_ticket *rp_get(struct rp_handle);
int rp_control(struct rp_handle, struct rp_handle, struct rp_handle, struct rp_handle,
               const struct nt_context *, const struct nt_control *, struct sb_backend *,
               const struct nt_stream *);
/* Exact observed PENDING -> SET acknowledgement is not a fresh ACTIVE GET.
 * DEL consumes an owned observed incarnation, not a PREPARE handle. */
int rp_session_active_readback(struct rp_handle, struct rp_handle, const struct nt_context *,
                               const struct nt_readback *, const struct nt_stream *);
int rp_session_change(struct rp_handle, struct rp_handle, const struct nt_context *, unsigned,
                      const struct nt_readback *, const struct nt_stream *);
int rp_selected_readback(struct rp_handle, struct rp_handle, const struct nt_context *,
                         const struct nt_readback *, const struct nt_stream *);
int rp_list(struct rp_handle, const struct nt_context *, const struct nt_selection *,
            const struct nt_stream *);
/* Independently supplied remote identity is mandatory; never learned as trust
 * from a wire response. Source is accepted CTX_GET for SET, attempted SET for DEL. */
int rp_expectation(struct rp_handle, struct rp_handle, const struct nt_context *,
                   const struct nt_readback *, const struct nt_stream *);
int rp_readback(struct rp_handle, const struct nt_context *, const struct nt_readback *,
                const struct nt_stream *);
int rp_member_context(struct rp_handle, struct rp_handle, const struct nt_context *, unsigned,
                      unsigned, const struct nt_stream *);
int rp_carrier(struct rp_handle, const struct nt_context *, const struct nt_carrier *,
               const struct nt_stream *);
int rp_prepare(struct rp_handle, const struct nt_context *, const struct nt_prepare *,
               const struct nt_stream *);
int rp_commit(struct rp_handle, const struct nt_context *, uint64_t, const struct sc_client *,
              const struct nt_stream *);
int rp_sign(struct rp_handle, const struct nt_context *, const struct nt_prepare *,
            struct sc_client *, const struct sa_policy *, const unsigned char[32], uint32_t,
            const struct sa_ops *);
int rp_commit_prepared(struct rp_handle, struct rp_handle, const struct nt_context *,
                       const struct nt_stream *);
int rp_sign_m2(struct rp_handle, const struct nt_context *, const struct nt_prepare *,
               struct sc_client *, const struct sa_policy *, const struct nt_remote_m1 *,
               const unsigned char *, size_t, struct sb_backend *, const struct sa_ops *);
/* Post-COMMIT DIRECT: record an unused cancellation reservation, no IO or
 * cleanup claim. Only stable persistence can retire its live slot. */
int rp_cancel_not_run(struct rp_handle, struct rp_handle, struct rp_handle,
                      const struct nt_context *);
int rp_cancel_adjacent(struct rp_handle, struct rp_handle, const struct nt_context *,
                       const struct nt_stream *);
int rp_cancel(struct rp_handle, struct rp_handle, const struct nt_context *,
              const struct nt_stream *);
int rp_encode(struct rp_handle, const struct sc_client *);
struct rp_decoded {
    uint64_t id, generation;
    unsigned records;
    size_t command, fact, terminal, raw;
    int primary, possible;
};
int rp_decode(const unsigned char *, size_t, struct rp_decoded *);
struct rp_write_result {
    int rc, settled;
    size_t written, read_length;
    unsigned char readback[RP_RECEIPT];
};
struct rp_store {
    uint64_t (*clock)(void *);
    void (*write_once)(void *, uint64_t, const unsigned char *, size_t, struct rp_write_result *);
    void *arg;
};
/* end is independently supplied absolute persistence closure bound, never a
 * duration. No retry on partial/late/unsettled outcome; reservations survive. */
int rp_persist(struct rp_handle, uint64_t end, const struct rp_store *);
int rp_fanout(struct rp_handle, const struct nt_context *, const struct nt_fanout *,
              const struct nt_stream *);
int rp_empty_list(struct rp_handle, const struct nt_context *, unsigned, const struct nt_stream *);
#endif
