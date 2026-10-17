#ifndef EXP_TRANSACTION_H
#define EXP_TRANSACTION_H
#include "local_client.h"
#include "provider_backend.h"
/* One bounded injected exchange; no socket or native entry point. */
struct nt_context { uint64_t socket,epoch,netns,deadline; uint32_t seq,port; uint16_t family; };
struct nt_reply { unsigned char bytes[4096]; size_t length; struct nt_context context; int rc,truncated; uint32_t sender; };
struct nt_ops { uint64_t (*clock)(void *); void (*exchange)(void *,const unsigned char *,size_t,struct nt_reply *); void *arg; };
struct nt_prepare { uint64_t peer; unsigned char scope,kind; uint16_t alias; unsigned char public_key[32]; };
/* Independently selected exact readback expectations; no handle discovery from
 * PREPARE/COMMIT or ACK. Only identity1/session0002 in this client slice. */
struct nt_readback {unsigned command;uint64_t handle,peer,max_bytes;uint32_t generation;uint16_t alias;unsigned char scope,direction,strong_id[32];unsigned char state;};
/* Caller-supplied restrictive population and absolute freshness reservation.
 * No claim that a dump is atomic or a selected session was created by COMMIT. */
#define NT_LIST_MAX 16
struct nt_selection {struct nt_readback match;unsigned population;uint64_t not_before,valid_until;};
struct nt_control {unsigned command;uint64_t peer;uint32_t transfer;size_t capacity;};
/* Finite core Ethernet lifecycle. Member observations are not peer contexts. */
struct nt_carrier {unsigned command,ifindex,population;};
struct nt_member_context {uint32_t handle;uint64_t generation;unsigned char direction;};
struct nt_member_observation {uint32_t handle,ifindex;uint64_t generation;unsigned char flags;};
/* Exact level1 administrative mapping; handle0 LIST means empty baseline. */
struct nt_fanout {unsigned command;uint64_t handle,peer,max_bytes,lease_ms;uint32_t generation,max_members,flags;};
struct nt_state {
 unsigned empty_list_command;
 struct nt_fanout fanout;
 struct nt_member_context member_context;uint64_t peer_context;
 struct nt_member_observation members[4];unsigned char member_consumed[4];
 struct nt_carrier carrier;unsigned carrier_records,carrier_count_seen;
 uint64_t commit_source_id,commit_source_generation;
 uint64_t control_pre_id,control_pre_generation,control_commit_id,control_commit_generation,control_parent_id,control_parent_generation,control_hash_before,control_hash_after;
 struct nt_control control;
 unsigned selection_consumed;uint64_t selection_id,selection_generation,selection_before,selection_after,selection_end;
 struct nt_selection selection;unsigned population,matches,list_done;uint64_t selected_handle;
 struct nt_readback expected_readback;unsigned readback_observed;
 struct nt_context bound;struct nt_prepare setup;int sign_consumed;
 int started,busy,primary,secondary,possible,accepted,time_refused;
 uint64_t before,after,last,handle,expires_at; uint32_t expires;
 unsigned char request[264],sent[264],payload[172];size_t request_length,sent_length,payload_length;
 struct nt_reply raw;
 unsigned char remote_m1[130];size_t remote_length;int remote_verify_rc;uint64_t remote_before,remote_after,remote_hash_after;
};
/* A PREPARE handle is NOT a session handle or cleanup receipt. */
int nt_prepare(struct nt_state *,const struct nt_context *,const struct nt_prepare *,const struct nt_ops *);
int nt_commit(struct nt_state *,const struct nt_context *,uint64_t,const struct sc_client *,const struct nt_ops *);
int nt_sign_prepared(struct nt_state *,const struct nt_context *,const struct nt_prepare *,
                     struct sc_client *,const struct sa_policy *,const unsigned char [32],uint32_t,const struct sa_ops *);
int nt_m1_binding(struct sb_backend *,const struct sc_client *,unsigned char [32]);
/* One whole kind7 record only; insufficient approved frame capacity refuses.
 * Caller owns unique transfer ID and authenticated adjacent/route prerequisites.
 * Output is serialization, never an AOP send or remote acceptance. */
int nt_direct(struct sb_backend *,const struct sc_client *,uint32_t,unsigned char *,size_t,size_t *);

/* Required sub-reservation, not an allocation from the 13-pool controller.
 * Both raw and metadata bytes must already be reserved by the caller. */
#define NT_RECORDS 8
struct nt_budget { size_t body_bytes,metadata_bytes; unsigned calls; uint64_t ticks_per_ms; };
struct nt_record { size_t offset,reported,retained; uint64_t before,after; struct nt_context context; int rc,truncated,called; uint32_t sender; };
struct nt_ledger { struct nt_record records[NT_RECORDS]; unsigned calls; size_t retained,reported; int overflow,send_called,send_rc,started; uint64_t send_after; };
struct nt_stream { uint64_t (*clock)(void *); int (*send)(void *,const unsigned char *,size_t); void (*receive)(void *,size_t,struct nt_reply *); void *arg; };
int nt_prepare_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,const struct nt_prepare *,const struct nt_stream *);
int nt_commit_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,uint64_t,const struct sc_client *,const struct nt_stream *);
int nt_readback_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,const struct nt_readback *,const struct nt_stream *);
int nt_control_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,const struct nt_prepare *,const struct sc_client *,const struct nt_control *,struct sb_backend *,const struct nt_stream *);
int nt_list_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,const struct nt_selection *,const struct nt_stream *);
int nt_list_parse(struct nt_state *,const struct nt_context *,int);
int nt_carrier_parse(struct nt_state *,const struct nt_context *,int);
int nt_member_context_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,const struct nt_member_context *,const struct nt_stream *);
int nt_carrier_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,const struct nt_carrier *,const struct nt_stream *);
int nt_selection_valid(const struct nt_selection *);
/* state0 retains historical ACTIVE expectation; explicit1 is authenticated
 * PENDING observation only. Neither a zero size nor PENDING authorizes data. */
unsigned nt_session_state(const struct nt_readback *);
int nt_readback_valid(const struct nt_readback *);
int nt_session_change_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,unsigned,const struct nt_readback *,const struct nt_stream *);
int nt_readback_attrs(struct nt_state *,const unsigned char *,size_t);
int nt_cancel_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,uint64_t,const struct nt_stream *);
int nt_cancel_peer_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,uint64_t,const struct nt_stream *);
struct nt_remote_m1 { struct nt_context context;uint64_t peer,deadline,not_before;uint32_t generation;unsigned char public_key[32],expected_wire[130]; };
int nt_sign_m2(struct nt_state *,const struct nt_context *,const struct nt_prepare *,struct sc_client *,const struct sa_policy *,const struct nt_remote_m1 *,const unsigned char *,size_t,struct sb_backend *,const struct sa_ops *);
int nt_fanout_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,const struct nt_fanout *,const struct nt_stream *);
int nt_fanout_parse(struct nt_state *,const struct nt_context *,int);
int nt_empty_list_stream(struct nt_state *,struct nt_ledger *,const struct nt_budget *,const struct nt_context *,unsigned,const struct nt_stream *);
int nt_empty_list_parse(struct nt_state *,const struct nt_context *,int);
#endif
