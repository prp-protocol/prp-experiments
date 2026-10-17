#ifndef EXP002_MEMBER_PREPARE_H
#define EXP002_MEMBER_PREPARE_H
#include "member_storage.h"
#include "socket_identity.h"
/* Caller owns fresh/exclusively reusable storage and independently generated
 * catalogue operands. No setup/session/capture provenance is supplied here. */
struct em_preparation {
 struct em_storage *storage;struct ew_link link;struct ew_tx identity;
 unsigned started,next,finished,bind_attempted,bound,session_attempted;int primary;
 struct nt_context session_context;struct nt_readback session_expected;
 uint64_t session_id,session_generation,session_handle,session_observed,session_admission,session_not_before,session_until;
};
int em_prepare_begin(struct em_preparation *,struct em_storage *,const struct ew_link *,const struct ew_tx *);
int em_prepare_record(struct em_preparation *,unsigned,const unsigned char *,size_t,const unsigned char *,size_t);
int em_prepare_finish(struct em_preparation *);
/* Only local endpoint sockets. The owner separately establishes namespace,
 * authenticated session/profile, clock admission and future FD continuity. */
int em_bind(struct em_preparation *,const struct si_set *,const struct si_expect [5],
            const struct ew_link *,const struct es_ports *);
#endif
