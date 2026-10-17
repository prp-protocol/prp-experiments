#ifndef EXP002_PAYLOAD_LEDGER_H
#define EXP002_PAYLOAD_LEDGER_H
#include "socket_backend.h"
#include "../signer-adapter/reservations.h"
#define EL_SUCCESS_BYTES (EP_COUNT * 2500u)
#define EL_COMPACT_BYTES (EP_COUNT * 228u + 7212u)
#define EL_INGRESS_BYTES (EP_COUNT * 1210u)
#define EL_ARENA_BYTES (EL_SUCCESS_BYTES + 4940u)
struct el_export_result {
 int attempted,busy,primary,secondary,closed,verified,reusable;
 uint64_t last,dev,ino;size_t written,read;
};
struct el_ledger {
 uint64_t id,generation,clock_frontier;struct el_export_result exported;
 struct rp_pool *pool;unsigned ticket,index,stage,records;int primary,finished;
 unsigned char *arena;size_t capacity,length,wire_length;
 unsigned char *frames;size_t frame_stride;
 struct rp_amount held[5];
 const struct ep_packet *requests;struct ew_link link;
 struct ep_result result;
 unsigned char (*ingress)[1146],(*ingress_headers)[64];
 struct ew_link ingress_link;struct rp_amount ingress_held[2];
 unsigned ingress_count;int clock_regressed,validation_error,validation_done;
 uint64_t validation_before,validation_after;unsigned char ingress_error[1984];

};
int el_init(struct el_ledger *,struct rp_pool *,unsigned char *,size_t,const struct ep_packet *,const struct ew_link *);
/* Compact mode borrows immutable requests and exclusively owns received slots
 * through export. No external writer/reuse is permitted during this lifetime. */
int el_compact_init(struct el_ledger *,struct rp_pool *,unsigned char *,size_t,const struct ep_packet *,const struct ew_link *,unsigned char [EP_COUNT][EP_SLOT]);
int el_compact_stride_init(struct el_ledger *,struct rp_pool *,unsigned char *,size_t,
 const struct ep_packet *,const struct ew_link *,unsigned char *,size_t);
int el_bind_ingress(struct el_ledger *,unsigned char [EP_COUNT][1146],unsigned char [EP_COUNT][64],const struct ew_link *);
int el_ingress_record(const struct el_ledger *,unsigned,unsigned char [64],const unsigned char **,size_t *);
int el_record(const struct el_ledger *,size_t,unsigned char [64],const unsigned char **,size_t *,size_t *);
int el_reserve(void *,unsigned,size_t,size_t,size_t);
int el_commit(void *,const struct es_raw *);
int el_finish_ingress(struct el_ledger *,const struct ep_result *,uint64_t (*)(void *),void *);
int el_finish(struct el_ledger *,const struct ep_result *);
int el_decode(const unsigned char *,size_t,struct es_raw *,size_t *);
/* One post-finish attempt; caller owns immutable ledger/arena and private path. */
int el_export(struct el_ledger *,const char *,uint64_t,uint64_t (*)(void *),void *);
#endif
