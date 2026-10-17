/* Experiment-owned serializers for the designated external interface; no IO. */
#ifndef EXP002_WIRE_ADAPTER_H
#define EXP002_WIRE_ADAPTER_H
#include <stddef.h>
#include <stdint.h>
struct ew_tx {uint16_t family;uint32_t sequence,port;uint64_t peer;};
struct ew_link {uint64_t netns,epoch;uint32_t ifindex;unsigned direction;unsigned char source[6],destination[6];};
int ew_request(const struct ew_tx *,const unsigned char *,size_t,unsigned char *,size_t);
int ew_expected(const struct ew_link *,const unsigned char *,size_t,unsigned char *,size_t);
int ew_envelope(const struct ew_link *,const struct ew_link *,const unsigned char *,size_t,int truncated,int lost);
int ew_ingress_envelope(const struct ew_link *,const struct ew_link *,const unsigned char *,size_t,int,int);
#endif
