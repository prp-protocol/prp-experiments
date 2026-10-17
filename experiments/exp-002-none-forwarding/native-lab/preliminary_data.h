#ifndef EXP_PRELIMINARY_DATA_H
#define EXP_PRELIMINARY_DATA_H
#include "route_query.h"
#include "session_query.h"
struct rp_pool *pd_pool(void);
int pd_control(int);
int pd_handshake(void);
void pd_body64(const unsigned char *,size_t);
int pd_run(struct sf_flow *,struct sf_flow *,struct so_owner *,struct so_owner *,uint16_t,uint32_t *,const struct pair_plan *);
#endif
