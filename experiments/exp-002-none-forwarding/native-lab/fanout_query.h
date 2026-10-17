#ifndef EXP_FANOUT_QUERY_H
#define EXP_FANOUT_QUERY_H
#include "session_query.h"
#include "fanout_flow.h"
struct fq_query {struct ff_flow flow;struct rn_port port[5];struct nt_stream io[5];};
int fq_open(struct fq_query *,struct so_owner *,uint16_t,uint32_t *,struct sf_flow *,const struct nt_fanout *);
int fq_checkpoint(struct fq_query *,struct nq_store *);
int fq_close(struct fq_query *,struct nq_store *);
#endif
