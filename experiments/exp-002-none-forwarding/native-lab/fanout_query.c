#include "fanout_query.h"
int fq_open(struct fq_query *q,struct so_owner *o,uint16_t family,uint32_t *seq,struct sf_flow *egress,const struct nt_fanout *mapping){
 struct rp_handle active;
 if(!q||!o||!o->ready||o->closed||o->primary||!seq||*seq>UINT32_MAX-5||!mapping||sf_active_ticket(egress,&active))return SA_REFUSED;
 struct rp_pool *p=active.pool;struct ff_plan plan={0};plan.egress=egress;plan.mapping=*mapping;plan.budget=(struct nt_budget){1024,sizeof(struct nt_ledger),4,1000000};
 uint64_t end=rp_get(active)->transaction.bound.deadline;
 for(unsigned i=0;i<5;i++){
  plan.context[i]=(struct nt_context){o->expected.ino,o->plan.epoch,o->plan.netns_ino,i==4?p->close_end:end,++*seq,o->plan.binding,family};
  if(!rn_init(&q->port[i],p,&q->flow.ticket[i],o->fd,o->expected.dev,o->expected.ino,&plan.context[i],&plan.budget))return SA_REFUSED;
  q->io[i]=rn_stream(&q->port[i]);
 }
 return ff_open(&q->flow,&plan,q->io);
}
int fq_close(struct fq_query *q,struct nq_store *store){
 if(!q||!store||store->files.pool!=q->flow.parent.pool)return SA_REFUSED;
 ff_close(&q->flow,q->io);struct rp_store io=rf_operations(&store->files);
 return ff_archive(&q->flow,store->files.end,&io);
}

int fq_checkpoint(struct fq_query *q,struct nq_store *store){
 if(!q||!store||store->files.pool!=q->flow.parent.pool)return SA_REFUSED;
 struct rp_store io=rf_operations(&store->files);return ff_checkpoint(&q->flow,&io);
}
