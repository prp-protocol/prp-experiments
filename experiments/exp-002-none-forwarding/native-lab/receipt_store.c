#include "receipt_store.h"
int nq_open(struct nq_store *s,struct rp_pool *p,const char *path,uint64_t end,uint64_t (*clock)(void *),void *arg){
 if(!s||s->files.initialized)return 0;
 return rf_open(&s->files,p,path,end,clock,arg);
}
int nq_archive_before(struct nq_store *s,struct rp_handle h,uint64_t end){
 if(!s||s->files.pool!=h.pool||s->files.dirfd<0||!end||end>s->files.end)return 0;
 struct rp_ticket *t=rp_get(h);
 if(!t||!t->ran||t->busy||t->persist_attempted){s->failed++;return 0;}
 /* Encoding already emitted on the bounded console remains the SAME receipt.
  * Never encode again or mutate a completed receipt to manufacture success. */
 if(!t->length&&!rp_encode(h,t->bound_client)){s->failed++;return 0;}
 struct rp_store io=rf_operations(&s->files);
 if(!rp_persist(h,end,&io)){s->failed++;return 0;}
 s->archived++;return 1;
}
int nq_close(struct nq_store *s){return s&&rf_close(&s->files);}

int nq_archive(struct nq_store *s,struct rp_handle h){return s&&nq_archive_before(s,h,s->files.end);}
