#include "peer_path.h"
#include <errno.h>
static int refused(struct pp_path *p,int rc){if(p&&!p->primary)p->primary=rc;return p?p->primary:SA_REFUSED;}
static int usable(struct rp_ticket *t,unsigned command){
 return t&&t->ran&&!t->busy&&!t->primary&&!t->persist_attempted&&
        t->transaction.accepted&&t->transaction.request[16]==command;
}
static int retained(struct pp_path *p){
 for(unsigned k=0;k<2;k++){
  unsigned n=p->index*2+k;struct rp_ticket *t=rp_get(p->context[n]);
  if(!usable(t,76)||t->revision!=p->revision[n+1])return 0;
 }
 return 1;
}
int pp_select(struct pp_path *p,struct rp_handle list,const struct rp_handle h[4],unsigned ifindex){
 if(!p)return SA_REFUSED;
 if(p->initialized)return refused(p,SA_REPEAT);
 p->initialized=1;
 struct rp_ticket *l=rp_get(list);
 if(!h||!ifindex||!usable(l,75)||l->transaction.carrier_records!=2)return refused(p,SA_IDENTITY);
 unsigned found=0;
 for(unsigned i=0;i<2;i++)if(l->transaction.members[i].ifindex==ifindex){p->index=i;found++;}
 if(found!=1)return refused(p,SA_IDENTITY);
 p->list=list;p->ifindex=ifindex;p->revision[0]=l->revision;
 for(unsigned i=0;i<4;i++){
  struct rp_ticket *t=rp_get(h[i]);const struct nt_member_observation *m=&l->transaction.members[i/2];
  if(h[i].pool!=list.pool||!usable(t,76)||!t->transaction.peer_context||
     t->transaction.member_context.handle!=m->handle||
     t->transaction.member_context.generation!=m->generation||
     t->transaction.member_context.direction!=1+i%2||
     l->transaction.member_consumed[i/2]!=3)return refused(p,SA_IDENTITY);
  const struct nt_context *a=&t->transaction.bound,*b=&l->transaction.bound;
  if(a->socket!=b->socket||a->netns!=b->netns||a->epoch!=b->epoch||a->family!=b->family||a->port!=b->port||a->seq<=b->seq||a->deadline>b->deadline)return refused(p,SA_IDENTITY);
  for(unsigned j=0;j<i;j++)if(h[i].id==h[j].id)return refused(p,SA_IDENTITY);
  p->context[i]=h[i];p->revision[i+1]=t->revision;
 }
 p->tx=h[p->index*2];p->rx=h[p->index*2+1];return 0;
}
int pp_retire(struct pp_path *p,struct nq_store *store){
 if(!p||!p->initialized||p->primary||p->attempted)return refused(p,SA_REPEAT);
 p->attempted=1;
 if(!store||store->files.pool!=p->list.pool||!retained(p))return refused(p,SA_IDENTITY);
 struct rp_handle old[3]={p->context[(1-p->index)*2],p->context[(1-p->index)*2+1],p->list};
 for(unsigned i=0;i<3;i++){
  struct rp_ticket *t=rp_get(old[i]);unsigned slot=i<2?((1-p->index)*2+i+1):0;
  if(!usable(t,i==2?75:76)||t->revision!=p->revision[slot])return refused(p,SA_IDENTITY);
  if(!nq_archive(store,old[i]))return refused(p,-EIO);
  p->retired++;
  if(p->primary)return p->primary;
  if(!retained(p))return refused(p,SA_IDENTITY);
 }
 return 0;
}

int pp_retire_list(struct pp_path paths[2],struct nq_store *store){
 if(!paths)return SA_REFUSED;
 struct pp_path *a=&paths[0],*b=&paths[1];
 if(!a->initialized||!b->initialized||a->attempted||b->attempted||a->primary||b->primary)return refused(a,SA_REPEAT);
 a->attempted=b->attempted=1;
 if(!store||a->list.pool!=store->files.pool||b->list.pool!=a->list.pool||b->list.id!=a->list.id||b->list.generation!=a->list.generation||b->list.slot!=a->list.slot||a->index==b->index||!retained(a)||!retained(b))return refused(a,SA_IDENTITY);
 struct rp_ticket *list=rp_get(a->list);
 if(!usable(list,75)||list->revision!=a->revision[0]||list->revision!=b->revision[0])return refused(a,SA_IDENTITY);
 if(!nq_archive(store,a->list))return refused(a,-EIO);
 a->retired=b->retired=1;
 if(a->primary||b->primary||!retained(a)||!retained(b))return refused(a,SA_IDENTITY);
 return 0;
}
