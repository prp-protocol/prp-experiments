#include "payload_geometry.h"
#include "member_prepare.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
static int fail(struct em_preparation *p,int error){
 if(!p->primary)p->primary=error;
 /* Prevent an ignored late preparation error from reaching em_payload_run. */
 if(p->storage&&!p->storage->backend.primary)p->storage->backend.primary=p->primary;
 return p->primary;
}
int em_prepare_begin(struct em_preparation *p,struct em_storage *w,const struct ew_link *link,const struct ew_tx *id){
 if(!p)return -EINVAL;
 if(p->started)return fail(p,-EALREADY);
 p->started=1;
 if(!w||!link||!id||!w->pool.initialized||w->pool.primary||w->backend.initialized||
    w->backend.primary||w->ledger.id||w->ledger.finished||!link->netns||!link->epoch||
    !link->ifindex||link->ifindex>INT_MAX||(link->direction!=1&&link->direction!=2)||
    id->family<16||!id->sequence||id->sequence>UINT32_MAX-EP_COUNT||!id->port||!id->peer)
  return fail(p,-EINVAL);
 for(unsigned i=0;i<EP_COUNT;i++)if(w->lengths[i])return fail(p,-EBUSY);
 p->storage=w;p->link=*link;p->identity=*id;return 0;
}
int em_prepare_record(struct em_preparation *p,unsigned index,const unsigned char *input,size_t ni,const unsigned char *output,size_t no){
 if(!p)return -EINVAL;
 if(p->primary)return p->primary;
 if(!p->started||!p->storage||p->finished||index!=p->next||index>=EP_COUNT||
    !input||!output||ni!=EG_INPUT||no!=EG_OUTPUT)return fail(p,-EINVAL);
 struct em_storage *w=p->storage;
 if(w->backend.initialized||w->ledger.id)return fail(p,-EBUSY);
 struct ew_tx tx=p->identity;tx.sequence+=index;
 unsigned char independent[1104];
 int rc=ew_request(&tx,input,ni,w->requests[index],1168);
 if(rc!=EG_REQUEST)return fail(p,rc<0?rc:-EPROTO);
 rc=ew_expected(&p->link,output,no,independent,sizeof(independent));
 if(rc!=EG_FRAME)return fail(p,rc<0?rc:-EPROTO);
 /* Full independent byte equality before timing, not a hash substitution.
  * The split oracle later borrows this suffix from immutable requests. */
 if(memcmp(independent+24,w->requests[index]+88,EG_SUFFIX))return fail(p,-EBADMSG);
 if(index&&memcmp(w->expected[0],independent,24))return fail(p,-EBADMSG);
 memcpy(w->expected[0],independent,24);
 w->inputs[index]=(struct ep_packet){w->requests[index]+36,EG_INPUT};
 w->tx[index]=(struct ep_packet){w->requests[index],EG_REQUEST};
 w->expected_packets[index]=(struct ep_packet){w->expected[0],24};
 p->next++;return 0;
}
int em_prepare_finish(struct em_preparation *p){
 if(!p)return -EINVAL;
 if(p->primary)return p->primary;
 if(!p->started||!p->storage||p->finished||p->next!=EP_COUNT)return fail(p,-EINVAL);
 p->finished=1;return 0;
}
