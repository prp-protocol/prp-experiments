#define _POSIX_C_SOURCE 200809L
#include "socket_backend.h"
#include "payload_geometry.h"
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
static int fail(struct es_backend *b,int e){if(b->closed&&!b->cleanup_fault)b->cleanup_fault=e;if(!b->primary)b->primary=e;else if(!b->secondary)b->secondary=e;return b->primary;}
static uint32_t u32(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint16_t u16(const void *p){uint16_t v;memcpy(&v,p,2);return v;}
static uint64_t now(void *v){
 struct es_backend *b=v;struct timespec t;
 if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000L||(uint64_t)t.tv_sec>UINT64_MAX/1000000000ULL){b->time_failed=1;fail(b,-EIO);return 0;}
 uint64_t n=(uint64_t)t.tv_sec*1000000000ULL;
 if(n>UINT64_MAX-(uint64_t)t.tv_nsec){b->time_failed=1;fail(b,-EIO);return 0;}
 n+=(uint64_t)t.tv_nsec;if(n<b->last){b->time_failed=1;fail(b,-ETIMEDOUT);}else b->last=n;
 return n;
}
static int admit(struct es_backend *b,uint64_t end){
 uint64_t n=now(b);if(!end||end>b->hard_end||n>=end){b->time_failed=1;fail(b,-ETIMEDOUT);}
 return !b->primary&&!b->time_failed;
}
static int wait_one(struct es_backend *b,int fd,uint64_t end){
 if(!admit(b,end))return b->primary;
 uint64_t ms=(end-b->last)/1000000ULL+((end-b->last)%1000000ULL!=0);
 int timeout=ms>INT_MAX?INT_MAX:(int)ms;struct pollfd p={fd,POLLIN,0};
 int r=poll(&p,1,timeout);
 if(r<0)fail(b,-errno);
 if(!admit(b,end))return b->primary;
 if(r!=1||p.revents!=POLLIN)return fail(b,r==0?-ETIMEDOUT:-EIO);
 return 0;
}
static int custody(struct es_backend *b){int rc=b->ports.commit(b->ports.arg,&b->raw);if(rc)fail(b,rc<0?rc:-EIO);return b->primary;}
static int receive_raw(struct es_backend *b,int fd,unsigned lane,uint64_t end){
 if(wait_one(b,fd,end))return b->primary;
 union {struct sockaddr_nl nl;struct sockaddr_ll ll;} address;memset(&address,0,sizeof(address));
 memset(&b->raw,0,sizeof(b->raw));b->raw.lane=lane;b->raw.index=b->index;
 struct iovec iov={b->raw.bytes,lane==2?4096:1984};struct msghdr msg={0};
 msg.msg_name=&address;msg.msg_namelen=sizeof(address);msg.msg_iov=&iov;msg.msg_iovlen=1;
 if(!admit(b,end))return b->primary;
 b->raw.before=b->last;
 ssize_t n=recvmsg(fd,&msg,MSG_DONTWAIT|MSG_TRUNC);
 b->raw.flags=msg.msg_flags;b->raw.result=n;b->raw.address_length=msg.msg_namelen;memcpy(b->raw.address,&address,sizeof(address));
 if(n<0){b->raw.error=-errno;fail(b,b->raw.error);}
 else {b->raw.reported=(size_t)n;b->raw.kept=(size_t)n>iov.iov_len?iov.iov_len:(size_t)n;}
 /* Commit returned bytes even under a pre-existing callback/time error. */
 b->raw.after=now(b);custody(b);admit(b,end);
 if(b->primary)return b->primary;
 if(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)||b->raw.reported>iov.iov_len)return fail(b,-EMSGSIZE);
 if(lane==2){
  if(msg.msg_namelen!=sizeof(struct sockaddr_nl)||address.nl.nl_family!=AF_NETLINK||address.nl.nl_pid||address.nl.nl_groups)return fail(b,-EPROTO);
 }else{
  const struct ew_link *link=lane==4?&b->ingress_link:&b->link;
  if(msg.msg_namelen!=sizeof(struct sockaddr_ll)||address.ll.sll_family!=AF_PACKET||address.ll.sll_ifindex!=(int)link->ifindex||address.ll.sll_halen!=6||address.ll.sll_pkttype!=(link->direction==1?PACKET_HOST:PACKET_OUTGOING)||memcmp(address.ll.sll_addr,link->source,6))return fail(b,-EPROTO);
  if((lane==4?ew_ingress_envelope:ew_envelope)(link,link,b->raw.bytes,b->raw.kept,0,0))return fail(b,-EPROTO);
 }
 return 0;
}
static int send_one(void *v,const unsigned char *bytes,size_t n,uint64_t end){
 struct es_backend *b=v;
 if(!b->initialized||b->busy||b->pending||b->closed||b->index>=EP_COUNT)return fail(b,-EPROTO);
 if(b->primary)return b->primary;
 b->busy=1;
 if(bytes!=b->inputs[b->index].bytes||n!=b->inputs[b->index].len){fail(b,-EINVAL);goto done;}
 if(!admit(b,end))goto done;
 int r=b->ports.reserve(b->ports.arg,b->index,EG_REQUEST,4096,1984);if(r)fail(b,r<0?r:-EIO);
 if(!admit(b,end))goto done;
 const struct ep_packet *request=&b->requests[b->index];
 memset(&b->raw,0,sizeof(b->raw));b->raw.lane=1;b->raw.index=b->index;b->raw.reported=b->raw.kept=request->len;memcpy(b->raw.bytes,request->bytes,request->len);
 struct sockaddr_nl dest={0};dest.nl_family=AF_NETLINK;
 struct iovec iov={b->raw.bytes,request->len};struct msghdr msg={0};msg.msg_name=&dest;msg.msg_namelen=sizeof(dest);msg.msg_iov=&iov;msg.msg_iovlen=1;
 if(!admit(b,end))goto done;
 b->possible=1;b->raw.before=b->last;ssize_t sent=sendmsg(b->netlink_fd,&msg,MSG_DONTWAIT|MSG_NOSIGNAL);
 b->raw.result=sent;
 if(sent<0){b->raw.error=-errno;fail(b,b->raw.error);}else if((size_t)sent!=request->len)fail(b,-EIO);
 b->raw.after=now(b);custody(b);if(!admit(b,end))goto done;
 if(receive_raw(b,b->netlink_fd,2,end))goto done;
 const unsigned char *a=b->raw.bytes;
 if(b->raw.kept!=36||u32(a)!=36||u16(a+4)!=NLMSG_ERROR||(u16(a+6)!=0&&u16(a+6)!=256)||u32(a+8)!=u32(request->bytes+8)||u32(a+12)!=b->port||memcmp(a+20,request->bytes,16)){fail(b,-EPROTO);goto done;}
 int32_t error;memcpy(&error,a+16,4);if(error){fail(b,error<0?error:-EPROTO);goto done;}
 b->pending=1;
 done:b->busy=0;return b->primary?b->primary:(int)n;
}
static int receive_one(void *v,unsigned char *out,size_t cap,uint64_t end){
 struct es_backend *b=v;if(b->busy||!b->pending||b->closed||cap<EG_FRAME||!out)return fail(b,-EPROTO);
 if(b->primary)return b->primary;
 b->busy=1;
 int rc=b->ingress_enabled?receive_raw(b,b->ingress_fd,4,end):0;
 if(!rc)rc=receive_raw(b,b->packet_fd,3,end);
 if(!rc){memcpy(out,b->raw.bytes,EG_FRAME);b->pending=0;b->index++;}
 b->busy=0;return b->primary?b->primary:EG_FRAME;
}
static int quiet(void *v,uint64_t end){
 struct es_backend *b=v;if(b->busy||b->pending||b->closed||b->index!=EP_COUNT)return fail(b,-EPROTO);
 b->busy=1;
 if(!admit(b,end))goto done;
 uint64_t ms=(end-b->last)/1000000ULL+((end-b->last)%1000000ULL!=0);
 struct pollfd p[3]={{b->netlink_fd,POLLIN,0},{b->packet_fd,POLLIN,0},{b->ingress_fd,POLLIN,0}};
 int rc=poll(p,b->ingress_enabled?3:2,ms>INT_MAX?INT_MAX:(int)ms);
 if(rc<0)fail(b,-errno);else if(rc)fail(b,-EPROTO);
 uint64_t n=now(b);if(n<end||n>=b->hard_end||b->time_failed)fail(b,-ETIMEDOUT);
 done:b->busy=0;return b->primary;
}
static int cleanup(void *v){struct es_backend *b=v;if(b->closed)return fail(b,-EPROTO);b->closed=1;int rc=b->ports.cleanup(b->ports.arg);if(rc)fail(b,rc<0?rc:-EIO);return b->cleanup_fault;}
int es_init(struct es_backend *b,int nl,int packet,const struct ep_packet *inputs,const struct ep_packet *requests,const struct ew_link *link,const struct ew_tx *identity,uint64_t end,const struct es_ports *ops){
 if(!b||b->initialized||nl<0||packet<0||nl==packet||!inputs||!requests||!link||!link->netns||!link->epoch||!link->ifindex||(link->direction!=1&&link->direction!=2)||!identity||!identity->port||identity->family<16||!identity->peer||!identity->sequence||identity->sequence>UINT32_MAX-EP_COUNT||!end||!ops||!ops->reserve||!ops->commit||!ops->cleanup)return -EINVAL;
 uint32_t port=identity->port,seq=0;for(unsigned i=0;i<EP_COUNT;i++){
  if(!inputs[i].bytes||inputs[i].len!=EG_INPUT||!requests[i].bytes||requests[i].len!=EG_REQUEST)return -EINVAL;
  const unsigned char *r=requests[i].bytes;uint32_t current=u32(r+8);if(current!=identity->sequence+i||u16(r+4)!=identity->family||current<=seq||u32(r)!=EG_REQUEST||u32(r+12)!=port||r[16]!=19||r[17]!=1||memcmp(r+36,inputs[i].bytes,EG_INPUT))return -EINVAL;uint64_t peer;memcpy(&peer,r+24,8);if(peer!=identity->peer)return -EINVAL;struct ew_tx tx={u16(r+4),current,port,peer};unsigned char canonical[1168];if(ew_request(&tx,inputs[i].bytes,EG_INPUT,canonical,sizeof(canonical))!=EG_REQUEST||memcmp(canonical,r,EG_REQUEST))return -EINVAL;seq=current;
 }
 b->initialized=1;b->netlink_fd=nl;b->packet_fd=packet;b->inputs=inputs;b->requests=requests;b->link=*link;b->port=port;b->hard_end=end;b->ports=*ops;return 0;
}
struct ep_io es_operations(struct es_backend *b){return (struct ep_io){b,now,send_one,receive_one,quiet,cleanup};}

int es_bind_ingress(struct es_backend *b,int fd,const struct ew_link *link){
 if(!b)return -EINVAL;
 if(!b->initialized||b->ingress_enabled||b->busy||b->primary||b->closed||b->possible||b->last||b->index||fd<0||fd==b->netlink_fd||fd==b->packet_fd||!link||!link->netns||!link->epoch||!link->ifindex||link->ifindex>INT_MAX||(link->direction!=1&&link->direction!=2))return fail(b,-EINVAL);
 b->ingress_enabled=1;b->ingress_fd=fd;b->ingress_link=*link;return 0;
}
