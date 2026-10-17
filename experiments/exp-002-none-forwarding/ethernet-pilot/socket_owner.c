#define _GNU_SOURCE
#include "socket_owner.h"
#ifdef EXP002_PRP_CAPTURE
#include "packet_filter.h"
#endif
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <limits.h>

static int fail(struct so_owner *o,int e){o->revision++;if(!o->primary)o->primary=e;else if(!o->secondary&&e!=o->primary)o->secondary=e;o->ready=0;return o->primary;}
static int tick(struct so_owner *o,uint64_t end,int cleanup){
 uint64_t revision=o->revision;struct timespec t;
 if(clock_gettime(CLOCK_MONOTONIC,&t)){o->time_failed=1;return fail(o,-errno);}
 if(t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000L||(uint64_t)t.tv_sec>(UINT64_MAX-999999999)/1000000000){o->time_failed=1;return fail(o,-ETIMEDOUT);}
 uint64_t n=(uint64_t)t.tv_sec*1000000000+(uint64_t)t.tv_nsec;o->raw_clock=n;
 if(o->time_failed||n<o->last){o->time_failed=1;return fail(o,-ETIMEDOUT);}
 o->last=n;if(n>=end)return fail(o,-ETIMEDOUT);
 if(o->revision!=revision||(!cleanup&&o->primary))return o->primary;
 return 0;
}
static int namespace_matches(struct so_owner *o){
 struct stat s;
 if(stat("/proc/self/ns/net",&s))return fail(o,-errno);
 if(!S_ISREG(s.st_mode)||(uint64_t)s.st_dev!=o->plan.netns_dev||(uint64_t)s.st_ino!=o->plan.netns_ino)return fail(o,-ESTALE);
 return 0;
}
static int identity(struct so_owner *o){
 struct stat s;
 if(fstat(o->fd,&s))return fail(o,-errno);
 if(!S_ISSOCK(s.st_mode)||!s.st_ino)return fail(o,-ESTALE);
 if(o->identified&&((uint64_t)s.st_dev!=o->expected.dev||(uint64_t)s.st_ino!=o->expected.ino))return fail(o,-ESTALE);
 if(!o->identified){o->expected=(struct si_expect){o->fd,s.st_dev,s.st_ino,o->plan.binding};o->identified=1;}
 return 0;
}
int so_open(struct so_owner *o,const struct so_plan *p){
 if(!o)return -EINVAL;
 if(o->attempted)return fail(o,-EALREADY);
 o->attempted=1;o->fd=-1;
 if(!p||p->slot>4||!p->binding||(p->slot<2&&p->binding>INT_MAX)||!p->netns_ino||!p->epoch||!p->normal_end||p->close_end<=p->normal_end)return fail(o,-EINVAL);
 o->plan=*p;p=&o->plan;
 if(tick(o,p->normal_end,0)||namespace_matches(o)||tick(o,p->normal_end,0))return o->primary;
 /* Protocol zero leaves packet reception disabled until explicit bind. The
  * returned FD is owned immediately, even when a post-call check fails. */
 int packet=p->slot<2;
 o->fd=socket(packet?AF_PACKET:AF_NETLINK,SOCK_RAW|SOCK_NONBLOCK|SOCK_CLOEXEC,packet?0:NETLINK_GENERIC);
 int e=errno;if(o->fd>=0)o->created=1;else fail(o,-e);
 if(tick(o,p->normal_end,0)||o->primary)return o->primary;
 if(identity(o)||tick(o,p->normal_end,0))return o->primary;
 for(unsigned i=0;i<2;i++){
  int value=packet?262144:87381,name=i?SO_SNDBUF:SO_RCVBUF;
  if(tick(o,p->normal_end,0))return o->primary;
  int rc=setsockopt(o->fd,SOL_SOCKET,name,&value,sizeof(value));e=errno;
  if(!rc)o->configured|=1u<<i;else fail(o,-e);
  if(tick(o,p->normal_end,0)||o->primary)return o->primary;
  socklen_t size=sizeof(value);value=0;
  if(getsockopt(o->fd,SOL_SOCKET,name,&value,&size))fail(o,-errno);
  else if(size!=sizeof(value)||value!=(packet?524288:174762))fail(o,-ENOBUFS);
  if(tick(o,p->normal_end,0)||o->primary)return o->primary;
 }
#ifdef EXP002_PRP_CAPTURE
 if(packet){
  int (*steps[])(int)={pf_attach,pf_lock,pf_verify};
  for(unsigned i=0;i<3;i++){
   if(tick(o,p->normal_end,0))return o->primary;
   int r=steps[i](o->fd);if(r)fail(o,r);
   if(tick(o,p->normal_end,0)||o->primary)return o->primary;
  }
 }
#endif
 if(namespace_matches(o)||tick(o,p->normal_end,0)||identity(o)||tick(o,p->normal_end,0))return o->primary;
 int rc;
 if(packet){struct sockaddr_ll a={.sll_family=AF_PACKET,.sll_protocol=htons(ETH_P_ALL),.sll_ifindex=(int)p->binding};rc=bind(o->fd,(struct sockaddr *)&a,sizeof(a));}
 else{struct sockaddr_nl a={.nl_family=AF_NETLINK,.nl_pid=p->binding};rc=bind(o->fd,(struct sockaddr *)&a,sizeof(a));}
 e=errno;if(!rc)o->bound=1;else fail(o,-e);
 if(tick(o,p->normal_end,0)||o->primary)return o->primary;
 /* Reuse the established inspector later for the complete domain. This local
  * readback verifies the exact binding immediately, not native provenance. */
 union {struct sockaddr_ll packet;struct sockaddr_nl netlink;} address={0};socklen_t n=sizeof(address);
 if(getsockname(o->fd,(struct sockaddr *)&address,&n))fail(o,-errno);
 else if(packet?(n!=offsetof(struct sockaddr_ll,sll_addr)+ETH_ALEN||address.packet.sll_halen!=ETH_ALEN||address.packet.sll_family!=AF_PACKET||address.packet.sll_protocol!=htons(ETH_P_ALL)||address.packet.sll_ifindex!=(int)p->binding):(n!=sizeof(address.netlink)||address.netlink.nl_family!=AF_NETLINK||address.netlink.nl_pid!=p->binding||address.netlink.nl_groups))fail(o,-EPROTO);
 if(tick(o,p->normal_end,0)||o->primary||namespace_matches(o)||tick(o,p->normal_end,0)||identity(o)||tick(o,p->normal_end,0))return o->primary;
 o->ready=1;return 0;
}
int so_close(struct so_owner *o){
 if(!o||!o->attempted||!o->created)return -EINVAL;
 if(o->close_started)return fail(o,-EALREADY);
 o->close_started=1;
 /* Old primary does not prevent still-timely local cleanup. A failed identity
  * lookup cannot authorize closing an FD possibly replaced outside ownership. */
 if(tick(o,o->plan.close_end,1)||identity(o)||tick(o,o->plan.close_end,1))return o->primary;
 o->close_attempted=1;o->ready=0;
 o->close_rc=close(o->fd);o->close_errno=o->close_rc?errno:0;
 if(!o->close_rc)o->closed=1;else{o->close_unknown=1;fail(o,-o->close_errno);}
 if(tick(o,o->plan.close_end,1))return o->primary;
 return o->primary;
}
