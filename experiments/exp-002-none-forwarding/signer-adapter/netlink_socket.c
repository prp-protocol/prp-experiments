#define _GNU_SOURCE
#include "netlink_socket.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
static int fail(struct ns_port *p,int e){if(!p->primary)p->primary=e;else if(!p->secondary)p->secondary=e;return p->primary;}
static uint64_t clock_port(void *v){
 struct ns_port *p=v;struct timespec t;uint64_t n=0;
 if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0||t.tv_nsec<0||t.tv_nsec>=1000000000L||(uint64_t)t.tv_sec>(UINT64_MAX-(uint64_t)t.tv_nsec)/1000000000ULL){fail(p,EPROTO);return UINT64_MAX;}
 n=(uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
 if(n<p->last||n>=p->operation_end)fail(p,ETIMEDOUT);
 p->last=n;
 if(p->admission&&!p->admission(p->admission_arg))fail(p,ESTALE);
 if(n>=p->operation_end)fail(p,ETIMEDOUT);
 return p->primary?UINT64_MAX:n;
}
static int identity(struct ns_port *p){
 struct stat st;struct sockaddr_nl a={0};socklen_t z=sizeof(a);int flags;
 if(fstat(p->fd,&st)||!S_ISSOCK(st.st_mode)||(uint64_t)st.st_dev!=p->dev||(uint64_t)st.st_ino!=p->ino)return fail(p,ESTALE);
 flags=fcntl(p->fd,F_GETFL);if(flags<0||!(flags&O_NONBLOCK))return fail(p,ESTALE);
 int opts[]={SO_DOMAIN,SO_TYPE,SO_PROTOCOL};int values[]={AF_NETLINK,SOCK_RAW,NETLINK_GENERIC};
 for(unsigned i=0;i<3;i++){int x=0;socklen_t l=sizeof(x);if(getsockopt(p->fd,SOL_SOCKET,opts[i],&x,&l)||l!=sizeof(x)||x!=values[i])return fail(p,ESTALE);}
 if(getsockname(p->fd,(struct sockaddr *)&a,&z)||z!=sizeof(a)||a.nl_family!=AF_NETLINK||a.nl_pid!=p->context.port||a.nl_groups)return fail(p,ESTALE);
 return p->primary;
}
static int enter(struct ns_port *p){if(!p||!p->initialized)return EINVAL;if(p->busy)return fail(p,EDEADLK);if(p->primary)return p->primary;p->busy=1;return 0;}
static int send_port(void *v,const unsigned char *b,size_t n){
 struct ns_port *p=v;int e=enter(p);if(e)return -e;
 if(p->sent||!b||n<20||n>sizeof(p->request)){fail(p,EINVAL);goto out;}
 p->sent=1;memcpy(p->request,b,n);p->request_length=n;
 uint32_t len,seq,port;uint16_t family;memcpy(&len,b,4);memcpy(&family,b+4,2);memcpy(&seq,b+8,4);memcpy(&port,b+12,4);
 if(len!=n||family!=p->context.family||seq!=p->context.seq||port!=p->context.port){fail(p,EINVAL);goto out;}
 if(identity(p))goto out;
 p->send_before=clock_port(p);if(p->primary)goto out;
 struct sockaddr_nl kernel={.nl_family=AF_NETLINK};p->possible=1;
 p->send_result=sendto(p->fd,b,n,MSG_DONTWAIT|MSG_NOSIGNAL,(struct sockaddr *)&kernel,sizeof(kernel));
 p->send_errno=p->send_result<0?errno:0;
 if(p->send_result!=(long)n)fail(p,p->send_errno?p->send_errno:EIO);
 clock_port(p);p->send_after=p->last;
 out:p->busy=0;return p->primary?-p->primary:0;
}
static void receive_port(void *v,size_t cap,struct nt_reply *r){
 struct ns_port *p=v;if(!r)return;memset(r,0,sizeof(*r));
 int e=enter(p);if(e){r->rc=-e;return;}r->context=p->context;
 if(!p->sent||!p->possible||p->calls>=p->max_calls||!cap||cap>sizeof(r->bytes)||cap>p->remaining){fail(p,ENOBUFS);goto out;}
 p->calls++;
 if(identity(p))goto out;
 uint64_t t=clock_port(p);if(p->primary)goto out;
 uint64_t left=p->operation_end-t,ms=left/1000000ULL+(left%1000000ULL!=0);
 struct pollfd f={p->fd,POLLIN,0};int rc=poll(&f,1,ms>INT_MAX?INT_MAX:(int)ms);
 if(rc!=1||f.revents!=POLLIN)fail(p,rc<0?errno:ETIMEDOUT);
 clock_port(p);if(p->primary||identity(p))goto out;
 clock_port(p);if(p->primary)goto out;
 struct sockaddr_nl a={0};struct iovec i={r->bytes,cap};struct msghdr m={0};m.msg_name=&a;m.msg_namelen=sizeof(a);m.msg_iov=&i;m.msg_iovlen=1;
 ssize_t got=recvmsg(p->fd,&m,MSG_DONTWAIT|MSG_TRUNC);int saved=errno;
 /* Custody precedes clock/error propagation, including contradictory returns. */
 r->sender=a.nl_pid;r->truncated=!!(m.msg_flags&(MSG_TRUNC|MSG_CTRUNC));
 if(got>=0){r->length=(size_t)got;size_t kept=r->length>cap?cap:r->length;p->remaining-=kept;}
 else fail(p,saved);
 if(got==0||got>(ssize_t)cap||r->truncated)fail(p,EMSGSIZE);
 if(m.msg_namelen!=sizeof(a)||a.nl_family!=AF_NETLINK||a.nl_pid||a.nl_groups)fail(p,EPROTO);
 clock_port(p);p->receive_after=p->last;
 out:r->rc=p->primary?-p->primary:0;p->busy=0;
}
int ns_init(struct ns_port *p,int fd,uint64_t dev,uint64_t ino,const struct nt_context *c,const struct nt_budget *b){
 if(!p)return EINVAL;
 if(p->initialized)return fail(p,EALREADY);
 p->initialized=1;
 if(!c||!b||fd<0||!ino||!c->socket||!c->epoch||!c->netns||!c->seq||!c->port||c->family<16||!c->deadline||!b->calls||b->calls>NT_RECORDS||!b->body_bytes||b->body_bytes>4096||b->ticks_per_ms!=1000000||b->metadata_bytes<sizeof(struct nt_ledger))return fail(p,EINVAL);
 p->fd=fd;p->dev=dev;p->ino=ino;p->context=*c;p->operation_end=c->deadline;p->remaining=b->body_bytes;p->max_calls=b->calls;return 0;
}
struct nt_stream ns_stream(struct ns_port *p){return (struct nt_stream){clock_port,send_port,receive_port,p};}
