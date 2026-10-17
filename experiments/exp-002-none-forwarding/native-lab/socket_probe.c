#define _GNU_SOURCE
/* Consumer-only native socket/family qualification. No PRP session mutation. */
#include "socket_owner.h"
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <net/if.h>
#include <unistd.h>
#include <poll.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#ifdef SUITE_QUERY
#include "suite_query.h"
#ifdef CARRIER_QUERY
#include "carrier_query.h"
#ifdef M1_QUERY
#include "m1_query.h"
#include "pair_plan.h"
#include "control_capture.h"
#endif
#endif
#ifdef PRELIMINARY_DATA
#include "preliminary_data.h"
#define suite_pool (*pd_pool())
#else
static struct rp_pool suite_pool;
#endif
#endif
static uint64_t now(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return UINT64_MAX;return (uint64_t)t.tv_sec*1000000000+t.tv_nsec;}
#ifdef CARRIER_QUERY
static uint64_t store_clock(void *unused){(void)unused;return now();}
#endif
static void hex(const void *p,size_t n){const unsigned char *s=p;putchar('"');for(size_t i=0;i<n;i++)printf("%02x",s[i]);putchar('"');}
#ifdef M1_QUERY
static int hex_digit(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return -1;}
static int mac_read(FILE *f,unsigned char out[6]){
 for(unsigned i=0;i<6;i++){int a=hex_digit(fgetc(f)),b=hex_digit(fgetc(f));if(a<0||b<0)return 0;out[i]=(unsigned char)(16*a+b);if(fgetc(f)!=(i==5?'\n':':'))return 0;}
 return fgetc(f)==EOF&&!ferror(f)?6:0;
}
#endif
static uint16_t u16(const void *p){uint16_t x;memcpy(&x,p,2);return x;}
static uint32_t u32(const void *p){uint32_t x;memcpy(&x,p,4);return x;}
static int parse(const unsigned char *b,size_t n,const char *name,uint32_t seq,uint32_t port){
 if(n<20||u32(b)!=n||u16(b+4)!=GENL_ID_CTRL||u16(b+6)||u32(b+8)!=seq||u32(b+12)!=port||b[16]!=CTRL_CMD_NEWFAMILY||b[17]!=2||u16(b+18))return -EPROTO;
 unsigned seen=0;int family=-1;size_t at=20;
 while(at<n){
  if(n-at<4)return -EPROTO;
  unsigned len=u16(b+at),type=u16(b+at+2)&NLA_TYPE_MASK;size_t aligned=(len+3u)&~3u;
  if(len<4||aligned>n-at||type>31||(seen&(1u<<type)))return -EPROTO;
  seen|=1u<<type;
  const unsigned char *v=b+at+4;unsigned z=len-4;
  if(type==CTRL_ATTR_FAMILY_ID){if(z!=2||u16(v)<16)return -EPROTO;family=u16(v);}
  if(type==CTRL_ATTR_FAMILY_NAME&&(z!=strlen(name)+1||memcmp(v,name,z)))return -EPROTO;
  if(type==CTRL_ATTR_VERSION&&(z!=4||u32(v)!=1))return -EPROTO;
  at+=aligned;
 }
 return (seen&14)==14?family:-EPROTO;
}
static int resolve(struct so_owner *o,const char *name,uint32_t seq,uint64_t end){
 unsigned char tx[64]={0},rx[4096];unsigned n=(unsigned)strlen(name)+1,attr=4+n,total=20+((attr+3)&~3u);
 struct nlmsghdr h={.nlmsg_len=total,.nlmsg_type=GENL_ID_CTRL,.nlmsg_flags=NLM_F_REQUEST,.nlmsg_seq=seq,.nlmsg_pid=o->plan.binding};
 memcpy(tx,&h,16);tx[16]=CTRL_CMD_GETFAMILY;tx[17]=2;uint16_t a=attr,k=CTRL_ATTR_FAMILY_NAME;memcpy(tx+20,&a,2);memcpy(tx+22,&k,2);memcpy(tx+24,name,n);
 struct sockaddr_nl dst={.nl_family=AF_NETLINK};int result=-ETIMEDOUT;ssize_t sent=-1,received=-1;int flags=0,sender=-1,send_error=0;uint64_t before=now(),after=before;
 if(before<end){sent=sendto(o->fd,tx,total,0,(struct sockaddr *)&dst,sizeof(dst));send_error=errno;after=now();}
 if(sent==(ssize_t)total&&after>=before&&after<end){
  struct pollfd p={.fd=o->fd,.events=POLLIN};uint64_t remaining=end-after;int ms=(int)(remaining/1000000);if(ms>2000)ms=2000;
  int ready=poll(&p,1,ms);int poll_error=errno;uint64_t poll_end=now();
  if(ready>0&&poll_end>=after&&poll_end<end){
   struct sockaddr_nl src={0};struct iovec i={rx,sizeof(rx)};struct msghdr m={.msg_name=&src,.msg_namelen=sizeof(src),.msg_iov=&i,.msg_iovlen=1};
   received=recvmsg(o->fd,&m,MSG_DONTWAIT|MSG_TRUNC);int e=errno;after=now();flags=m.msg_flags;sender=(int)src.nl_pid;
   if(received<0)result=-e;
   else if(after<poll_end||after>=end)result=-ETIMEDOUT;
   else if(received>4096||(flags&(MSG_TRUNC|MSG_CTRUNC))||m.msg_namelen!=sizeof(src)||src.nl_family!=AF_NETLINK||src.nl_pid||src.nl_groups)result=-EPROTO;
   else result=parse(rx,(size_t)received,name,seq,o->plan.binding);
  }else if(ready<0)result=-poll_error;
 }else if(sent<0&&before<end)result=-send_error;
 printf("{\"slot\":%u,\"name\":\"%s\",\"seq\":%u,\"port\":%u,\"before_ns\":%llu,\"after_ns\":%llu,\"send_result\":%ld,\"receive_result\":%ld,\"sender\":%d,\"flags\":%d,\"family\":%d,\"tx\":",o->plan.slot,name,seq,o->plan.binding,(unsigned long long)before,(unsigned long long)after,(long)sent,(long)received,sender,flags,result);hex(tx,total);printf(",\"rx\":");hex(rx,received>0?(size_t)(received>4096?4096:received):0);putchar('}');return result;
}
#ifndef PARSER_TEST
int main(int argc,char **argv){
 if(argc!=2||(strcmp(argv[1],"endpoint")&&strcmp(argv[1],"dut")))return 2;

#ifdef M1_QUERY
 struct mq_identity identity={0},second_identity={0};
 if(fread(identity.seed,1,32,stdin)!=32||fread(identity.public_key,1,32,stdin)!=32)return 2;
 struct pair_plan pair={0};unsigned char pair_bytes[104];size_t pair_len=fread(pair_bytes,1,sizeof(pair_bytes),stdin);
 if((pair_len&&pair_len!=60&&pair_len!=104)||ferror(stdin))return 2;
 if(pair_len){
  if(!(pair_len==60?pair_decode(&pair,pair_bytes,!strcmp(argv[1],"endpoint")?2:1):pair_decode_route(&pair,pair_bytes,pair_len,!strcmp(argv[1],"endpoint")?2:1)))return 2;
  if(pair.links==2&&pair.role==2&&(fread(second_identity.seed,1,32,stdin)!=32||fread(second_identity.public_key,1,32,stdin)!=32))return 2;
  unsigned char actual[6];FILE *mac=fopen("/sys/class/net/eth0/address","r");if(!mac)return 2;
  int count=mac_read(mac,actual);int closed=fclose(mac);
  if(count!=6||closed||memcmp(actual,pair.local,6))return 2;
  if(pair.links==2){mac=fopen("/sys/class/net/eth1/address","r");if(!mac)return 2;count=mac_read(mac,actual);closed=fclose(mac);if(count!=6||closed||memcmp(actual,pair.local_second,6))return 2;}

 }
 if(fgetc(stdin)!=EOF||ferror(stdin))return 2;
#endif
#ifdef PRELIMINARY_DATA
 const char *control=getenv("EXP002_CONTROL_FD");int control_number=0;
 if(!control||!*control||strlen(control)>5)return 2;
 for(const char *c=control;*c;c++){if(*c<'0'||*c>'9')return 2;control_number=control_number*10+(*c-'0');}
 if(control_number>65535||pd_control(control_number))return 2;
#endif
 int endpoint=!strcmp(argv[1],"endpoint"),primary=0;struct stat ns={0};struct so_owner owners[5]={0};struct si_expect expected[5]={0};struct si_set inspect={0};
 uint64_t start=now(),end=start+20000000000ull,close_end=start+30000000000ull;
#ifdef CARRIER_QUERY
 /* Keep normal work and cleanup inside the caller's existing20s command cap. */
 end=start+15000000000ull;close_end=start+18000000000ull;
#ifdef PRELIMINARY_DATA
 end=start+35000000000ull;close_end=start+38000000000ull;
#endif
#endif
 if(end>360000000000ull)end=360000000000ull;
 if(close_end>410000000000ull)close_end=410000000000ull;
#ifdef CARRIER_QUERY
 struct nq_store receipts={0};struct nq_store *store=NULL;
#endif
 if(stat("/proc/self/ns/net",&ns))primary=-errno;
 for(unsigned i=0;i<5&&!primary;i++){
  if(endpoint?i==3:i!=3)continue;
  unsigned bind=i<2?if_nametoindex(i?"eth1":"eth0"):(unsigned)getpid()*8u+i+1;
  struct so_plan p={i,bind,ns.st_dev,ns.st_ino,1,end,close_end};
  primary=so_open(&owners[i],&p);expected[i]=owners[i].expected;
 }
 if(!primary)primary=si_inspect_domain(&inspect,expected,endpoint?SI_ENDPOINT_VM:SI_DUT_VM);
 printf("{\"schema\":\"EXP002-NATIVE-SOCKET-1\",\"role\":\"%s\",\"netns_dev\":%llu,\"netns_ino\":%llu,\"effective_sum\":%llu,\"mask\":%u,\"resolutions\":[",argv[1],(unsigned long long)ns.st_dev,(unsigned long long)ns.st_ino,(unsigned long long)inspect.effective_sum,inspect.mask);
 unsigned seq=0;
#ifdef SUITE_QUERY
 uint16_t session_families[5]={0};
#ifdef CARRIER_QUERY
 uint16_t core_families[5]={0};
#endif
 if(!rp_init(&suite_pool,end,close_end))primary=-EINVAL;
#ifdef CARRIER_QUERY
 /* Fresh private guest directory, never overwrite a previous run. */
 if(!primary&&(mkdir("/run/exp002-receipts",0700)||!nq_open(&receipts,&suite_pool,"/run/exp002-receipts",close_end,store_clock,NULL)))primary=-EIO;
 if(!primary)store=&receipts;
#endif
#endif
 for(unsigned i=2;i<5&&!primary;i++){
  if(endpoint?i==3:i!=3)continue;
  const char *names[]={"prp","prp_session"};
  for(unsigned j=0;j<2&&!primary;j++){if(seq)putchar(',');int f=resolve(&owners[i],names[j],++seq,end);if(f<0)primary=f;
#ifdef SUITE_QUERY
   else if(j==1)session_families[i]=(uint16_t)f;
#ifdef CARRIER_QUERY
   else core_families[i]=(uint16_t)f;
#endif
#endif
  }
 }
 printf("]");
#ifdef SUITE_QUERY
 printf(",\"suite_queries\":[");unsigned queries=0;
 for(unsigned i=2;i<5&&!primary;i++){
  if(endpoint?i==3:i!=3)continue;
  struct rp_handle handle={0};int rc=sq_run(&suite_pool,&owners[i],session_families[i],++seq,&handle);
  struct rp_ticket *t=rp_get(handle);
  if(queries++)putchar(',');
  printf("{\"slot\":%u,\"rc\":%d,\"ticket\":%llu,\"accepted\":%s,\"receipt\":",i,rc,(unsigned long long)handle.id,t&&t->transaction.accepted?"true":"false");
  hex(t?t->receipt:NULL,t?t->length:0);putchar('}');if(rc)primary=rc;
#ifdef CARRIER_QUERY
  if(t&&store&&!nq_archive(store,handle)&&!primary)primary=-EIO;
#endif
 }
 printf("],\"suite_pools\":[");
 for(unsigned i=0;i<13;i++){if(i)putchar(',');printf("{\"slots\":%llu,\"body\":%llu,\"encoded\":%llu}",(unsigned long long)suite_pool.used[i].slots,(unsigned long long)suite_pool.used[i].body,(unsigned long long)suite_pool.used[i].encoded);}
 printf("]");
#endif
 #ifdef CARRIER_QUERY
 if(!primary){unsigned slot=endpoint?2:3;printf(",\"carrier\":");primary=cq_run(&suite_pool,&owners[slot],core_families[slot],&seq,if_nametoindex("eth0"),if_nametoindex("eth1"),store
#ifdef M1_QUERY
 ,session_families[slot],&identity,endpoint?&second_identity:NULL,endpoint?owners:NULL,pair_len?&pair:NULL
#endif
 );

#ifdef M1_QUERY

#endif
 printf(",\"carrier_pools\":[");for(unsigned i=0;i<13;i++){if(i)putchar(',');printf("{\"slots\":%llu,\"body\":%llu,\"encoded\":%llu}",(unsigned long long)suite_pool.used[i].slots,(unsigned long long)suite_pool.used[i].body,(unsigned long long)suite_pool.used[i].encoded);}printf("]");}
#endif
#ifdef CARRIER_QUERY
 int file_close=receipts.files.dirfd>=0?nq_close(&receipts):0;
 printf(",\"receipt_store\":{\"archived\":%u,\"failed\":%u,\"inventory\":%u,\"closed\":%s}",receipts.archived,receipts.failed,receipts.files.count,file_close?"true":"false");
 printf(",\"receipt_inventory\":[");
 for(unsigned j=0;j<receipts.files.count;j++){struct rf_entry *e=&receipts.files.entries[j];if(j)putchar(',');printf("{\"id\":%llu,\"generation\":%llu,\"bytes\":%zu,\"read\":%zu,\"primary\":%d,\"secondary\":%d,\"settled\":%d,\"inventory_settled\":%d}",(unsigned long long)e->id,(unsigned long long)e->generation,e->written,e->read,e->primary,e->secondary,e->settled,e->inventory_settled);}
 printf("]");
 if(!file_close&&!primary)primary=-EIO;
#endif
 printf(",\"sockets\":[");unsigned count=0;int cleanup=0;
 for(unsigned i=0;i<5;i++){
  if(!owners[i].created)continue;
  int rb=-1,sb=-1;socklen_t z=sizeof(int);getsockopt(owners[i].fd,SOL_SOCKET,SO_RCVBUF,&rb,&z);z=sizeof(int);getsockopt(owners[i].fd,SOL_SOCKET,SO_SNDBUF,&sb,&z);
  int rc=so_close(&owners[i]);if((!owners[i].closed||owners[i].close_errno||owners[i].time_failed)&&!cleanup)cleanup=rc?rc:-EIO;
  if(count++)putchar(',');
  printf("{\"slot\":%u,\"dev\":%llu,\"ino\":%llu,\"binding\":%u,\"closed\":%s,\"close_return\":%d,\"close_rc\":%d,\"rcvbuf\":%d,\"sndbuf\":%d}",i,(unsigned long long)expected[i].dev,(unsigned long long)expected[i].ino,owners[i].plan.binding,owners[i].closed?"true":"false",rc,owners[i].close_rc,rb,sb);
 }
 const char *success="PASS_SOCKET_FAMILY_ONLY";
#ifdef M1_QUERY
 if(pair_len)success=pair.links==2?"PASS_ROUTE_SESSIONS_ONLY":"PASS_PAIRED_SESSION_ONLY";
#endif
 printf("],\"primary\":%d,\"cleanup_error\":%d,\"state\":\"%s\"}\n",primary,cleanup,primary||cleanup?"INCOMPLETE":success);return primary||cleanup?1:0;
}
#endif
