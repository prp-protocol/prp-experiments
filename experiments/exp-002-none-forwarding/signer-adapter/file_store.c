#define _POSIX_C_SOURCE 200809L
#include "file_store.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
static void error(struct rf_store *s,struct rf_entry *e,int n){s->revision++;if(!e->primary)e->primary=n;else if(!e->secondary)e->secondary=n;if(!s->primary)s->primary=n;}
static int tick(struct rf_store *s,struct rf_entry *e){uint64_t t=s->clock(s->arg);struct rp_ticket *ticket=rp_get(s->current);int changed=s->revision!=s->seen||!ticket||ticket->revision!=s->ticket_revision;s->seen=s->revision;if(changed&&!e->primary)error(s,e,SA_REENTRY);int ok=t<s->end&&t>=s->last;s->last=t;if(!ok)error(s,e,SA_TIME);return ok&&!e->primary;}
static uint64_t clock_read(void *v){struct rf_store *s=v;return s&&s->initialized&&s->clock?s->clock(s->arg):UINT64_MAX;}
int rf_open(struct rf_store *s,struct rp_pool *p,const char *path,uint64_t end,uint64_t (*clock)(void *),void *arg){
 if(!s||s->initialized||!p||!p->initialized||!path||!clock||!end||end>p->close_end)return 0;
 s->initialized=1;s->dirfd=-1;s->pool=p;s->clock=clock;s->arg=arg;s->end=end;
 uint64_t before=clock(arg);s->last=before;if(before>=end)return 0;
 int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return 0;struct stat st;int ok=fstat(fd,&st)==0&&S_ISDIR(st.st_mode)&&st.st_uid==geteuid()&&(st.st_mode&0777)==0700;
 uint64_t after=clock(arg);s->last=after;if(!ok||after<before||after>=end){close(fd);return 0;}s->dirfd=fd;return 1;
}
static void write_once(void *v,uint64_t id,const unsigned char *data,size_t n,struct rp_write_result *out){
 struct rf_store *s=v;struct rp_decoded d;out->rc=-1;
 if(!s||!s->initialized||!s->pool||!s->clock||s->busy||s->dirfd<0||s->count>=256||!rp_decode(data,n,&d)||id!=d.id){if(s){s->revision++;if(!s->primary)s->primary=SA_REFUSED;}return;}
 unsigned slot;for(slot=0;slot<RP_TICKETS;slot++){struct rp_ticket *t=&s->pool->tickets[slot];if(t->active&&t->id==id&&t->generation==d.generation)break;}
 if(slot==RP_TICKETS)return;
 struct rp_ticket *ticket=&s->pool->tickets[slot];
 if(!ticket->busy||!ticket->persist_attempted||ticket->length!=n||memcmp(ticket->receipt,data,n))return;
 s->current=(struct rp_handle){s->pool,slot,d.generation,id};s->ticket_revision=ticket->revision;
 for(unsigned i=0;i<s->count;i++)if(s->entries[i].id==id){s->revision++;if(!s->primary)s->primary=SA_REPEAT;return;}
 /* Reserve inventory before any file creation, including refused/partial writes.
  * Fixed 4096-byte reservation is never refunded on uncertainty. */
 struct rp_amount *u=&s->pool->used[12];if(u->slots>=256||u->body>1048576-4096||u->encoded>1048576-4096){s->primary=SA_REFUSED;return;}
 u->slots++;u->body+=4096;u->encoded+=4096;s->busy=1;s->seen=s->revision;struct rf_entry *e=&s->entries[s->count++];e->id=id;e->generation=d.generation;
 snprintf(e->name,sizeof(e->name),"receipt-%llu-%llu.bin",(unsigned long long)id,(unsigned long long)d.generation);
 int fd=-1;struct stat before,after;
 if(!tick(s,e))goto done;
 fd=openat(s->dirfd,e->name,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(fd<0){error(s,e,errno);goto done;}
 if(fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_nlink!=1||before.st_size){error(s,e,SA_IDENTITY);goto done;}e->dev=before.st_dev;e->ino=before.st_ino;
 if(!tick(s,e))goto done;
 ssize_t w=write(fd,data,n);if(w>0)e->written=(size_t)w;if(w<0||(size_t)w!=n){error(s,e,w<0?errno:SA_CALLBACK);goto done;}
 if(!tick(s,e))goto done;
 if(fsync(fd)){error(s,e,errno);goto done;}
 if(!tick(s,e))goto done;
 ssize_t r=pread(fd,out->readback,n,0);if(r>0)e->read=(size_t)r;if(r<0||(size_t)r!=n){error(s,e,r<0?errno:SA_CALLBACK);goto done;}
 if(!tick(s,e))goto done;
 if(fstat(fd,&after)||after.st_dev!=before.st_dev||after.st_ino!=before.st_ino||after.st_size!=(off_t)n||after.st_nlink!=1||memcmp(data,out->readback,n)){error(s,e,SA_IDENTITY);goto done;}
 if(!tick(s,e))goto done;
 if(fsync(s->dirfd))error(s,e,errno);
 (void)tick(s,e);
 if(!e->primary){
  char name[80],record[256];snprintf(name,sizeof(name),"inventory-%llu-%llu.txt",(unsigned long long)id,(unsigned long long)d.generation);
  int len=snprintf(record,sizeof(record),"HOST_RECEIPT_POST_READBACK_PRE_RETURN\nid=%llu generation=%llu dev=%llu inode=%llu bytes=%zu\nNo crash durability or external writer proof.\n",(unsigned long long)id,(unsigned long long)d.generation,(unsigned long long)e->dev,(unsigned long long)e->ino,e->read);
  int inventory=-1;
  if(len<0||(size_t)len>=sizeof(record))error(s,e,SA_SHAPE);
  if(tick(s,e)){inventory=openat(s->dirfd,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(inventory<0)error(s,e,errno);}
  if(inventory>=0){e->inventory_opened=1;
   if(tick(s,e)){ssize_t z=write(inventory,record,(size_t)len);if(z!=len)error(s,e,z<0?errno:SA_CALLBACK);}
   if(tick(s,e)&&fsync(inventory))error(s,e,errno);
   if(close(inventory))error(s,e,errno);else e->inventory_settled=1;
   if(tick(s,e)&&fsync(s->dirfd))error(s,e,errno);
   (void)tick(s,e);
  }
 }
 done:
 /* Closing this exact descriptor is HOST housekeeping, not a guest cleanup or
  * deadline containment claim. An error is not retried (descriptor reuse risk). */
 if(fd>=0){if(close(fd))error(s,e,errno);else e->settled=1;}
 out->written=e->written;out->read_length=e->read;out->settled=e->settled&&(!e->inventory_opened||e->inventory_settled);out->rc=e->primary?e->primary:0;s->busy=0;
}
struct rp_store rf_operations(struct rf_store *s){return (struct rp_store){clock_read,write_once,s};}
int rf_close(struct rf_store *s){if(!s||!s->initialized||s->busy||s->dirfd<0)return 0;int fd=s->dirfd;s->dirfd=-1;return close(fd)==0;}
