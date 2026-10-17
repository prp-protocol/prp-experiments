"""Pinned public product inputs; no ambient sibling catalogue or executable lookup."""
import hashlib,json,os,pathlib,re,stat
MODULES={'prp_adjacencies','prp_carrier_ethernet','blake3','ed25519','ed25519_blake3'}
KERNEL='5.14.0-687.39.1.el9_8.x86_64'

def need(ok,message):
 if not ok:raise ValueError(message)
def unique(items):
 d={}
 for k,v in items:
  need(k not in d,'Duplicate JSON field');d[k]=v
 return d
def digest(pin):return type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin) is not None

def bounded(path,limit):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  a=os.fstat(f.fileno());need(stat.S_ISREG(a.st_mode) and a.st_size<=limit,'Bounded regular file required')
  data=f.read(limit+1);b=os.fstat(f.fileno())
  need(len(data)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns),'File changed during read')
 return data

def load(path,pin,artifacts):
 need(digest(pin),'Independent deployment digest required')
 raw=bounded(path,32768);need(hashlib.sha256(raw).hexdigest()==pin,'Deployment manifest digest')
 d=json.loads(raw,object_pairs_hook=unique)
 need(type(d) is dict and set(d)=={'schema','kernel','source_commit','image','modules'},'Deployment schema')
 need(d['schema']=='exp002-native-assets-1' and d['kernel']==KERNEL,'Supported kernel/profile')
 need(type(d['source_commit']) is str and re.fullmatch('[0-9a-f]{40}',d['source_commit']),'Exact module source version')
 image=d['image'];need(type(image) is dict and set(image)=={'sha256','bytes','virtual_bytes'},'Image schema')
 need(digest(image['sha256']) and all(type(image[k]) is int and image[k]>0 for k in ('bytes','virtual_bytes')),'Image geometry/digest')
 need(type(d['modules']) is dict and set(d['modules'])==MODULES,'Exact five product modules')
 root=pathlib.Path(artifacts).absolute();need(root.resolve()==root,'Symlinked artifact directory')
 total=0;rows={}
 for name,v in d['modules'].items():
  need(type(v) is dict and set(v)=={'file','sha256','bytes'} and v['file']==name+'.ko','Module filename/schema')
  need(digest(v['sha256']) and type(v['bytes']) is int and 0<v['bytes']<=16777216,'Module bound/digest')
  total+=v['bytes'];need(total<=16777216,'Aggregate module input bound')
  raw=bounded(root/v['file'],v['bytes']);need(len(raw)==v['bytes'] and hashlib.sha256(raw).hexdigest()==v['sha256'],'Module bytes differ: '+name)
  rows[name]={'path':str(root/v['file']),'bytes':v['bytes'],'sha256':v['sha256']}
 return d,rows

def network(path,pin):
 need(digest(pin),'Network manifest digest required')
 raw=bounded(path,8192);need(hashlib.sha256(raw).hexdigest()==pin,'Network manifest changed')
 d=json.loads(raw,object_pairs_hook=unique)
 need(type(d) is dict and set(d)=={'schema','netns_inode','ports'} and d['schema']=='exp002-inherited-tap-vhost-1','Network schema')
 need(type(d['netns_inode']) is int and d['netns_inode']==os.stat('/proc/self/ns/net').st_ino,'Network owner namespace changed')
 need(type(d['ports']) is list and len(d['ports'])==4,'Four network ports')
 result=[];fds=set();macs=set()
 for p in d['ports']:
  need(type(p) is dict and set(p)=={'tap','vhost','mac'},'Port fields')
  for k in ('tap','vhost'):
   fd=p[k];need(type(fd) is int and fd>=3 and fd not in fds,'Distinct inherited descriptors');fds.add(fd)
   need(stat.S_ISCHR(os.fstat(fd).st_mode),'TAP/vhost character descriptor required')
  m=p['mac'];need(type(m) is str and re.fullmatch('[0-9a-f]{2}(:[0-9a-f]{2}){5}',m) and int(m[:2],16)&3==2 and m not in macs,'Distinct local unicast MAC');macs.add(m)
  result.append((p['tap'],p['vhost'],m))
 return result
