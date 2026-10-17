"""Retire only inventoried disposable files after the two owned guests were reaped.

Receipts are local owner records, not adversarial writer-census or secure erasure.
No process is signalled and the shared base is never a cleanup candidate.
"""
import json,os,pathlib,signal,stat
from deployment import bounded

def identity(p):
 s=p.lstat()
 if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_uid!=os.geteuid():raise ValueError('Owned regular disposable file required')
 return [s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def root_owned(root):
 root=pathlib.Path(root).absolute();s=root.lstat()
 if root.resolve()!=root or not stat.S_ISDIR(s.st_mode) or s.st_uid!=os.geteuid() or s.st_mode&0o077:raise ValueError('Private run directory required')
 return root,[s.st_dev,s.st_ino]
def settled(root):
 r=json.loads(bounded(root/'native/receipt.json',4*1024*1024));g=r.get('guests',{})
 if set(g)!={'endpoint','dut'}:raise ValueError('Both original children required')
 for v in g.values():
  t=v.get('terminal')
  if (v.get('reaped') is not True or type(t) is not list or len(t)!=5
      or not all(type(x) is int for x in t) or t[0]!=v.get('pid') or t[0]<=0
      or t[1]!=signal.SIGCHLD or t[2] not in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED)
      or t[4]!=os.getuid() or not (0<=t[3]<=255 if t[2]==os.CLD_EXITED else 0<t[3]<signal.NSIG)):
   raise ValueError('Both original children must be terminal and reaped; no kill fallback')
 return r

def capture(directory):
 root,rid=root_owned(directory);settled(root)
 names=['disks/endpoint.qcow2','disks/dut.qcow2','native/endpoint-seed.iso','native/dut-seed.iso',*[f'identities/private/{r}.seed' for r in ('U','D','E')]]
 for role in ('endpoint','dut'):
  seed=root/'native'/(role+'-seed')
  for p in seed.rglob('*'):
   if p.is_symlink():raise ValueError('Symlink in owned seed')
   if p.is_file():
    if len(names)>=128:raise ValueError('Disposable inventory bound')
    names.append(str(p.relative_to(root)))
 if len(names)>128:raise ValueError('Disposable inventory bound')
 rows={n:identity(root/n) for n in names}
 disks=json.loads(bounded(root/'disks/installation.json',65536))
 for role in ('endpoint','dut'):
  if rows[f'disks/{role}.qcow2'][:2]!=disks['overlay_identities'][role+'.qcow2'][:2]:raise ValueError('Overlay ownership changed')
 value={'schema':'exp002-disposable-files-1','root':rid,'files':rows,'base_included':False}
 with (root/'cleanup-inventory.json').open('x') as f:json.dump(value,f,indent=2);f.write('\n')
 return value

def clean(directory):
 root,rid=root_owned(directory);settled(root)
 inv=json.loads(bounded(root/'cleanup-inventory.json',65536))
 if inv.get('schema')!='exp002-disposable-files-1' or inv.get('root')!=rid or inv.get('base_included') is not False or type(inv.get('files')) is not dict or len(inv['files'])>128:raise ValueError('Cleanup inventory binding')
 paths=[]
 for n,expected in inv['files'].items():
  rel=pathlib.PurePosixPath(n)
  allowed=(n in ('disks/endpoint.qcow2','disks/dut.qcow2','native/endpoint-seed.iso','native/dut-seed.iso') or n in [f'identities/private/{r}.seed' for r in ('U','D','E')] or any(n.startswith('native/'+r+'-seed/') for r in ('endpoint','dut')))
  if rel.is_absolute() or '..' in rel.parts or not allowed:raise ValueError('Not a disposable path')
  p=root/rel
  if p.resolve()!=p or identity(p)!=expected:raise ValueError('Disposable file changed; nothing removed')
  paths.append((p,expected))
 record=root/'cleanup.json'
 # Exclusive claim precedes any deletion. A partial cleanup is not silently retried.
 with record.open('x') as f:
  result={'schema':'exp002-cleanup-1','state':'INCOMPLETE','removed':[],'primary':None,'base_untouched':True,'secure_erasure_claimed':False}
  try:
   for p,expected in paths:
    if identity(p)!=expected:raise ValueError('Disposable file changed after admission')
    p.unlink();result['removed'].append(str(p.relative_to(root)))
   result['state']='OWN_DISPOSABLE_FILES_REMOVED'
  except Exception as e:result['primary']=type(e).__name__+': '+str(e);raise
  finally:json.dump(result,f,indent=2);f.write('\n')
 return result
