#!/usr/bin/env python3
"""Private, one-shot U/D/E provisioning. No VM, trust-store or network action."""
import argparse,hashlib,json,os,pathlib,secrets,stat,subprocess,time
ROLES=('U','D','E')
def write_new(path,data):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(data)
  while view:
   n=os.write(fd,view)
   if n<=0:raise RuntimeError('No progress writing private input')
   view=view[n:]
  os.fsync(fd)
 except BaseException:
  # This file was exclusively created by this call. Retain no partial seed.
  try:
   a=os.fstat(fd);b=path.stat(follow_symlinks=False)
   if (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino):path.unlink()
  except OSError:pass # Caller records remaining private input; preserve first error.
  raise
 finally:os.close(fd)
def derive(helper,seed,end):
 left=end-time.monotonic()
 if left<=0:raise RuntimeError('Provisioning deadline')
 r=subprocess.run([str(helper)],input=seed,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(20,left),check=False)
 if time.monotonic()>=end or r.returncode or len(r.stdout)>1024 or len(r.stderr)>1024:raise RuntimeError('Public derivation refused')
 x=json.loads(r.stdout)
 if set(x)!={'identity_suite','public_key','strong_id','provider','fips_default','self_check'} or x['identity_suite']!=1 or x['self_check'] is not True:raise RuntimeError('Public result shape')
 for k in ('public_key','strong_id'):
  if not isinstance(x[k],str) or len(x[k])!=64 or len(bytes.fromhex(x[k]))!=32:raise RuntimeError('Public result size')
 if not isinstance(x['provider'],str) or len(x['provider'])>64 or type(x['fips_default']) is not bool:raise RuntimeError('Provider result shape')
 return x
def create(destination,helper,helper_sha256,derive_fn=derive,entropy=secrets.token_bytes):
 # Helper is our built executable, not downloaded/guest content.
 helper=pathlib.Path(helper).absolute();before=helper.stat()
 if not stat.S_ISREG(before.st_mode) or hashlib.sha256(helper.read_bytes()).hexdigest()!=helper_sha256:raise RuntimeError('Helper pin mismatch')
 destination=pathlib.Path(destination).absolute();destination.mkdir(mode=0o700)
 private=destination/'private';private.mkdir(mode=0o700)
 end=time.monotonic()+60;created=[]
 public={'schema':'EXP002-DISPOSABLE-IDENTITIES-1','run_nonce':entropy(16).hex(),'state':'INCOMPLETE','roles':{},'helper_sha256':helper_sha256,'target_qualified':False,'native_used':False,'secret_evidence_allowed':False}
 try:
  for role in ROLES:
   if time.monotonic()>=end:raise RuntimeError('Provisioning deadline')
   seed=entropy(32)
   if len(seed)!=32:raise RuntimeError('Entropy length')
   result=derive_fn(helper,seed,end)
   path=private/(role+'.seed');created.append(path);write_new(path,seed)
   public['roles'][role]=result
   del seed
  if len({x['public_key'] for x in public['roles'].values()})!=3 or len({x['strong_id'] for x in public['roles'].values()})!=3:raise RuntimeError('Duplicate identities')
  public['state']='PRIVATE_PROVISIONING_COMPLETE_HOST_ONLY'
  write_new(destination/'public.json',(json.dumps(public,indent=2)+'\n').encode())
  return public
 except BaseException:
  cleanup_failed=False
  for p in created:
   try:p.unlink(missing_ok=True)
   except OSError:cleanup_failed=True
  public['state']='INCOMPLETE_SECRET_RETIREMENT_UNKNOWN' if cleanup_failed else 'INCOMPLETE_SECRETS_RETIRED'
  # Only a fixed failure class. No subprocess data/secret exception text.
  public['error']='PROVISIONING_REFUSED'
  try:write_new(destination/'failure.json',(json.dumps(public,indent=2)+'\n').encode())
  except Exception:pass # First failure remains primary even if its receipt cannot persist.
  raise
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('destination');p.add_argument('helper');p.add_argument('helper_sha256');a=p.parse_args()
 try:
  r=create(a.destination,a.helper,a.helper_sha256);print(json.dumps({'state':r['state'],'roles':list(r['roles']),'public_manifest':str(pathlib.Path(a.destination)/'public.json')}))
 except Exception:raise SystemExit('Private provisioning refused; no retry')
