"""One-shot private input staging. Not a VM launcher or public artifact exporter."""
import hashlib,json,os,pathlib,stat,time
from public_evidence import read as read_public
from provision import write_new
ROLE_MAP={'endpoint':('U','E'),'dut':('D',)}
def stage(bundle,destination,public_sha256,nonce,deadline):
 def gate():
  if not isinstance(deadline,(int,float)) or not 0<deadline<float('inf') or time.monotonic()>=deadline:raise RuntimeError('Original staging deadline')
 gate();bundle=pathlib.Path(bundle).absolute();destination=pathlib.Path(destination).absolute()
 public=read_public(bundle);manifest=json.loads(public)
 if hashlib.sha256(public).hexdigest()!=public_sha256 or manifest['run_nonce']!=nonce:raise RuntimeError('Identity run binding')
 gate()
 # Own exclusive bundle and retained directory FD, not ambient arbitrary paths.
 directory=os.open(bundle/'private',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 created=[];receipt={'schema':'EXP002-PRIVATE-STAGE-1','run_nonce':nonce,'public_sha256':public_sha256,'state':'INCOMPLETE','roles':ROLE_MAP,'secret_bytes':96,'native_used':False}
 try:
  info=os.fstat(directory)
  if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:raise RuntimeError('Private directory ownership/mode')
  gate();destination.mkdir(mode=0o700)
  # Claim precedes secret reads or copies; failure never silently retries a run.
  write_new(bundle/'stage-claim.json',(json.dumps({'nonce':nonce,'state':'STAGING_ATTEMPTED'})+'\n').encode())
  for vm,roles in ROLE_MAP.items():
   target=destination/vm;target.mkdir(mode=0o700)
   write_new(target/'public.json',public)
   for role in roles:
    gate();fd=os.open(role+'.seed',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    try:
     before=os.fstat(fd)
     if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600 or before.st_size!=32:raise RuntimeError('Private input shape/ownership')
     seed=os.read(fd,33);after=os.fstat(fd)
     if len(seed)!=32 or before.st_ino!=after.st_ino or before.st_mtime_ns!=after.st_mtime_ns or after.st_size!=32:raise RuntimeError('Private input changed')
    finally:os.close(fd)
    gate();p=target/(role+'.seed');created.append(p);write_new(p,seed);del seed;gate()
  receipt['state']='PRIVATE_STAGED_NOT_BOOTED';write_new(destination/'public-receipt.json',(json.dumps(receipt,indent=2)+'\n').encode());return receipt
 except BaseException:
  failed=False
  for p in created:
   try:p.unlink(missing_ok=True)
   except OSError:failed=True
  receipt['state']='INCOMPLETE_RETIREMENT_UNKNOWN' if failed else 'INCOMPLETE_STAGED_SECRETS_RETIRED'
  if destination.exists():
   try:write_new(destination/'failure.json',(json.dumps(receipt,indent=2)+'\n').encode())
   except OSError:pass
  raise
 finally:os.close(directory)
