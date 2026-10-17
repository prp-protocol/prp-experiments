"""Fixed private read-only block input. Never export/hash this volume as evidence.

The public manifest is independently supplied. This decoder is not proof of
private-key/public-key correspondence; the provider must derive and compare it.
"""
import hashlib,json,os,pathlib,stat,struct,time

SIZE=4096
MAGIC=b'EXP2KEY1'
ROLES={'endpoint':('U','E'),'dut':('D',)}
DEVICE='/dev/disk/by-id/virtio-exp002-identity'

def gate(deadline,clock=time.monotonic):
 if type(deadline) not in (int,float) or not 0<deadline<float('inf') or clock()>=deadline:
  raise RuntimeError('Private input deadline')

def encode(vm,nonce,public_digest,seeds):
 if vm not in ROLES or set(seeds)!=set(ROLES[vm]):raise ValueError('Private input roles')
 if len(nonce)!=16 or len(public_digest)!=32:raise ValueError('Private input binding')
 out=bytearray(MAGIC+bytes([1 if vm=='endpoint' else 2,len(seeds)])+nonce+public_digest)
 for role in ROLES[vm]:
  if type(seeds[role]) is not bytes or len(seeds[role])!=32:raise ValueError('Private input size')
  out.extend(role.encode()+seeds[role])
 if len(out)>SIZE:raise ValueError('Private input capacity')
 out.extend(bytes(SIZE-len(out)));return bytes(out)

def decode(raw,vm,nonce,public_digest):
 if vm not in ROLES or type(raw) is not bytes or len(raw)!=SIZE:raise ValueError('Private input shape')
 if raw[:8]!=MAGIC or raw[8]!=({'endpoint':1,'dut':2}[vm]) or raw[9]!=len(ROLES[vm]):raise ValueError('Private input role binding')
 if len(nonce)!=16 or len(public_digest)!=32 or raw[10:26]!=nonce or raw[26:58]!=public_digest:raise ValueError('Private input run binding')
 result={};offset=58
 for role in ROLES[vm]:
  if raw[offset:offset+1]!=role.encode():raise ValueError('Private input order')
  result[role]=raw[offset+1:offset+33];offset+=33
 if any(raw[offset:]):raise ValueError('Private input trailing data')
 return result

def create(stage,vm,public_digest,nonce,deadline):
 """Create once in an existing PRIVATE stage, never the public seed directory."""
 from provision import write_new
 from public_evidence import read as read_public
 gate(deadline);stage=pathlib.Path(stage)
 public=read_public(stage/vm)
 if hashlib.sha256(public).hexdigest()!=public_digest or json.loads(public)['run_nonce']!=nonce:raise ValueError('Public manifest binding')
 fd=os.open(stage/vm,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 seeds={}
 try:
  st=os.fstat(fd)
  if st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700:raise ValueError('Private directory mode')
  for role in ROLES[vm]:
   gate(deadline);source=os.open(role+'.seed',os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
   try:
    before=os.fstat(source)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size!=32 or before.st_uid!=os.geteuid() or stat.S_IMODE(before.st_mode)!=0o600:raise ValueError('Private seed shape')
    data=os.read(source,33);after=os.fstat(source)
    if len(data)!=32 or (before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise ValueError('Private seed changed')
    seeds[role]=data
   finally:os.close(source)
  gate(deadline);raw=encode(vm,bytes.fromhex(nonce),bytes.fromhex(public_digest),seeds)
  path=stage/vm/'identity.raw'
  write_new(path,raw);gate(deadline)
  return {'vm':vm,'bytes':SIZE,'roles':list(ROLES[vm]),'public_sha256':public_digest,'run_nonce':nonce,'state':'PRIVATE_VOLUME_NOT_ATTACHED'}
 finally:
  seeds.clear();os.close(fd)

def qemu_args(path):
 # Caller must bind this owned path and keep it private through child settlement.
 path=str(pathlib.Path(path).absolute())
 if ',' in path or '\n' in path:raise ValueError('Private volume path')
 return ['-drive','file='+path+',format=raw,if=none,id=expidentity,readonly=on',
         '-device','virtio-blk-pci,drive=expidentity,serial=exp002-identity']

def attach_fixture(argv,root,path):
 # Explicit root boot priority; other device ordering is not a boot contract.
 argv=list(argv);old='file='+str(root)+',format=qcow2,if=virtio'
 if argv.count(old)!=1 or any('bootindex=' in x or x=='-boot' for x in argv):raise ValueError('Ambiguous boot binding')
 argv[argv.index(old)]='file='+str(root)+',format=qcow2,if=none,id=exproot'
 return argv+['-device','virtio-blk-pci,drive=exproot,bootindex=1']+qemu_args(path)

def read_guest(vm,nonce,public_digest,deadline,device=DEVICE):
 """Read exactly one fixed block device; absence/foreign input refuses.

No mount, console output or guest disk copy. The caller owns the returned secret
buffers and must only pass them to the provider, never an evidence serializer.
"""
 gate(deadline);fd=os.open(device,os.O_RDONLY|os.O_CLOEXEC)
 try:
  if not stat.S_ISBLK(os.fstat(fd).st_mode):raise ValueError('Private input is not a block device')
  # BLKROGET: refuse writable input; this does not prove host writer absence.
  import fcntl
  ro=bytearray(4);fcntl.ioctl(fd,0x125e,ro,True)
  if struct.unpack('=I',ro)[0]!=1:raise ValueError('Private input must be read-only')
  raw=os.read(fd,SIZE+1);gate(deadline)
  return decode(raw,vm,bytes.fromhex(nonce),bytes.fromhex(public_digest))
 finally:os.close(fd)
