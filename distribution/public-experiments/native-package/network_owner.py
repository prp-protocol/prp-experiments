"""Create two isolated TAP/vhost links in a NEW network namespace only.

Called explicitly by the local native runner. Requires CAP_SYS_ADMIN/NET_ADMIN
and /dev/net/tun plus /dev/vhost-net. No global interfaces, routes or sysctls.
"""
import ctypes,fcntl,json,math,os,pathlib,secrets,struct,subprocess,time

def create(directory,end,*,clock=time.monotonic):
 def bound():
  at=clock()
  if not math.isfinite(end) or not math.isfinite(at) or at>=end:raise RuntimeError('Network setup deadline')
  return end-at
 def run(args):
  remaining=bound();p=subprocess.run(args,capture_output=True,timeout=min(5,remaining))
  bound()
  if p.returncode:raise RuntimeError('Private network setup failed: '+p.stderr.decode(errors='replace')[:512])
  return p.stdout
 bound()
 original=os.stat('/proc/self/ns/net').st_ino
 lib=ctypes.CDLL(None,use_errno=True);lib.unshare.argtypes=[ctypes.c_int];lib.unshare.restype=ctypes.c_int
 if lib.unshare(0x40000000)!=0:raise OSError(ctypes.get_errno(),'Cannot create private network namespace; no fallback')
 current=os.stat('/proc/self/ns/net').st_ino
 if current==original:raise RuntimeError('Private network namespace not established')
 fds=[];ports=[]
 try:
  for bridge in ('inlink','outlink'):
   run(['ip','link','add',bridge,'type','bridge'])
   run(['ip','link','set','dev',bridge,'addrgenmode','none'])
   run(['ip','link','set','dev',bridge,'up'])
  for index in range(4):
   bound();name='exp'+str(index)
   tap=os.open('/dev/net/tun',os.O_RDWR|os.O_CLOEXEC);fds.append(tap)
   actual=fcntl.ioctl(tap,0x400454ca,struct.pack('16sH',name.encode(),0x0002|0x1000))
   if actual[:16].split(b'\0')[0]!=name.encode():raise RuntimeError('TAP name differs')
   vhost=os.open('/dev/vhost-net',os.O_RDWR|os.O_CLOEXEC);fds.append(vhost)
   run(['ip','link','set','dev',name,'addrgenmode','none'])
   run(['ip','link','set','dev',name,'master','inlink' if index%2==0 else 'outlink'])
   run(['ip','link','set','dev',name,'up'])
   mac='02:'+':'.join(f'{b:02x}' for b in secrets.token_bytes(5))
   ports.append({'tap':tap,'vhost':vhost,'mac':mac})
  bound()
  if len({p['mac'] for p in ports})!=4:raise RuntimeError('MAC collision; no retry')
  value={'schema':'exp002-inherited-tap-vhost-1','netns_inode':current,'ports':ports}
  path=pathlib.Path(directory)/'network.json'
  with path.open('x') as out:json.dump(value,out,indent=2);out.write('\n')
  os.chmod(path,0o600)
  # Caller owns descriptors; namespace persists only through its processes/fds.
  return path,fds
 except BaseException:
  for fd in fds:os.close(fd)
  raise
