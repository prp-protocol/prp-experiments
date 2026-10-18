"""Two-mode, private serial barrier. No frame/remote-acceptance claim."""
import json
def decode_line(line):
 marker=b'EXP002_SYNC '
 if marker not in line:return None
 if len(line)>512 or line.count(marker)!=1:raise ValueError('Ambiguous/oversized barrier')
 return json.loads(line.split(marker,1)[1])

class Relay:
 def __init__(self,nonces,setup=False,phases=2):
  if type(phases) is not int or phases not in (1,2):raise ValueError('phase count')
  self.phases=phases
  if set(nonces)!={'endpoint','dut'}:raise ValueError('roles')
  self.nonces=dict(nonces);self.setup=setup;self.mode=3 if setup else 1;self.ready=set();self.done=set();self.rows=[]
 def accept(self,role,row):
  if set(row)!={'nonce','role','mode','event'} or row['nonce']!=self.nonces[role] or row['role']!=role or type(row['mode']) is not int or row['mode']!=self.mode:raise ValueError('Foreign/stale barrier')
  if not self.setup and self.mode>self.phases:raise ValueError('Barrier already complete')
  event=row['event'];self.rows.append(dict(row))
  if self.setup:
   if event!='READY' or role in self.ready:raise ValueError('Setup barrier order')
   self.ready.add(role)
   if len(self.ready)!=2:return []
   actions=[(r,'G',self.mode) for r in ('endpoint','dut')]
   self.ready.clear();self.mode+=1
   if self.mode==6:self.setup=False;self.mode=1
   return actions
  if event=='READY':
   if self.done or role in self.ready:raise ValueError('Duplicate/late ready')
   self.ready.add(role)
   return [(r,'G',self.mode) for r in ('endpoint','dut')] if len(self.ready)==2 else []
  if event!='DONE' or len(self.ready)!=2 or role in self.done:raise ValueError('Unexpected barrier')
  if role=='dut' and 'endpoint' not in self.done:raise ValueError('DUT before data completion')
  self.done.add(role)
  if role=='endpoint':return [('dut','E',self.mode)]
  actions=[(r,'N',self.mode) for r in ('endpoint','dut')]
  self.mode+=1;self.ready.clear();self.done.clear();return actions

def guest_run(argv,secret,role,nonce,end,stage_capture=None):
 import os,select,subprocess,termios,time
 tty=os.open('/dev/ttyS0',os.O_RDWR|os.O_NOCTTY|os.O_NONBLOCK|os.O_CLOEXEC)
 saved=termios.tcgetattr(tty);changed=list(saved);changed[3]&=~(termios.ICANON|termios.ECHO);termios.tcsetattr(tty,termios.TCSANOW,changed)
 rd,wr=os.pipe2(os.O_CLOEXEC);p=None;out=bytearray();err=bytearray();lines=bytearray();incoming=bytearray();transcript=[]
 try:
  if time.monotonic()>=end:raise RuntimeError('Before probe deadline')
  env=dict(os.environ,EXP002_CONTROL_FD=str(rd))
  p=subprocess.Popen(argv,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,pass_fds=(rd,),env=env)
  os.close(rd);rd=-1;p.stdin.write(secret);p.stdin.close();del secret
  poll=select.poll();channels={p.stdout.fileno():out,p.stderr.fileno():err}
  for fd in channels:os.set_blocking(fd,False);poll.register(fd,select.POLLIN|select.POLLHUP)
  poll.register(tty,select.POLLIN)
  while channels:
   if time.monotonic()>=end:raise RuntimeError('Probe deadline')
   for fd,events in poll.poll(50):
    if fd==tty:
     b=os.read(tty,1024);incoming.extend(b)
     if len(incoming)>2048:raise RuntimeError('Serial input overflow')
     while b'\n' in incoming:
      line,_,rest=incoming.partition(b'\n');incoming[:]=rest
      if not line:continue
      row=json.loads(line);transcript.append(row)
      if len(transcript)>9 or set(row)!={'nonce','role','token','mode'} or row['nonce']!=nonce or row['role']!=role or row['token'] not in ('G','E','N') or type(row['mode']) is not int or row['mode'] not in (1,2,3,4,5):raise RuntimeError('Serial binding')
      raw=('%s %d\n'%(row['token'],row['mode'])).encode()
      if time.monotonic()>=end or os.write(wr,raw)!=len(raw):raise RuntimeError('Control write incomplete')
    elif fd in channels:
     b=os.read(fd,8192);buf=channels[fd];buf.extend(b)
     if len(buf)>131072:raise RuntimeError('Probe output overflow')
     if fd==p.stderr.fileno():
      lines.extend(b)
      while b'\n' in lines:
       line,_,rest=lines.partition(b'\n');lines[:]=rest
       if line.startswith(b'EXP002_DATA '):
        _,mode,event=line.decode('ascii').split()
        if stage_capture is not None:stage_capture.boundary(int(mode),event)
        print('EXP002_SYNC '+json.dumps(dict(nonce=nonce,role=role,mode=int(mode),event=event),separators=(',',':')),flush=True)
     if not b:poll.unregister(fd);del channels[fd]
  left=end-time.monotonic()
  if left<=0:raise RuntimeError('Probe late completion')
  rc=p.wait(timeout=left)
  return subprocess.CompletedProcess(argv,rc,bytes(out),bytes(err))
 except Exception as error:
  return subprocess.CompletedProcess(argv,124,bytes(out[:131072]),bytes(err[:130000])+b'\nSUPERVISOR_FAILURE '+str(error).encode()[:1000])
 finally:
  if p is not None and p.poll() is None:
   p.kill();p.wait(timeout=2)
  if p is not None:
   for stream in (p.stdout,p.stderr):stream.close()
  if rd>=0:os.close(rd)
  os.close(wr);termios.tcsetattr(tty,termios.TCSANOW,saved);os.close(tty)
