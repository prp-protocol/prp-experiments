#!/usr/bin/env python3
"""Native two-guest boot qualification. No PRP traffic or performance conclusion.

Uses the existing held-child owner, private inherited QMP, immutable shared base
and two owned overlays. Broker-provided isolated TAP/vhost descriptors only.
"""
import argparse,ctypes,fcntl,hashlib,importlib.machinery,json,os,pathlib,select,socket,subprocess,sys,time,uuid
ROOT=pathlib.Path(__file__).resolve().parents[3]
PKG=ROOT/'distribution/public-experiments/package';sys.path.insert(0,str(PKG))
from held_binding import Binding,plan
from fd_channel import Channel
from qmp_control import Client
from evidence_io import EvidenceIO,cleanup_drain
from guest_records import decode as decode_guest
installer=importlib.machinery.SourceFileLoader('exp_install',str(PKG/'install')).load_module()
BASE=pathlib.Path('/opt/agentmux/vm/images/sha256/a9b0d42ceb48f79a1cefbe7674c7d4564f58873f0fb6d5f7a31169c96aaee4f8.qcow2')
PIN=BASE.stem

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--started',type=float);ap.add_argument('--deployment');ap.add_argument('--deployment-sha256');ap.add_argument('--artifacts');ap.add_argument('--network-manifest');ap.add_argument('--network-sha256');ap.add_argument('--directory',required=True);ap.add_argument('--helper',required=True);ap.add_argument('--prepared',required=True);ap.add_argument('--modules',action='store_true');ap.add_argument('--socket-probe');ap.add_argument('--identity-probe');ap.add_argument('--private-input-fixture',action='store_true');ap.add_argument('--private-identities');ap.add_argument('--identity-manifest-sha256');ap.add_argument('--paired-handshake',action='store_true');ap.add_argument('--paired-route',action='store_true');ap.add_argument('--setup-diagnostic',action='store_true');ap.add_argument('--permanent-references',action='store_true');ap.add_argument('--rx-tx-references',action='store_true');ap.add_argument('--preliminary',action='store_true');ap.add_argument('--stage-timing',action='store_true');ap.add_argument('--route-timing',action='store_true');ap.add_argument('--route-timing-owned-guest',action='store_true');a=ap.parse_args()
 if a.deployment and not all((a.deployment_sha256,a.artifacts,a.network_manifest,a.network_sha256)):ap.error('Complete pinned standalone deployment required')
 if a.route_timing_owned_guest and not a.route_timing:ap.error('owned guest trace requires route timing')
 if a.route_timing and (not a.preliminary or a.stage_timing):ap.error('route timing requires preliminary and excludes stage timing')
 if a.setup_diagnostic and (not a.permanent_references or a.stage_timing or a.route_timing):ap.error('Setup diagnostic requires permanent profile without timing study')
 if a.stage_timing and not a.preliminary:ap.error('stage timing requires preliminary profile')
 if a.permanent_references and (a.rx_tx_references or not a.preliminary or not a.modules or not a.socket_probe or not a.deployment):ap.error('Permanent references require separate pinned preliminary profile')
 if a.rx_tx_references and (not a.preliminary or not a.modules or not a.socket_probe):ap.error('Reference qualification requires preliminary module/probe profile')
 if a.preliminary and not a.paired_route:ap.error('--preliminary requires paired-route')
 if a.private_identities and (not a.modules or not a.socket_probe or a.private_input_fixture):ap.error('Private identities require module/socket probe and exclude fixtures')
 if a.paired_route:
  if not a.modules or not a.socket_probe:ap.error('--paired-route requires --modules and --socket-probe')
  a.paired_handshake=True
 if a.paired_handshake and not a.private_identities:ap.error('--paired-handshake requires pinned private identity staging')
 if a.identity_probe and not a.modules:ap.error('--identity-probe requires --modules')
 if a.socket_probe and not a.modules:ap.error('--socket-probe requires --modules')
 dest=pathlib.Path(a.directory).absolute();dest.mkdir(mode=0o700)
 t0=time.monotonic() if a.started is None else a.started
 if not 0<t0<=time.monotonic() or time.monotonic()-t0>=600:ap.error('Original runtime origin invalid/expired')
 end=t0+600;launch=t0+40;normal=t0+420;cleanup=t0+590
 receipt={'schema':'EXP002-NATIVE-BOOT-PAIR-1','state':'INCOMPLETE','started':t0,'deadline':end,'primary':None,'secondary':[],
  'authorization':'User: Prossiga até conseguir executar as VMs e obter evidências','method_unchanged':True,
  'scope':'NATIVE_BOOT_AND_OPTIONAL_SIGNED_CONTROL_NO_SPEEDUP','guests':{},'commands':[]}
 caps={};channels={};qclients={};resources=[];streams={};counts={};buffers={};binding=None;private_stage=None;public_raw=None;public_manifest=None
 control_inputs={};sync_offsets={};relay=None;deployment=None;pending_port_fds=set()
 sink=EvidenceIO(dest,receipt['secondary']);drain_errors=set()
 def now():return time.monotonic_ns()
 def bound(e):
  if time.monotonic()>=e:raise RuntimeError('Absolute phase deadline exceeded')
 def run(argv,e):
  bound(e);r=subprocess.run([str(x) for x in argv],capture_output=True,timeout=min(20,e-time.monotonic()))
  receipt['commands'].append({'argv':[str(x) for x in argv],'exit':r.returncode,'stdout':r.stdout.decode(errors='replace'),'stderr':r.stderr.decode(errors='replace')})
  bound(e)
  if r.returncode:raise RuntimeError('Preparation command failed')
  return r.stdout
 def retained(fd):
  n=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,16);os.close(fd);resources.append(n);return n
 def close_owned(fd):
  if fd in resources:resources.remove(fd);os.close(fd)
 def drain(timeout):
  poll=select.poll()
  for fd in streams:poll.register(fd,select.POLLIN|select.POLLHUP)
  for role,cap in caps.items():
   if cap.child and not cap.child.reaped:poll.register(cap.record.pidfd,select.POLLIN)
  for fd,mask in poll.poll(timeout):
   if fd not in streams:continue
   role,kind=streams[fd]
   data=os.read(fd,min(65536,1048576-counts[fd]+1))
   counts[fd]+=len(data)
   # Keep bounded evidence even when refusing overflow.
   keep=data[:max(0,1048576-(counts[fd]-len(data)))]
   buffers[(role,kind)].extend(keep)
   sink.write(role+'-'+kind+'.log',keep,'ab')
   if counts[fd]>1048576:raise RuntimeError('Console stream exceeds 1MiB')
   if not data:close_owned(fd);del streams[fd]
 def relay_data():
  nonlocal relay
  if not a.preliminary:return
  if relay is None:
   from data_sync import Relay
   relay=Relay({r:receipt['guests'][r]['nonce'] for r in ('endpoint','dut')},setup=True,phases=1 if a.permanent_references else 2)
  for role in ('endpoint','dut'):
   b=bytes(buffers[(role,'stdout')]);at=sync_offsets.get(role,0)
   while b'\n' in b[at:]:
    line,_,_=b[at:].partition(b'\n');at+=len(line)+1
    from data_sync import decode_line
    row=decode_line(line)
    if row is not None:
     for target,token,mode in relay.accept(role,row):
      bound(normal);wire=(json.dumps(dict(nonce=receipt['guests'][target]['nonce'],role=target,token=token,mode=mode),separators=(',',':'))+'\n').encode()
      if os.write(control_inputs[target],wire)!=len(wire):raise RuntimeError('Partial barrier write')
   sync_offsets[role]=at
  receipt['data_barriers']=relay.rows
 def record_guest(role):
  lines=bytes(buffers[(role,'stdout')]).split(b'\n')[:-1]
  value=decode_guest(lines)
  if value is None:return False
  expected=receipt['guests'][role];expected['raw_observation']=value
  if value['role']!=role or value['nonce']!=expected['nonce'] or value['probe_sha256']!=receipt['probe_sha256']:raise RuntimeError('Foreign guest evidence')
  if a.modules and value.get('module_smoke',{}).get('state')!='PASS_MODULE_LOAD_READBACK_ONLY':expected['qualification_failure']='Module qualification incomplete'
  if value['kernel']!='5.14.0-687.39.1.el9_8.x86_64':raise RuntimeError('Unexpected target kernel')
  if sorted(i['mac'] for i in value['interfaces'])!=sorted(expected['macs']):raise RuntimeError('Interface identity mismatch')
  if 'observation' not in expected:print(json.dumps({'event':'guest_observed','role':role,'elapsed_s':time.monotonic()-t0,'kernel':value['kernel']}),flush=True)
  if a.private_input_fixture and value.get('private_input_fixture',{}).get('state')!='PASS_PUBLIC_PRIVATE_CHANNEL_FIXTURE':raise RuntimeError('Private input fixture incomplete')
  expected['observation']=value;return True
 try:
  deployment=None;product_catalogue=None;explicit_ports=None;image_pin=PIN
  if a.deployment:
   sys.path.insert(0,str(ROOT/'distribution/public-experiments/native-package'))
   import deployment as public_inputs
   explicit_ports=public_inputs.network(a.network_manifest,a.network_sha256)
   pending_port_fds.update(fd for port in explicit_ports for fd in port[:2])
   deployment,product_catalogue=public_inputs.load(a.deployment,a.deployment_sha256,a.artifacts)
   image_pin=deployment['image']['sha256']
   receipt['deployment_sha256']=a.deployment_sha256;receipt['network_manifest_sha256']=a.network_sha256
   receipt['network_source']='EXPLICIT_INHERITED_TAP_VHOST'
  elif os.environ.get('AGENTMUX_NET_COUNT')!='4':raise RuntimeError('Four broker ports required')
  probe=pathlib.Path(__file__).with_name('guest_probe.py').read_bytes();receipt['probe_sha256']=hashlib.sha256(probe).hexdigest()
  receipt['launcher_sha256']=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()
  receipt['helper_sha256']=hashlib.sha256(pathlib.Path(a.helper).read_bytes()).hexdigest()
  receipt['qemu_sha256']=hashlib.sha256(pathlib.Path('/usr/bin/qemu-system-x86_64').read_bytes()).hexdigest()
  from prepared_run import load
  disk_root=pathlib.Path(a.prepared).resolve();raw=(disk_root/'installation.json').read_bytes()
  prepared=load(disk_root,hashlib.sha256(raw).hexdigest(),image_pin)
  receipt['disks']=prepared.summary()
  bound(t0+20)
  if a.private_identities:
   sys.path.insert(0,str(pathlib.Path(__file__).with_name('identities')))
   from public_evidence import read as read_public
   import stage_private,private_volume
   public_raw=read_public(a.private_identities);public_manifest=json.loads(public_raw)
   public_pin=hashlib.sha256(public_raw).hexdigest()
   if public_pin!=(a.identity_manifest_sha256 or '2b9102e2cdbd69e83c5a1340505c75847137b46de525983c23d7b36d31f470fb'):raise RuntimeError('Unapproved identity manifest')
   private_stage=dest/'private-stage'
   receipt['identity_stage']=stage_private.stage(a.private_identities,private_stage,public_pin,public_manifest['run_nonce'],launch)
   for vm in ('endpoint','dut'):
    private_volume.create(private_stage,vm,public_pin,public_manifest['run_nonce'],launch)
   receipt['identity_manifest_sha256']=public_pin
  network=[]
  if explicit_ports is None:
   explicit_ports=[(int(os.environ['AGENTMUX_TAP_FD_'+str(i)]),int(os.environ['AGENTMUX_VHOST_FD_'+str(i)]),os.environ['AGENTMUX_NET_MAC_'+str(i)]) for i in range(4)]
  for tap,vhost,mac in explicit_ports:
   network.append((retained(os.dup(tap)),retained(os.dup(vhost)),mac))
  for tap,vhost,mac in explicit_ports:
   for fd in (tap,vhost):os.close(fd);pending_port_fds.discard(fd)
  # Reserve child destination numbers0..7 before helper creates gate pipes.
  while True:
   fd=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC);resources.append(fd)
   if fd>=8:break
  binding=Binding(ctypes.CDLL(a.helper),now,int(cleanup*1e9))
  for index,role in enumerate(('endpoint','dut')):
   bound(launch);nonce=str(uuid.uuid4());macs=[network[2*index+i][2] for i in range(2)]
   seed=dest/(role+'-seed');seed.mkdir(mode=0o700)
   user={'write_files':[{'path':'/root/exp002-probe.py','permissions':'0700','content':probe.decode()}],
    'runcmd':[['/usr/bin/python3','/root/exp002-probe.py',role,nonce]]}
   if a.modules:
    import shutil
    catalogue=product_catalogue if product_catalogue is not None else json.loads((ROOT/'experiments/exp-002-none-forwarding/module-only/lab-spec/resumption/m1-crosscheck/checks.json').read_text())['modules']
    (seed/'modules').mkdir();manifest={}
    for name,row in catalogue.items():
     raw=pathlib.Path(row['path']).read_bytes()
     if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise RuntimeError('Product artifact changed')
     (seed/'modules'/(name+'.ko')).write_bytes(raw);manifest[name]={'bytes':len(raw),'sha256':row['sha256']}
    (seed/'modules.json').write_text(json.dumps(manifest))
    smoke=pathlib.Path(__file__).with_name('module_smoke.py').read_text()
    user['write_files'].append({'path':'/root/module_smoke.py','permissions':'0700','content':smoke})
    user['runcmd'][0].append('modules')
    receipt['module_smoke_sha256']=hashlib.sha256(smoke.encode()).hexdigest()
    if a.socket_probe:
     raw=pathlib.Path(a.socket_probe).read_bytes()
     if len(raw)>2097152:raise RuntimeError('Socket probe binary cap')
     (seed/'socket_probe').write_bytes(raw);probe_pin=hashlib.sha256(raw).hexdigest()
     probe_meta={'sha256':probe_pin,'bytes':len(raw),'role':role,'preliminary':a.preliminary}
     if a.permanent_references:probe_meta['reference_profile']='PERMANENT_NONE_REFERENCES_V1'
     if a.rx_tx_references and role=='dut':probe_meta['reference_profile']='RX_TX_REFERENCES_V1'
     if a.route_timing and role=='dut':
      probe_meta['route_timing']=True
      probe_meta['route_timing_owned_guest']=a.route_timing_owned_guest
      for filename in ('stage_capture.py','route_capture.py'):
       content=pathlib.Path(__file__).with_name(filename).read_text()
       receipt[filename+'_sha256']=hashlib.sha256(content.encode()).hexdigest()
       user['write_files'].append({'path':'/root/'+filename,'permissions':'0600','content':content})
     if a.setup_diagnostic and role=='endpoint':probe_meta['setup_diagnostic']=True
     if (a.stage_timing and role=='dut') or (a.setup_diagnostic and role=='endpoint'):
      if a.stage_timing:probe_meta['stage_timing']=True
      trace_source=pathlib.Path(__file__).with_name('stage_capture.py').read_text()
      receipt['stage_capture_sha256']=hashlib.sha256(trace_source.encode()).hexdigest()
      user['write_files'].append({'path':'/root/stage_capture.py','permissions':'0600','content':trace_source})
     if a.preliminary:user['write_files'].append({'path':'/root/data_sync.py','permissions':'0600','content':pathlib.Path(__file__).with_name('data_sync.py').read_text()})
     if a.paired_handshake:
      import pair_plan
      other=2 if role=='endpoint' else 0;peer_key=public_manifest['roles']['D' if role=='endpoint' else 'U']['public_key']
      peer_key_second=public_manifest['roles']['D' if role=='endpoint' else 'E']['public_key']
      paired=pair_plan.encode_route(role,macs[0],network[other][2],macs[1],network[other+1][2],peer_key,peer_key_second) if a.paired_route else pair_plan.encode(role,macs[0],network[other][2],peer_key)
      probe_meta['paired_route']=bool(a.paired_route)
      (seed/'paired-input.bin').write_bytes(paired);probe_meta['paired_input_sha256']=hashlib.sha256(paired).hexdigest()
      receipt.setdefault('paired_inputs',{})[role]={'sha256':probe_meta['paired_input_sha256'],'bytes':len(paired),'local_mac':macs[0],'remote_mac':network[other][2],'remote_public_key':peer_key}
      if a.paired_route:receipt['paired_inputs'][role].update(local_second=macs[1],remote_second=network[other+1][2],remote_public_key_second=peer_key_second)
     (seed/'socket_probe.json').write_text(json.dumps(probe_meta))
     receipt['socket_probe_sha256']=probe_pin
   if a.identity_probe:
    # Public RFC fixture qualification only. No lab identity is staged here.
    raw=pathlib.Path(a.identity_probe).read_bytes()
    if len(raw)>2097152:raise RuntimeError('Identity probe binary cap')
    identity_pin=hashlib.sha256(raw).hexdigest()
    (seed/'identity_probe').write_bytes(raw)
    (seed/'identity_probe.json').write_text(json.dumps({'sha256':identity_pin,'bytes':len(raw),'real_lab_identity':False}))
    receipt['identity_probe_sha256']=identity_pin
   private_fixture=None
   if a.private_identities:
    private_fixture=private_stage/role/'identity.raw'
    (seed/'public-identities.json').write_bytes(public_raw)
    user['write_files'].append({'path':'/root/private_volume.py','permissions':'0700','content':pathlib.Path(private_volume.__file__).read_text()})
    # Public metadata only; private bytes never enter cloud-init or the seed ISO.
    (seed/'private-input.json').write_text(json.dumps({'vm':role,'run_nonce':public_manifest['run_nonce'],'public_sha256':public_pin}))
   if a.private_input_fixture:
    # PUBLIC deterministic transport fixture; never the authorized lab bundle.
    sys.path.insert(0,str(pathlib.Path(__file__).with_name('identities')))
    import private_volume
    nonce_bytes=uuid.UUID(nonce).bytes;public_pin=hashlib.sha256(b'EXP002-PUBLIC-TRANSPORT-FIXTURE-1').digest()
    fixture={r:r.encode()*32 for r in private_volume.ROLES[role]}
    private_fixture=dest/(role+'-public-fixture.raw')
    private_fixture.write_bytes(private_volume.encode(role,nonce_bytes,public_pin,fixture));private_fixture.chmod(0o600)
    source=pathlib.Path(private_volume.__file__).read_text()
    user['write_files'].append({'path':'/root/private_volume.py','permissions':'0700','content':source})
    user['runcmd'][0].append('private-input-fixture')
    receipt['private_input_fixture']={'source_sha256':hashlib.sha256(source.encode()).hexdigest(),'bytes_per_guest':4096,'real_lab_identity':False}
   (seed/'user-data').write_text('#cloud-config\n'+json.dumps(user)+'\n');(seed/'meta-data').write_text('instance-id: exp002-'+nonce+'\nlocal-hostname: exp002-'+role+'\n')
   iso=dest/(role+'-seed.iso');run(['genisoimage','-quiet','-output',iso,'-volid','cidata','-joliet','-rock',seed],launch)
   if sum(p.stat().st_size for p in dest.glob('*-seed.iso'))+sum(p.stat().st_size for p in dest.glob('*-public-fixture.raw'))+(8192 if a.private_identities else 0)>33554432:raise RuntimeError('Aggregate seed exceeds32MiB')
   pin=hashlib.sha256(iso.read_bytes()).hexdigest()
   qparent,qchild=socket.socketpair();qparent.setblocking(False)
   parentfd=retained(qparent.detach());childfd=retained(qchild.detach())
   if a.preliminary:
    infd,input_write=os.pipe2(os.O_CLOEXEC);infd=retained(infd);control_inputs[role]=retained(input_write);os.set_blocking(control_inputs[role],False)
   else:infd=retained(os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC))
   outread,outwrite=os.pipe2(os.O_CLOEXEC);errread,errwrite=os.pipe2(os.O_CLOEXEC)
   outread=retained(outread);outwrite=retained(outwrite);errread=retained(errread);errwrite=retained(errwrite)
   for fd,kind in ((outread,'stdout'),(errread,'stderr')):os.set_blocking(fd,False);streams[fd]=(role,kind);counts[fd]=0;buffers[(role,kind)]=bytearray()
   exefd=retained(os.open('/usr/bin/qemu-system-x86_64',os.O_RDONLY|os.O_CLOEXEC));pairs=network[2*index:2*index+2];nfds=tuple(x for pair in pairs for x in pair[:2])
   argv=['qemu-system-x86_64','-no-user-config','-nodefaults','-machine','pc,accel=kvm','-cpu','host','-m','2048','-smp','1','-display','none','-vga','std','-no-reboot',
    '-chardev','socket,id=expqmp,fd=3,mux=off,server=off','-mon','chardev=expqmp,mode=control',
    '-chardev','stdio,id=console,signal=off','-serial','chardev:console','-drive','file='+str(disk_root/(role+'.qcow2'))+',format=qcow2,if=virtio',
    '-drive','file='+str(iso)+',format=raw,media=cdrom,readonly=on']
   if private_fixture:argv=private_volume.attach_fixture(argv,disk_root/(role+'.qcow2'),private_fixture)
   for i,mac in enumerate(macs):argv+=['-netdev',f'tap,id=link{i},fd={4+2*i},vhost=on,vhostfd={5+2*i}','-device',f'virtio-net-pci,netdev=link{i},mac={mac}']
   selected=plan(exefd,(infd,outwrite,errwrite,childfd),tuple(x.encode() for x in argv),(b'LANG=C',b'LC_ALL=C'),int(launch*1e9),network=nfds)
   receipt['guests'][role]={'nonce':nonce,'macs':macs,'seed_sha256':pin,'argv':argv}
   prepared.recheck(role)
   result=binding.create_held(role,selected);cap=result.capability
   if cap:caps[role]=cap;receipt['guests'][role]['pid']=cap.record.pid
   print(json.dumps({'event':'held_child','role':role,'pid':cap.record.pid if cap else None}),flush=True)
   if result.error:raise result.error
   for fd in (infd,outwrite,errwrite,childfd,exefd,*nfds):close_owned(fd)
   st=os.fstat(parentfd);channel=Channel(parentfd,(st.st_dev,st.st_ino),now,int(cleanup*1e9),calls=32,chunk_bytes=4096)
   q=Client(channel,object(),time.monotonic,cleanup,rx_bytes=65536,tx_bytes=4096,calls=32,frame_bytes=4096);qclients[role]=q;channels[role]=channel
   binding.release(cap);q.negotiate(q.identity,launch);receipt['guests'][role]['qmp_version']=q.version
   print(json.dumps({'event':'qmp_ready','role':role,'elapsed_s':time.monotonic()-t0}),flush=True)
  while True:
   bound(normal);drain(250);relay_data()
   if sink.failed:raise RuntimeError('Evidence persistence failed')
   ready=[record_guest(role) for role in caps]
   if all(ready):
    if any(v.get('qualification_failure') for v in receipt['guests'].values()):raise RuntimeError('Module qualification incomplete')
    break
   for cap in caps.values():
    p=select.poll();p.register(cap.record.pidfd,select.POLLIN)
    if p.poll(0):raise RuntimeError('QEMU terminated before guest evidence')
  receipt['state']='PASS_NATIVE_BOOT_ONLY'
 except Exception as error:receipt['primary']=type(error).__name__+': '+str(error)
 finally:
  for fd in pending_port_fds:
   try:os.close(fd)
   except OSError as e:receipt['secondary'].append('Unconsumed network descriptor: '+str(e))
  # Early failure uses the same original bounds; never fresh cleanup timers.
  for role,cap in caps.items():
   try:
    q=qclients.get(role)
    if q and q.state=='READY':
     try:q.quit(q.identity)
     except Exception as error:receipt['secondary'].append(role+' QMP quit: '+str(error))
    poll=select.poll();poll.register(cap.record.pidfd,select.POLLIN)
    settle_end=min(time.monotonic()+20,cleanup-20)
    while not poll.poll(0) and time.monotonic()<settle_end:cleanup_drain(drain,poll,receipt['secondary'],drain_errors)
    if not poll.poll(0):binding.terminate_exact(cap)
    while not poll.poll(0):bound(cleanup);cleanup_drain(drain,poll,receipt['secondary'],drain_errors)
    binding.observe(cap,'TERMINAL');binding.observe(cap,'REAPED')
    receipt['guests'][role]['terminal']=cap.child.terminal;receipt['guests'][role]['reaped']=cap.child.reaped
    os.close(cap.record.exec_error);cap.record.exec_error=-1;os.close(cap.record.pidfd);cap.record.pidfd=-1
   except Exception as error:receipt['secondary'].append(role+': '+str(error));receipt['state']='INCOMPLETE'
  try:
   while streams:bound(cleanup);drain(100)
  except Exception as error:receipt['secondary'].append('streams: '+str(error));receipt['state']='INCOMPLETE'
  for role,q in qclients.items():
   receipt['guests'][role]['qmp_raw']=[(kind,value.hex() if isinstance(value,bytes) else value) for kind,value in q.raw]
   receipt['guests'][role]['qmp_readiness']=channels[role].readiness
  for (role,kind),body in buffers.items():sink.write(role+'-'+kind+'.log',body,'wb')
  for fd in list(resources):
   try:close_owned(fd)
   except OSError as e:receipt['secondary'].append(str(e))
  if private_stage is not None:
   settled=all(cap.child and cap.child.reaped for cap in caps.values())
   receipt['private_stage_retired']=False
   if settled:
    try:
     for vm,roles in (('endpoint',('U','E')),('dut',('D',))):
      for name in [*(r+'.seed' for r in roles),'identity.raw']:
       (private_stage/vm/name).unlink(missing_ok=True)
     receipt['private_stage_retired']=True
    except OSError:receipt['secondary'].append('Private staged input retirement failed')
   else:receipt['secondary'].append('Private input retained: child settlement unknown')
  receipt['elapsed_s']=time.monotonic()-t0;
  if time.monotonic()>=end:receipt['secondary'].append('Final persistence deadline expired')
  receipt['source_commit']=deployment['source_commit'] if deployment is not None else subprocess.run(['git','rev-parse','HEAD'],cwd=ROOT,capture_output=True,text=True).stdout.strip()
  if deployment is not None:receipt['source_commit_scope']='PRODUCT_MODULE_SOURCE_NOT_CONSUMER_LAUNCHER'
  if receipt['primary'] or receipt['secondary']:receipt['state']='INCOMPLETE'
  (dest/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
 print(json.dumps({'state':receipt['state'],'elapsed_s':receipt['elapsed_s'],'primary':receipt['primary'],'secondary':receipt['secondary'],'receipt':str(dest/'receipt.json')}))
 return 0 if receipt['state']=='PASS_NATIVE_BOOT_ONLY' else 1
if __name__=='__main__':sys.exit(main())
