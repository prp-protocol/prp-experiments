#!/usr/bin/python3
"""Finite private-guest module load/readback/unload qualification; no PRP traffic."""
import hashlib,json,os,pathlib,subprocess,time

def exercise(nonce=None):
 result={'schema':'EXP002-MODULE-SMOKE-1','state':'INCOMPLETE','primary':None,'secondary':[],'commands':[],'loaded':[],'unloaded':[],'pins':{},'parameters':{}}
 trace_capture=None
 buffer_restore=[];root=pathlib.Path('/run/exp002-seed');owned=[];mounted=False;start=time.monotonic();end=min(start+60,360);close_end=min(start+80,410)
 def read(p):
  try:return pathlib.Path(p).read_text().strip()
  except OSError as e:return {'error':str(e)}
 def modules():return {x.split()[0] for x in pathlib.Path('/proc/modules').read_text().splitlines()}
 def run(argv,cleanup=False,output_cap=8192):
  limit=close_end if cleanup else end;remaining=limit-time.monotonic()
  if remaining<=0:raise RuntimeError('Original guest phase expired')
  r=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(20,remaining))
  row={'argv':argv,'rc':r.returncode,'stdout':r.stdout[:output_cap].decode(errors='replace'),'stderr':r.stderr[:output_cap].decode(errors='replace'),'at':time.monotonic()};result['commands'].append(row)
  if len(r.stdout)>output_cap or len(r.stderr)>output_cap:raise RuntimeError('Command output overflow')
  if r.returncode or time.monotonic()>=limit:raise RuntimeError('Command failed or completed late: '+argv[0])
  return r
 stage=pathlib.Path('/usr/lib/modules')/os.uname().release/'extra/exp002-owned'
 before=modules();result['before']=sorted(before);result['tainted_before']=read('/proc/sys/kernel/tainted')
 try:
  if os.uname().release!='5.14.0-687.39.1.el9_8.x86_64':raise RuntimeError('Kernel mismatch')
  root.mkdir(mode=0o700);run(['/usr/bin/mount','-o','ro','/dev/sr0',str(root)]);mounted=True
  manifest=json.loads((root/'modules.json').read_text());names=['blake3','ed25519','ed25519_blake3','prp_adjacencies','prp_carrier_ethernet']
  if set(manifest)!=set(names):raise RuntimeError('Module manifest scope')
  for name in names:
   raw=(root/'modules'/(name+'.ko')).read_bytes();pin=manifest[name]
   if len(raw)!=pin['bytes'] or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise RuntimeError('Module hash mismatch')
   result['pins'][name]=pin
   if name in before:raise RuntimeError('Preexisting product module')
  # Standard private-guest module installation path and existing SELinux labels.
  # No policy switch, custom allow rule or signature bypass.
  stage.mkdir(parents=True,mode=0o700)
  for name in names:
   target=stage/(name+'.ko')
   with target.open('xb') as out:out.write((root/'modules'/(name+'.ko')).read_bytes())
   if hashlib.sha256(target.read_bytes()).hexdigest()!=manifest[name]['sha256']:raise RuntimeError('Staged module changed')
  run(['/usr/sbin/restorecon','-R',str(stage)])
  run(['/usr/bin/ls','-lZ',str(stage)])
  result['selinux_enforce']=read('/sys/fs/selinux/enforce')
  # Normal target policy is not changed. A load refusal remains a refusal.
  for name in ['libcurve25519_generic','curve25519_x86_64']:
   if name not in before:
    try:run(['/usr/sbin/modprobe',name])
    finally:
     if name in modules():owned.append(name);result['loaded'].append(name)
  for name in names:
   try:run(['/usr/sbin/insmod',str(stage/(name+'.ko'))])
   finally:
    if name in modules():owned.append(name);result['loaded'].append(name)
  for name in ['prp_adjacencies','prp_carrier_ethernet']:
   d=pathlib.Path('/sys/module')/name/'parameters'
   result['parameters'][name]={p.name:read(p) for p in sorted(d.iterdir())}
  if (root/'socket_probe.json').exists():
   result['buffer_limits']=[]
   for name in ('rmem_max','wmem_max'):
    path=pathlib.Path('/proc/sys/net/core')/name;before_value=int(path.read_text());row={'name':name,'before':before_value,'requested_minimum':262144};result['buffer_limits'].append(row)
    if before_value<262144:
     if time.monotonic()>=end:raise RuntimeError('Buffer setup deadline')
     buffer_restore.append((path,before_value,row));path.write_text('262144')
    row['after']=int(path.read_text())
    if row['after']<262144 or time.monotonic()>=end:raise RuntimeError('Buffer setup readback/deadline')
   pin=json.loads((root/'socket_probe.json').read_text());raw=(root/'socket_probe').read_bytes()
   if len(raw)!=pin['bytes'] or len(raw)>2097152 or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise RuntimeError('Socket probe hash')
   if pin.get('preliminary'):
    # Only the two independently bound, private guest links. No global/default
    # sysctl, host interface, filtering, or offload policy is changed.
    paired=(root/'paired-input.bin').read_bytes()
    if len(paired)!=104 or hashlib.sha256(paired).hexdigest()!=pin.get('paired_input_sha256'):raise RuntimeError('Private link plan binding')
    result['private_links']=[]
    for name,offset in (('eth0',16),('eth1',28)):
     base=pathlib.Path('/sys/class/net')/name;expected=paired[offset:offset+6].hex(':');index=int((base/'ifindex').read_text())
     if (base/'address').read_text().strip()!=expected:raise RuntimeError('Private interface MAC mismatch')
     row={'name':name,'mac':expected,'ifindex':index};result['private_links'].append(row)
     run(['/usr/bin/nmcli','device','set',name,'managed','no'])
     managed=run(['/usr/bin/nmcli','-g','GENERAL.NM-MANAGED','device','show',name]).stdout.decode().strip()
     if managed!='no':raise RuntimeError('Private interface still managed')
     run(['/usr/sbin/ip','link','set','dev',name,'down'])
     run(['/usr/sbin/ip','address','flush','dev',name])
     path=pathlib.Path('/proc/sys/net/ipv6/conf')/name/'disable_ipv6'
     if time.monotonic()>=end:raise RuntimeError('Private link setup deadline')
     row['disable_ipv6_before']=int(path.read_text());path.write_text('1');row['disable_ipv6_after']=int(path.read_text())
     if row['disable_ipv6_after']!=1:raise RuntimeError('Private IPv6 readback')
     run(['/usr/sbin/ip','link','set','dev',name,'up'])
     row['address_readback']=json.loads(run(['/usr/sbin/ip','-j','address','show','dev',name]).stdout)
     if len(row['address_readback'])!=1 or row['address_readback'][0].get('addr_info') or int((base/'ifindex').read_text())!=index or (base/'address').read_text().strip()!=expected:raise RuntimeError('Private link identity/address changed')
   target=pathlib.Path('/usr/local/bin/exp002-socket-probe')
   with target.open('xb') as out:out.write(raw)
   target.chmod(0o700);run(['/usr/sbin/restorecon',str(target)])
   result['socket_probe_pin']=pin
   if (root/'private-input.json').exists():
    from private_volume import read_guest
    meta=json.loads((root/'private-input.json').read_text());public_raw=(root/'public-identities.json').read_bytes()
    if hashlib.sha256(public_raw).hexdigest()!=meta['public_sha256'] or meta['vm']!=pin['role']:raise RuntimeError('Private input public binding')
    public=json.loads(public_raw);chosen='U' if pin['role']=='endpoint' else 'D'
    values=read_guest(meta['vm'],meta['run_nonce'],meta['public_sha256'],end)
    secret=values[chosen]+bytes.fromhex(public['roles'][chosen]['public_key'])
    if 'paired_input_sha256' in pin:
     paired=(root/'paired-input.bin').read_bytes()
     if len(paired)!=(104 if pin.get('paired_route') else 60) or hashlib.sha256(paired).hexdigest()!=pin['paired_input_sha256']:raise RuntimeError('Pairing metadata binding')
     secret+=paired
     if pin.get('paired_route') and pin['role']=='endpoint':secret+=values['E']+bytes.fromhex(public['roles']['E']['public_key'])
    values.clear()
    left=end-time.monotonic()
    if left<=0:raise RuntimeError('Private input admission deadline')
    if pin.get('preliminary'):
     from data_sync import guest_run
     if not nonce:raise RuntimeError('Missing barrier nonce')
     run(['/usr/bin/systemctl','stop','serial-getty@ttyS0.service'])
     if pin.get('stage_timing') or pin.get('route_timing'):
      if pin['role']!='dut':raise RuntimeError('trace scope')
      if pin.get('route_timing'):
       from route_capture import Capture
      else:
       from stage_capture import Capture
      trace_options={'global_guest':bool(pin.get('route_timing_owned_guest'))} if pin.get('route_timing') else {}
      trace_capture=Capture(nonce,result['private_links'][0]['ifindex'],end,close_end,**trace_options)
      result['route_timing' if pin.get('route_timing') else 'stage_timing']=trace_capture.result
      trace_capture.prepare()
     r=guest_run([str(target),pin['role']],secret,pin['role'],nonce,min(end,time.monotonic()+40),trace_capture)
    else:r=subprocess.run([str(target),pin['role']],input=secret,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(20,left))
    del secret
    result['commands'].append({'argv':[str(target),pin['role']],'rc':r.returncode,'stdout':r.stdout[:131072].decode(errors='replace'),'stderr':r.stderr[:131072].decode(errors='replace'),'at':time.monotonic(),'private_role':chosen})
    if r.returncode or len(r.stdout)>131072 or len(r.stderr)>131072 or time.monotonic()>=end:raise RuntimeError('Native M1 probe incomplete')
   else:r=run([str(target),pin['role']],output_cap=65536)
   result['socket_probe']=json.loads(r.stdout)
   expected_state=('PASS_ROUTE_SESSIONS_ONLY' if pin.get('paired_route') else 'PASS_PAIRED_SESSION_ONLY') if 'paired_input_sha256' in pin else 'PASS_SOCKET_FAMILY_ONLY'
   if result['socket_probe']['state']!=expected_state:raise RuntimeError('Socket/session qualification incomplete')
  if (root/'identity_probe.json').exists():
   pin=json.loads((root/'identity_probe.json').read_text());raw=(root/'identity_probe').read_bytes()
   if pin.get('real_lab_identity') is not False or len(raw)!=pin['bytes'] or len(raw)>2097152 or hashlib.sha256(raw).hexdigest()!=pin['sha256']:raise RuntimeError('Identity probe binding')
   target=pathlib.Path('/usr/local/bin/exp002-identity-probe')
   with target.open('xb') as out:out.write(raw)
   target.chmod(0o700);run(['/usr/sbin/restorecon',str(target)])
   # RFC8032 public fixture: NOT a credential, never installed as peer trust.
   fixture=bytes.fromhex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')
   left=end-time.monotonic()
   if left<=0:raise RuntimeError('Identity qualification deadline')
   r=subprocess.run([str(target)],input=fixture,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=min(20,left))
   result['identity_probe_raw']={'rc':r.returncode,'stdout':r.stdout[:1024].decode(errors='replace'),'stderr':r.stderr[:1024].decode(errors='replace'),'pin':pin,'before_remaining':left,'after':time.monotonic(),'real_lab_identity':False}
   if len(r.stdout)>1024 or len(r.stderr)>1024 or r.returncode or time.monotonic()>=end:raise RuntimeError('Guest identity qualification refused')
   value=json.loads(r.stdout)
   if value.get('public_key')!='d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a' or value.get('self_check') is not True or value.get('identity_suite')!=1:raise RuntimeError('Guest public fixture mismatch')
   result['identity_probe']=value
  result['state']='PASS_MODULE_LOAD_READBACK_ONLY'
 except Exception as e:
  result['primary']=str(e)
  # Bounded diagnostic tail from the owned guest, not another load attempt.
  try:
   with open('/var/log/audit/audit.log','rb') as audit:
    audit.seek(0,2);audit.seek(max(0,audit.tell()-8192));result['audit_tail']=audit.read(8192).decode(errors='replace')
  except OSError as error:result['audit_error']=str(error)
 finally:
  if trace_capture is not None:
   trace_capture.close()
   if trace_capture.result['primary'] or trace_capture.owned:result['secondary'].append('Trace capture/cleanup incomplete')
  for path,original,row in reversed(buffer_restore):
   try:
    if time.monotonic()>=close_end:raise RuntimeError('Buffer restore deadline')
    path.write_text(str(original));row['restored']=int(path.read_text())
    if row['restored']!=original or time.monotonic()>=close_end:raise RuntimeError('Buffer restore readback/deadline')
   except Exception as e:result['secondary'].append(str(e))
  for name in reversed(owned):
   try:run(['/usr/sbin/rmmod',name],True);result['unloaded'].append(name)
   except Exception as e:result['secondary'].append(str(e))
  if mounted:
   try:run(['/usr/bin/umount',str(root)],True)
   except Exception as e:result['secondary'].append(str(e))
  result['remaining_owned']=sorted(set(owned)&modules());result['tainted_after']=read('/proc/sys/kernel/tainted');result['elapsed_s']=time.monotonic()-start
  if result['primary'] or result['secondary'] or result['remaining_owned']:result['state']='INCOMPLETE'
 return result
