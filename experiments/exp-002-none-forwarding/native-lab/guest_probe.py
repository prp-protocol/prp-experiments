#!/usr/bin/python3
"""Read-only native guest qualification; no modules, keys or experiment traffic."""
import base64,hashlib,json,os,pathlib,platform,sys,time,uuid
guest_started=time.monotonic()
role,nonce=sys.argv[1:3]
def read(p):
 try:return pathlib.Path(p).read_text().strip()
 except OSError as e:return {'error':str(e)}
nics=[]
for p in sorted(pathlib.Path('/sys/class/net').iterdir()):
 if p.name=='lo':continue
 nics.append({'name':p.name,'mac':read(p/'address'),'ifindex':read(p/'ifindex'),'state':read(p/'operstate'),'mtu':read(p/'mtu')})
result={'schema':'EXP002-NATIVE-BOOT-1','role':role,'nonce':nonce,'kernel':platform.release(),'os_release':read('/etc/os-release'),
 'boot_id':read('/proc/sys/kernel/random/boot_id'),'netns':os.stat('/proc/self/ns/net').st_ino,
 'uptime':read('/proc/uptime'),'monotonic_ns':time.monotonic_ns(),'interfaces':nics,
 'lockdown':read('/sys/kernel/security/lockdown'),'module_sig_enforce':read('/sys/module/module/parameters/sig_enforce'),
 'crypto_policy':read('/etc/crypto-policies/config'),'fips_enabled':read('/proc/sys/crypto/fips_enabled'),
 'probe_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'module_loaded_by_probe':False,'traffic_sent_by_probe':False}
if len(sys.argv)>3 and sys.argv[3]=='modules':
 from module_smoke import exercise
 result['module_smoke']=exercise(nonce);result['module_loaded_by_probe']=bool(result['module_smoke']['loaded'])
 result['traffic_sent_by_probe']=any(x.get('m1',{}).get('public_control_submitted',False) for x in result['module_smoke'].get('socket_probe',{}).get('carrier',{}).get('operations',[]))
if 'private-input-fixture' in sys.argv[3:]:
 from private_volume import read_guest,ROLES
 try:
  values=read_guest(role,uuid.UUID(nonce).hex,hashlib.sha256(b'EXP002-PUBLIC-TRANSPORT-FIXTURE-1').hexdigest(),guest_started+360)
  if values!={r:r.encode()*32 for r in ROLES[role]}:raise ValueError('Private fixture differs')
  values.clear()
  result['private_input_fixture']={'state':'PASS_PUBLIC_PRIVATE_CHANNEL_FIXTURE','roles':list(ROLES[role]),'read_only':True,'real_lab_identity':False,'bytes':4096}
 except Exception:
  # Never serialize exception operands from a future secret-bearing reader.
  result['private_input_fixture']={'state':'INCOMPLETE','error':'PRIVATE_INPUT_REFUSED','real_lab_identity':False}
# Keep each console line below2048bytes. Large unframed JSON was split by the
# native serial path in attempt10; no guessing/reassembly of that failed record.
body=json.dumps(result,sort_keys=True,separators=(',',':')).encode()
if len(body)>524288:raise RuntimeError('Guest result exceeds existing receipt reservation')
pin=hashlib.sha256(body).hexdigest();count=(len(body)+1023)//1024
for index in range(count):
 chunk={'role':role,'nonce':nonce,'index':index,'count':count,'bytes':len(body),'sha256':pin,'data':base64.b64encode(body[index*1024:(index+1)*1024]).decode()}
 print('EXP002_BOOT_CHUNK '+json.dumps(chunk,separators=(',',':')),flush=True)
