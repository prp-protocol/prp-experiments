"""Build own consumer, dynamic target-compatible public ABI; no target execution."""
import hashlib,json,pathlib,subprocess,sys
h=pathlib.Path(__file__).resolve().parent;s=h.parent/'signer-adapter';e=h.parent/'ethernet-pilot';o=pathlib.Path(sys.argv[1]);o.mkdir(parents=True,exist_ok=True)
src=[h/x for x in ('socket_probe.c','suite_query.c','carrier_query.c','receipt_store.c','m1_query.c','control_capture.c','captured_m1.c','session_query.c','fanout_query.c','peer_path.c','paired_query.c','route_query.c','absence_query.c','pair_plan.c')]+[s/(x+'.c') for x in ('transaction','readback','reservations','netlink_socket','reserved_netlink','file_store','native_prepare','session_flow','fanout_flow','signer','local_client','provider_backend')]+[e/'socket_owner.c',e/'socket_identity.c']+[s/'public-blake3'/x for x in ('blake3.c','blake3_dispatch.c','blake3_portable.c')]
cmd=['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-ffunction-sections','-fdata-sections','-Wl,--gc-sections','-DSUITE_QUERY','-DCARRIER_QUERY','-DM1_QUERY','-DBLAKE3_NO_SSE2','-DBLAKE3_NO_SSE41','-DBLAKE3_NO_AVX2','-DBLAKE3_NO_AVX512','-DBLAKE3_USE_NEON=0','-I'+str(s),'-I'+str(e),*map(str,src),'-lcrypto','-o',str(o/'socket_probe')]
args=sys.argv[2:];payload=1024
if '--payload-bytes' in args:
 at=args.index('--payload-bytes')
 if at+1>=len(args):raise SystemExit('Missing payload size')
 payload=int(args[at+1]);del args[at:at+2]
 if payload not in (256,512,1024):raise SystemExit('Unsupported diagnostic payload size')
reference_only='--reference-only' in args
if reference_only:args.remove('--reference-only');cmd[1:1]=['-DPD_REFERENCE_ONLY']
filtered='--prp-capture' in args
if filtered:args.remove('--prp-capture')
opaque='--opaque-transit' in args
if opaque:args.remove('--opaque-transit')
warmed='--warmed' in args
if warmed:args.remove('--warmed')
if reference_only and (args!=['--preliminary'] or not (warmed and opaque and filtered)):raise SystemExit('Reference-only requires warmed opaque preliminary profile')
if args not in ([],['--preliminary'],['--preliminary-reverse']):raise SystemExit('Unknown build profile')
if args in (['--preliminary'],['--preliminary-reverse']):
 extra=[h/'preliminary_data.c']+[e/x for x in ('member_catalogue.c','member_prepare.c','wire_adapter.c','socket_backend.c','payload_ledger.c')]
 if args==['--preliminary-reverse']:cmd[1:1]=['-DPD_REVERSE=1']
 src+=extra;cmd[1:1]=['-DPRELIMINARY_DATA','-DPILOT_FLOW'];cmd[cmd.index('-lcrypto'):cmd.index('-lcrypto')]=list(map(str,extra))
if payload!=1024 and not (opaque and warmed and filtered and args):raise SystemExit('Size sweep requires opaque warmed filtered preliminary profile')
cmd[1:1]=['-DEP_EXPERIMENT_PAYLOAD='+str(payload)]
src.append(h/'preliminary_profile.h') # compile-time phase/record selection
src.append(e/'payload_geometry.h') # provenance only; not a separate compiler input
if opaque:
 if not warmed or not filtered:raise SystemExit('Opaque transit requires warmed filtered profile')
 cmd[1:1]=['-DPD_VERIFY_ANNEX=0','-DPD_POST_VERIFY']
if warmed:
 if not args or not filtered:raise SystemExit('Warmed profile requires filtered preliminary mode')
 extra=h/'raw_export.c';src.append(extra);cmd[1:1]=['-DPD_WARMED'];cmd.insert(cmd.index('-lcrypto'),str(extra));cmd.insert(cmd.index('-lcrypto'),'-lz')
if filtered:
 if not args:raise SystemExit('Capture filter requires preliminary profile')
 extra=e/'packet_filter.c';src.append(extra);cmd[1:1]=['-DEXP002_PRP_CAPTURE'];cmd.insert(cmd.index('-lcrypto'),str(extra))
r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);(o/'build.json').write_text(json.dumps({'command':cmd,'exit':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'pins':{str(x):hashlib.sha256(x.read_bytes()).hexdigest() for x in src}},indent=2)+'\n');assert r.returncode==0,r.stderr
v=subprocess.run(['readelf','--dyn-syms','--wide',str(o/'socket_probe')],capture_output=True,text=True,timeout=20)
(o/'imports.txt').write_text(v.stdout+v.stderr);assert v.returncode==0
import re
versions=[tuple(map(int,x.split('.'))) for x in re.findall(r'@GLIBC_([0-9.]+)',v.stdout)]
assert versions and max(versions)<=(2,34),'Target Rocky glibc symbol version exceeded'
print(hashlib.sha256((o/'socket_probe').read_bytes()).hexdigest())
