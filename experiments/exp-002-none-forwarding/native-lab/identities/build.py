import hashlib,json,pathlib,subprocess,sys
here=pathlib.Path(__file__).resolve().parent;b=here.parents[1]/'signer-adapter/public-blake3';out=pathlib.Path(sys.argv[1]);out.mkdir(parents=True,exist_ok=True)
cmd=['cc','-std=c11','-O2','-Wall','-Wextra','-Werror','-DBLAKE3_NO_SSE2','-DBLAKE3_NO_SSE41','-DBLAKE3_NO_AVX2','-DBLAKE3_NO_AVX512','-DBLAKE3_USE_NEON=0','-I'+str(b),str(here/'public_identity.c')]+[str(b/n) for n in ('blake3.c','blake3_dispatch.c','blake3_portable.c')]+['-lcrypto','-o',str(out/'public_identity')]
if len(sys.argv)>2 and sys.argv[2]=='--san':cmd[1:1]=['-fsanitize=address,undefined','-fno-omit-frame-pointer','-fno-pie','-no-pie']
if '--guest' in sys.argv[2:]:cmd[1:1]=['-DEXP_GUEST_QUALIFICATION']
r=subprocess.run(cmd,capture_output=True,text=True,timeout=60);(out/'build.json').write_text(json.dumps(dict(command=cmd,exit=r.returncode,stdout=r.stdout,stderr=r.stderr),indent=2));assert not r.returncode,r.stderr
print(hashlib.sha256((out/'public_identity').read_bytes()).hexdigest())
