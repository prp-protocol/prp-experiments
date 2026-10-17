"""The ONLY identity artifact export: strict public manifest, never a tree walk."""
import json,os,pathlib,re,stat
FIELDS={'identity_suite','public_key','strong_id','provider','fips_default','self_check'}
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError('Duplicate public field')
  d[k]=v
 return d
def read(directory):
 p=pathlib.Path(directory)/'public.json';fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  before=os.fstat(fd)
  if not stat.S_ISREG(before.st_mode) or before.st_size>8192:raise ValueError('Public manifest size/type')
  raw=os.read(fd,8193);after=os.fstat(fd)
  if len(raw)!=before.st_size or before.st_size!=after.st_size or before.st_mtime_ns!=after.st_mtime_ns:raise ValueError('Changed public manifest')
 finally:os.close(fd)
 x=json.loads(raw,object_pairs_hook=unique)
 if set(x)!={'schema','run_nonce','state','roles','helper_sha256','target_qualified','native_used','secret_evidence_allowed'} or x['schema']!='EXP002-DISPOSABLE-IDENTITIES-1' or x['state']!='PRIVATE_PROVISIONING_COMPLETE_HOST_ONLY' or x['target_qualified'] is not False or x['native_used'] is not False or x['secret_evidence_allowed'] is not False:raise ValueError('Public schema')
 if not re.fullmatch('[0-9a-f]{32}',x['run_nonce']) or not re.fullmatch('[0-9a-f]{64}',x['helper_sha256']) or set(x['roles'])!={'U','D','E'}:raise ValueError('Public identity binding')
 for r in x['roles'].values():
  if set(r)!=FIELDS or type(r['identity_suite']) is not int or r['identity_suite']!=1 or r['self_check'] is not True or type(r['fips_default']) is not bool:raise ValueError('Role schema')
  if not re.fullmatch('[0-9a-f]{64}',r['public_key']) or not re.fullmatch('[0-9a-f]{64}',r['strong_id']) or not re.fullmatch('[A-Za-z0-9_-]{1,64}',r['provider']):raise ValueError('Public role fields')
 if len({r['public_key'] for r in x['roles'].values()})!=3 or len({r['strong_id'] for r in x['roles'].values()})!=3:raise ValueError('Duplicate roles')
 return raw
