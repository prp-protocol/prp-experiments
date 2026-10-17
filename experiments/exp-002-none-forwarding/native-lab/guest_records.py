"""Bounded serial receipt assembly. Missing/corrupt chunks are never repaired."""
import base64,hashlib,json
LIMIT=524288
PREFIX=b'EXP002_BOOT_CHUNK '

def decode(lines):
 legacy=[line.split(b'EXP002_BOOT_RESULT ',1)[1] for line in lines if b'EXP002_BOOT_RESULT ' in line]
 chunks=[line.split(PREFIX,1)[1] for line in lines if PREFIX in line]
 if legacy:
  if len(legacy)!=1 or chunks:raise ValueError('Duplicate/mixed guest record')
  return json.loads(legacy[0])
 if not chunks:return None
 if len(chunks)>512:raise ValueError('Guest chunk count cap')
 rows=[];binding=None;seen=set()
 for raw in chunks:
  if len(raw)>2048:raise ValueError('Guest chunk line cap')
  r=json.loads(raw)
  if set(r)!={'role','nonce','index','count','bytes','sha256','data'}:raise ValueError('Guest chunk shape')
  if any(type(r[k]) is not int for k in ('index','count','bytes')):raise ValueError('Guest chunk integer')
  if not 0<r['bytes']<=LIMIT or r['count']!=(r['bytes']+1023)//1024 or not 0<=r['index']<r['count']:raise ValueError('Guest chunk extent')
  if not all(type(r[k]) is str for k in ('role','nonce','sha256','data')):raise ValueError('Guest chunk strings')
  if len(r['sha256'])!=64:raise ValueError('Guest digest length')
  current=(r['role'],r['nonce'],r['count'],r['bytes'],r['sha256'])
  if binding is not None and binding!=current:raise ValueError('Foreign guest chunk')
  binding=current
  if r['index'] in seen or r['index']!=len(rows):raise ValueError('Duplicate/reordered guest chunk')
  seen.add(r['index']);body=base64.b64decode(r['data'],validate=True)
  if len(body)!=min(1024,r['bytes']-1024*r['index']):raise ValueError('Guest chunk length')
  rows.append(body)
 if len(rows)!=binding[2]:return None
 body=b''.join(rows)
 if hashlib.sha256(body).hexdigest()!=binding[4]:raise ValueError('Guest receipt digest')
 result=json.loads(body)
 if result['role']!=binding[0] or result['nonce']!=binding[1]:raise ValueError('Guest receipt binding')
 return result
