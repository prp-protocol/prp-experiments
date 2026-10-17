"""Independent full-byte reader for the small native comparison, not B8448."""
import base64,hashlib,json,pathlib,struct,sys,zlib
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent.parent/'ethernet-pilot'))
import catalogue

def need(ok,reason):
 if not ok:raise ValueError(reason)
def find(value,key):
 result=[]
 if isinstance(value,dict):
  if key in value:result.append(value[key])
  for v in value.values():result.extend(find(v,key))
 elif isinstance(value,list):
  for v in value:result.extend(find(v,key))
 return result
def counters(encoded):
 raw=bytes.fromhex(encoded);need(len(raw)<8192,'counter bound');out={}
 for line in raw.decode('ascii').splitlines():
  fields=line.replace(':',' ').split()
  if len(fields)==2 and fields[1].isdigit():
   need(fields[0] not in out,'counter duplicate');out[fields[0]]=int(fields[1])
 return out

def raw_rows(row):
 if 'raw_codec' not in row:return row['raw']
 need(row['raw_codec']=='zlib-records-v1' and row['raw']==[] and row['export_error']==0,'packed export status')
 encoded=row['packed_raw'];need(isinstance(encoded,str) and len(encoded)<=38232,'packed bound')
 packed=base64.b64decode(encoded,validate=True)
 need(len(packed)<=28672 and base64.b64encode(packed).decode()==encoded,'packed canonical')
 limit=512*(2+64+1168)
 codec=zlib.decompressobj();data=codec.decompress(packed,limit+1)
 need(len(data)<=limit and codec.eof and not codec.unused_data and not codec.unconsumed_tail,'compressed stream extent')
 rows=[];at=0
 while at<len(data):
  need(len(rows)<512 and at+66<=len(data),'record header extent')
  n=int.from_bytes(data[at:at+2],'big');need(n<=1168 and at+66+n<=len(data),'record body extent')
  rows.append([data[at+2:at+66].hex(),base64.b64encode(data[at+66:at+66+n]).decode()]);at+=66+n
 need(type(row['raw_count']) is int and row['raw_count']==len(rows),'record count')
 return rows

def verify(receipt):
 need(not receipt['primary'] and not receipt['secondary'],'run/cleanup failed')
 g=receipt['guests'];need(set(g)=={'endpoint','dut'},'two guests')
 for role,v in g.items():
  need(v['reaped'] and v['terminal'][3]==0,'QEMU unsettled')
  need(v['observation']['nonce']==v['nonce'],'boot nonce')
  smoke=v['observation']['module_smoke'];need(smoke['state']=='PASS_MODULE_LOAD_READBACK_ONLY' and not smoke['remaining_owned'],'guest cleanup')
 endpoint=g['endpoint']['observation']['module_smoke']['socket_probe'];dut=g['dut']['observation']['module_smoke']['socket_probe']
 selected={}
 for role,probe in [('endpoint',endpoint),('dut',dut)]:
  rows=find(probe,'preliminary');need(len(rows)==1,'one selected data result');selected[role]=rows[0]
  need(not rows[0]['primary'] and not rows[0]['final_error'] ,'data failure/count')
  need((rows[0].get('warmup_records',0),rows[0]['records_per_mode']) in ((0,2),(32,32)),'fixed profile')
  schema=rows[0]['schema'];need(schema in ('EXP002-SHORT-DATA-1','EXP002-SHORT-DATA-2'),'schema')
  order=[1,2] if schema=='EXP002-SHORT-DATA-1' else rows[0]['order']
  need(order in ([1,2],[2,1]) and all(type(x) is int for x in order),'declared mode order')
  need([x['mode'] for x in rows[0]['runs']]==order,'mode order')
  need(all(not x['primary'] for x in rows[0]['runs']),'phase failure')
  need(not probe['primary'] and not probe['cleanup_error'],'socket cleanup')
 e,d=selected['endpoint'],selected['dut']
 size=e['payload_bytes'];need(type(size) is int and size in (256,512,1024) and d['payload_bytes']==size,'payload geometry binding')
 if size!=1024:need(e.get('warmup_records')==32 and e.get('requested_annex_verification')==0 and e.get('capture_policy')=='PRP_ETHERTYPE_LOCKED_V1','diagnostic size profile')
 need(e['runs'][0]['last_receive_ns']<e['runs'][1]['begin_ns'],'phase chronology')
 order=[x['mode'] for x in e['runs']]
 need([x['mode'] for x in d['runs']]==order,'cross-guest mode order')
 annex=e.get('requested_annex_verification',1)
 need(type(annex) is int and annex in (0,1) and d.get('requested_annex_verification',1)==annex,'annex policy binding')
 timing=e.get('body_validation_timing','IN_LOOP')
 need(timing in ('IN_LOOP','POST_MEASUREMENT') and d.get('body_validation_timing','IN_LOOP')==timing,'validation timing binding')
 if annex==0:need(timing=='POST_MEASUREMENT' and e.get('warmup_records')==32,'opaque benchmark profile')
 capture=e.get('capture_policy','ALL_ETHERNET')
 need(capture in ('ALL_ETHERNET','PRP_ETHERTYPE_LOCKED_V1') and d.get('capture_policy','ALL_ETHERNET')==capture,'capture selection')
 need((e.get('warmup_records',0),e['records_per_mode'])==(d.get('warmup_records',0),d['records_per_mode']),'cross-guest profile')
 warmup=e.get('warmup_records',0);measured=e['records_per_mode'];per_mode=warmup+measured;total=2*per_mode
 raw=raw_rows(e);need(len(raw)==total*4,'complete custody')
 mac=lambda s:bytes.fromhex(s.replace(':',''))
 local=[mac(x) for x in g['endpoint']['macs']];remote=[mac(x) for x in g['dut']['macs']]
 sockets={x['slot']:x for x in endpoint['sockets']};family=next(x['family'] for x in endpoint['resolutions'] if x['slot']==2 and x['name']=='prp_session')
 records={}
 for encoded_h,encoded_b in raw:
  h=bytes.fromhex(encoded_h)
  encoding=e.get('raw_body_encoding','hex');need(encoding in ('hex','base64'),'body encoding')
  need(len(encoded_b)<=4096,'encoded body bound')
  b=base64.b64decode(encoded_b,validate=True) if encoding=='base64' else bytes.fromhex(encoded_b)
  if encoding=='base64':need(base64.b64encode(b).decode()==encoded_b,'canonical body encoding')
  need(len(h)==64,'header length')
  lane=h[0];flags,index,kept,result,before,after,error,alen=struct.unpack_from('!IHHqQQiI',h,1)
  need(lane in (1,2,3,4) and 0<=index<total and (index,lane) not in records,'lane/index/duplicate')
  need(not flags and not error and not any(h[61:]) and 0<before<=after,'raw success/time')
  need(kept==len(b)==result==(size+144,36,size+80,size+122)[lane-1],'raw extent')
  records[index,lane]=dict(body=b,before=before,after=after,address=h[41:61],alen=alen)
 sequences=[];peers=set()
 for i in range(total):
  tx,ack,rx,ing=(records[i,l] for l in (1,2,3,4));a,b=catalogue.packets(0,i,size)
  need(tx['body'][36:]==a and catalogue.decode(tx['body'][36:],0,i,True,size),'input oracle')
  n,t,f,seq,port=struct.unpack_from('<IHHII',tx['body']);need((n,t,f,port)==(size+144,family,5,sockets[2]['binding']),'request context');sequences.append(seq)
  need(tx['body'][16:20]==bytes((19,1,0,0)),'AOP_TX')
  na,attr,peer,nb,bodyattr=struct.unpack_from('<HHQHH',tx['body'],20);need((na,attr,nb,bodyattr)==(12,23,size+112,32) and peer>0,'request attrs');peers.add(peer)
  need(struct.unpack_from('<IHHIIi',ack['body']) in [(36,2,f,seq,port,0) for f in (0,256)] and ack['body'][20:]==tx['body'][:16],'ACK echo')
  for lane,r,src,dst,ix,kind,payload in [(4,ing,local[0],remote[0],sockets[0]['binding'],4,a),(3,rx,remote[1],local[1],sockets[1]['binding'],0,b)]:
   need(r['body']==dst+src+b'\x88\xfb'+payload,'complete Ethernet/PRP/payload oracle')
   family_a,proto,ifindex,hatype,ptype,halen,addr=struct.unpack('<HHiHBB8s',r['address'])
   need(r['alen']==20 and family_a==17 and ifindex==ix and ptype==kind and halen==6 and addr[:6]==src,'capture endpoint')
  need(tx['after']<=ack['before']<=ack['after']<=ing['before']<=ing['after']<=rx['before']<=rx['after'],'operation chronology')
  need(rx['after']-tx['before']<40000000,'response deadline')
 need(sequences==list(range(sequences[0],sequences[0]+total)) and len(peers)==1,'sequence/peer continuity')
 results=[]
 for position,mode in enumerate(order):
  row=e['runs'][position];state=d['runs'][position];pre=counters(state['before']);post=counters(state['after'])
  need(row['received']==measured and row['verified_bytes']==measured*size,'equal delivered volume')
  begin,end=row['begin_ns'],row['last_receive_ns'];need(0<begin<end,'measurement interval')
  first=position*per_mode+warmup;need(begin<=records[first,1]['before'] and records[first+measured-1,3]['after']<=end,'measurement brackets')
  if warmup:need(records[first-1,3]['after']<=begin,'warmup before measurement')
  for k,v in [('assembly_mode',mode),('assembly_records',1),('assembly_delay_ms',100),('verify_annex',annex)]:need(pre.get(k)==v and post.get(k)==v,'applied profile '+k)
  names=['assembly_preparation_copied_bytes','assembly_vector_bytes','assembly_submitted_bytes','assembly_errors','assembly_dropped_records','assembly_allocation_failures']
  need(all(k in pre and k in post and post[k]>=pre[k] for k in names),'counter presence/monotonicity')
  delta={k:post[k]-pre[k] for k in names}
  need(delta['assembly_preparation_copied_bytes']==(per_mode*(size+66) if mode==1 else 0) and delta['assembly_vector_bytes']==(per_mode*(size+66) if mode==2 else 0),'preparation path counters')
  need(delta['assembly_submitted_bytes']==per_mode*(size+66) and not any(delta[k] for k in names[3:]),'submitted/errors counters')
  if annex==0:
   names_annex=['checks','checked_bytes','bypasses','bypassed_bytes','forced_checks','mismatches','hash_errors']
   need(all(k in pre and k in post and post[k]>=pre[k] for k in names_annex),'annex counter custody')
   actual={k:post[k]-pre[k] for k in names_annex}
   need(actual==dict(checks=0,checked_bytes=0,bypasses=per_mode,bypassed_bytes=per_mode*(size+14),forced_checks=0,mismatches=0,hash_errors=0),'effective opaque transit')
   delta.update(actual)
  results.append(dict(mode='COPY' if mode==1 else 'REFERENCE',verified_payload_bytes=measured*size,elapsed_ns=end-begin,microseconds=(end-begin)/1000,MiB_per_s=measured*size*1e9/(end-begin)/1048576,counters=delta))
 results.sort(key=lambda x:x['mode'])
 return dict(state='PASS_PRELIMINARY_NATIVE_DELIVERY_COMPARISON',payload_bytes=size,capture_policy=capture,annex_verification=annex,body_validation_timing=timing,order=order,runs=results,copy_over_reference_time=results[0]['elapsed_ns']/results[1]['elapsed_ns'],warmup=warmup,repetitions=1,statistical_speedup=False,whole_stack_zero_copy=False)
if __name__=='__main__':
 raw=pathlib.Path(sys.argv[1]).read_bytes();r=json.loads(raw)
 try:result=verify(r)
 except Exception as e:result={'state':'INCOMPLETE','reason':str(e)}
 result['receipt_sha256']=hashlib.sha256(raw).hexdigest()
 print(json.dumps(result,indent=2));raise SystemExit(0 if result['state'].startswith('PASS_') else 1)
