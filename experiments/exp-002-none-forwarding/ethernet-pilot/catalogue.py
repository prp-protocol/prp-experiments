"""Finite PRP-level byte catalogue. No Ethernet/socket/runtime authority."""
import hashlib
import struct

WARMUP, MEASURED = 32, 1024
ORDERS = ((1, 2), (2, 1), (2, 1), (1, 2))
PAYLOAD = bytes(range(256)) * 4

def direct(annex, branch, child=b''):
    return struct.pack('!H', 32) + hashlib.sha256(annex).digest() + struct.pack('!HIH', 1, branch, len(child)) + child

def unit(alias, layer, annex):
    body = struct.pack('!H', len(layer)) + layer + annex
    return struct.pack('!HHBBH', 1, alias, 2, 0, len(body)) + body

def payload(size):
    if type(size) is not int or size not in (256,512,1024):
        raise ValueError('diagnostic payload size')
    return bytes(range(256))*(size//256)

def packets(pair, index, payload_bytes=1024):
    if type(pair) is not int or type(index) is not int or not 0 <= pair < 4 or not 0 <= index < WARMUP + MEASURED:
        raise ValueError('pair/index')
    data = payload(payload_bytes)
    sequence = 30 + pair * (WARMUP + MEASURED) + index
    annex = struct.pack('!HHQH', 17, 3, sequence, len(data)) + data
    leaf = direct(annex, 0xffffffff)
    return unit(1, direct(annex, 100, leaf), annex), unit(2100, leaf, annex)

def decode(raw, pair, index, incoming, payload_bytes=1024):
    # Parse independently from the generator, with exact lengths and no trailing bytes.
    if (type(raw) is not bytes or type(incoming) is not bool or
        type(pair) is not int or type(index) is not int or
        not 0 <= pair < 4 or not 0 <= index < WARMUP + MEASURED):
        raise ValueError('type')
    data = payload(payload_bytes)
    if len(raw) < 10:
        raise ValueError('truncated header')
    count, alias, suite, flags, length, layer_len = struct.unpack_from('!HHBBHH', raw)
    if (count, alias, suite, flags, length) != (1, 1 if incoming else 2100, 2, 0, len(raw)-8):
        raise ValueError('record header')
    layer, annex = raw[10:10+layer_len], raw[10+layer_len:]
    if len(annex) != payload_bytes+14:
        raise ValueError('annex length')
    if struct.unpack_from('!HHQH', annex) != (17, 3, 30+pair*(WARMUP+MEASURED)+index, payload_bytes) or annex[14:] != data:
        raise ValueError('annex identity/bytes')
    def parse_layer(buf, capability, child_size):
        if len(buf) != 42+child_size or struct.unpack_from('!H', buf)[0] != 32:
            raise ValueError('direct size')
        if buf[2:34] != hashlib.sha256(annex).digest() or struct.unpack_from('!HIH', buf, 34) != (1, capability, child_size):
            raise ValueError('direct commitment/branch')
        return buf[42:]
    if incoming:
        child = parse_layer(layer, 100, 42)
        parse_layer(child, 0xffffffff, 0)
    else:
        parse_layer(layer, 0xffffffff, 0)
    return True

def catalogue():
    members=[]
    for pair, order in enumerate(ORDERS):
        inputs=hashlib.sha256();outputs=hashlib.sha256()
        for index in range(WARMUP+MEASURED):
            a,b=packets(pair,index);decode(a,pair,index,True);decode(b,pair,index,False)
            # Length-delimited hashes bind order and framing, not only concatenated values.
            inputs.update(struct.pack('!I',len(a))+a);outputs.update(struct.pack('!I',len(b))+b)
        for position, mode in enumerate(order):
            members.append(dict(slot=len(members),pair=pair,position=position,mode=mode,
                inputs_sha256=inputs.hexdigest(),outputs_sha256=outputs.hexdigest()))
    return dict(schema='exp002-ethernet-pilot-proposal-v1',runtime_ready=False,
        layer='PRP_RRL_ONLY_NOT_ETHERNET_OR_ADJACENT_ENVELOPE',members=members,
        warmup=WARMUP,measured=MEASURED,total_offers=8*(WARMUP+MEASURED),
        input_bytes=len(packets(0,0)[0]),output_bytes=len(packets(0,0)[1]),
        sequence_reuse_within_pair='REQUIRES_FRESH_BOUND_CONTEXT_PER_MEMBER')

if __name__=='__main__':
    import json
    print(json.dumps(catalogue(),indent=2,sort_keys=True))
