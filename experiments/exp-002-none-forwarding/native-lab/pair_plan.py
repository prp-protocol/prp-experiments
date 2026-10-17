"""Public pairing record: launcher-owned MACs and pinned public identity only."""
import re

def encode(role, local, remote, key):
    if role not in ('endpoint', 'dut'):
        raise ValueError('Unknown paired role')
    def mac(value):
        if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', value):
            raise ValueError('Canonical MAC required')
        b = bytes.fromhex(value.replace(':', ''))
        if not any(b) or b[0] & 1:
            raise ValueError('Unicast MAC required')
        return b
    own, peer = mac(local), mac(remote)
    if own == peer or not isinstance(key, str) or not re.fullmatch(r'[0-9a-f]{64}', key):
        raise ValueError('Independent distinct endpoint/key required')
    pub = bytes.fromhex(key)
    if not any(pub):
        raise ValueError('Empty public identity')
    return b'EXP2HS01' + bytes([2 if role == 'endpoint' else 1, 0, 0, 0]) + (1).to_bytes(4, 'big') + own + peer + pub

def encode_route(role, local, remote, local_second, remote_second, key, key_second):
    first = encode(role, local, remote, key)
    second = encode(role, local_second, remote_second, key_second)
    addresses = [first[16:22], first[22:28], second[16:22], second[22:28]]
    if len(set(addresses)) != 4:
        raise ValueError('Four distinct independently supplied MACs required')
    return b'EXP2HS02' + first[8:28] + second[16:28] + first[28:] + second[28:]
