"""Consumer mathematical witness for the selected single-target NONE projection.

This is not a PRP implementation, validator, kernel replacement or security gate.
Valid external session/route/lifetime/opaque-transit predicates are preconditions.
Only framing/control reads are counted here. Materializing segments is an offline
oracle operation and intentionally excluded from the descriptor construction.
"""
from dataclasses import dataclass
import struct

@dataclass(frozen=True)
class Projection:
    header: bytes
    child: tuple
    annex: tuple
    control_reads: tuple
    capability: int

    def segments(self, packet):
        # These views are an executable representation witness, not native DMA.
        v = memoryview(packet).toreadonly()
        return memoryview(self.header), v[slice(*self.child)], v[slice(*self.annex)]


def project(packet, egress_alias=2100):
    if type(packet) is not bytes or not 52 <= len(packet) <= 4096:
        raise ValueError('selected packet extent/type')
    if type(egress_alias) is not int or not 1 <= egress_alias <= 65535:
        raise ValueError('alias')
    reads=[]
    def number(at, size):
        if at < 0 or at+size > len(packet):
            raise ValueError('control extent')
        reads.extend(range(at,at+size))
        return int.from_bytes(packet[at:at+size], 'big')
    count,alias,kind,flags,body,layer = (number(0,2),number(2,2),number(4,1),
                                      number(5,1),number(6,2),number(8,2))
    if (count,alias,kind,flags)!=(1,1,2,0) or body!=len(packet)-8:
        raise ValueError('selected RRL framing')
    # kind2 is ONION, not evidence of session cipher suite0002.
    if number(10,2)!=32 or number(44,2)!=1:
        raise ValueError('selected commitment size/target count')
    capability,child_len=number(46,4),number(50,2)
    if capability!=100 or not child_len or layer!=42+child_len or 10+layer>len(packet):
        raise ValueError('selected target/child extent')
    child=(52,52+child_len);annex=(10+layer,len(packet))
    output_body=2+child_len+(annex[1]-annex[0])
    header=struct.pack('!HHBBHH',1,egress_alias,2,0,output_body,child_len)
    if any(i>=annex[0] for i in reads):
        raise AssertionError('opaque-body access in descriptor construction')
    return Projection(header,child,annex,tuple(reads),capability)
