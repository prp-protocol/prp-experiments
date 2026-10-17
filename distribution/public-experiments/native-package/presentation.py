"""Readable console output; full receipts remain machine-readable evidence."""
import json


def comparison(result, directory):
    print('\nEXP-002 — COPY and REFERENCE forwarding')
    print('Result: '+result['state'])
    print(f"Payload: {result['payload_bytes']} bytes; warmup: {result['warmup']}; repetitions: {result['repetitions']}.")
    peel=result.get('onion_peeling')
    if peel and peel['state']=='PASS_CAPTURED_ONION_PEEL':
        geometry=peel['geometry']
        print('ONION result: one 42-byte DIRECT layer removed between the two interfaces.')
        print(f"Verified {peel['records']} input/output frame pairs, including warmup.")
        print(f"PRP unit: {geometry['input_prp_bytes']:,} -> {geometry['output_prp_bytes']:,} bytes; "
              f"{geometry['preserved_bytes']:,} child/annex bytes preserved exactly.")
        print('The forwarding alias/framing changes; the remaining child and annex are unchanged.')
        print('Access-limit result: NOT ESTABLISHED for the complete native path.')
        print('Byte equality and copy counters do not show every CPU read. Current transport')
        print('may copy the body; routing-only CPU cost and device offload remain unmeasured.')
    print('Mode          Verified bytes     Elapsed (ms)       MiB/s')
    for row in result['runs']:
        print(f"{row['mode']:<13} {row['verified_payload_bytes']:>14,} {row['elapsed_ns']/1e6:>16.3f} {row['MiB_per_s']:>11.3f}")
    for row in result['runs']:
        c=row['counters']
        print(f"{row['mode']}: preparation copied {c['assembly_preparation_copied_bytes']:,} bytes; referenced {c['assembly_vector_bytes']:,} bytes.")
    print(f"COPY/REFERENCE elapsed-time ratio: {result['copy_over_reference_time']:.3f}.")
    print('Annex verification: '+('enabled' if result['annex_verification'] else 'disabled')+
          '; body validation: '+result['body_validation_timing']+'.')
    modes={row['mode']:row for row in result['runs']}
    copy=modes.get('COPY'); reference=modes.get('REFERENCE')
    if (result['state']=='PASS_PRELIMINARY_NATIVE_DELIVERY_COMPARISON' and copy and reference
            and copy['verified_payload_bytes']==reference['verified_payload_bytes']>0
            and copy['counters']['assembly_preparation_copied_bytes']>0
            and reference['counters']['assembly_preparation_copied_bytes']==0
            and reference['counters']['assembly_vector_bytes']>0):
        print('Conclusion: both modes delivered the verified payload. REFERENCE avoided')
        print('the body copy in forwarding preparation by referencing existing byte ranges.')
        print('This demonstrates an opportunity to offload that preparation step, not actual')
        print('NIC offload, reduced total CPU work, or elimination of all packet copies.')
        relation=('slower than' if reference['elapsed_ns']>copy['elapsed_ns'] else
                  'faster than' if reference['elapsed_ns']<copy['elapsed_ns'] else 'as fast as')
        print('In this measurement, REFERENCE was '+relation+' COPY; this alone does not establish a performance advantage.')
    else:
        print('Conclusion: these results do not establish copy-free forwarding preparation.')
    if not result['statistical_speedup']:print('No statistical speedup established.')
    if not result['whole_stack_zero_copy']:print('This does not establish whole-stack zero-copy or hardware offload.')
    print('Evidence: '+str(directory))


class Events:
    """Line-sized progress only; preserve original JSON without a subprocess pipe."""
    def __init__(self, evidence, terminal):
        self.evidence=evidence; self.terminal=terminal; self.pending=''
    def write(self, text):
        if len(self.pending)+len(text)>65536:raise ValueError('Progress line too large')
        self.evidence.write(text);self.evidence.flush()
        self.pending+=text
        while '\n' in self.pending:
            line,self.pending=self.pending.split('\n',1)
            if not line:continue
            try: event=json.loads(line)
            except ValueError:
                self.terminal.write(line+'\n');continue
            role=event.get('role','guest')
            if event.get('event')=='held_child': message=f'Guest {role}: process created.'
            elif event.get('event')=='qmp_ready': message=f'Guest {role}: management channel ready.'
            elif event.get('event')=='guest_observed':message=f"Guest {role}: kernel {event['kernel']} observed after {event['elapsed_s']:.1f} s."
            elif 'state' in event:message=f"Guest lifecycle: {event['state']}."
            else:message='Progress event saved to evidence.'
            self.terminal.write(message+'\n');self.terminal.flush()
        return len(text)
    def flush(self):
        self.evidence.flush();self.terminal.flush()
