"""Readable console output; full receipts remain machine-readable evidence."""
import json


def comparison(result, directory):
    if result['state']=='PASS_NATIVE_REFERENCE_FORWARDING':
        return reference_forwarding(result,directory)
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
        witness=peel.get('descriptor_witness')
        if witness and witness['state']=='PASS_CONDITIONAL_REPRESENTATION':
            print('Representation proof (offline): the captured output also equals a 10-byte')
            print('new header plus views of the preserved child/annex. Descriptor construction')
            print('reads 20 control bytes and no annex bytes, with routing/session admission')
            print('as an external precondition. This is NOT a native kernel access measurement.')
        print('Access-limit result: NOT ESTABLISHED for the complete native path.')
        print('Byte equality and copy counters do not show every CPU read. Current transport')
        print('may copy the body; routing-only CPU cost and device offload remain unmeasured.')
    print('Mode          Verified bytes     Elapsed (ms)       MiB/s')
    for row in result['runs']:
        print(f"{row['mode']:<13} {row['verified_payload_bytes']:>14,} {row['elapsed_ns']/1e6:>16.3f} {row['MiB_per_s']:>11.3f}")
    for row in result['runs']:
        c=row['counters']
        print(f"{row['mode']}: preparation copied {c['assembly_preparation_copied_bytes']:,} bytes; referenced {c['assembly_vector_bytes']:,} bytes.")
    stages=[row.get('copy_stages',{}) for row in result['runs']]
    if len(stages)==2 and all(s.get('state')=='PASS_SCOPED_COPY_ACCOUNTING' for s in stages):
        print('Scoped logical copied bytes per forwarded record (including warmup):')
        print('Mode             Ingress    DIRECT   Assembly   Carrier')
        for row in result['runs']:
            c=row['copy_stages']['bytes_per_record']
            print(f"{row['mode']:<13} {c['assembly_ingress_copied_bytes']:>10,} "
                  f"{c['assembly_direct_copied_bytes']:>9,} "
                  f"{c['assembly_preparation_copied_bytes']:>10,} "
                  f"{c['assembly_carrier_accepted_copy_bytes']:>9,}")
        print('Ingress/carrier still copy whole units in this implementation. These counters')
        print('are logical operations, not total CPU work, cache misses or DRAM traffic.')
    elif result['state'] in ('PASS_SCOPED_RX_TX_REFERENCES','COPY_FALLBACK_OBSERVED'):
        print('Explicit RX/TX reference qualification; logical copied bytes including warmup:')
        for row in result['runs']:
            print(row['mode']+': '+json.dumps(row['copy_stages']['deltas'],sort_keys=True))
        print('Zero means no copies in these four instrumented operations, not every layer.')
    else:
        print('Complete stage-copy accounting unavailable; missing counters are not zero.')
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
    elif result['state']=='PASS_SCOPED_RX_TX_REFERENCES':
        print('Conclusion: onion forwarding preserved delivery and avoided all four counted')
        print('copy operations in REFERENCE. This is a scoped software-path result.')
    elif result['state']=='COPY_FALLBACK_OBSERVED':
        print('Conclusion: delivery passed, but the enabled reference path still fell back')
        print('to copying. This is not a successful copy-elimination qualification.')
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
            elif event.get('event')=='guest_observed':message=f"Guest {role}: kernel {event['kernel']} observed after {event['elapsed_s']:.1f} s (startup elapsed time)."
            elif 'state' in event:message=f"Guest lifecycle: {event['state']}."
            else:message='Progress event saved to evidence.'
            self.terminal.write(message+'\n');self.terminal.flush()
        return len(text)
    def flush(self):
        self.evidence.flush();self.terminal.flush()


def reference_forwarding(result,directory):
    row=result['runs'][0];g=result['onion_peeling']['geometry']
    print('\nEXP-002 — Onion forwarding by references')
    print('Result: '+result['state'])
    print(f"Verified {result['onion_peeling']['records']} input/output frame pairs, including warmup.")
    print(f"One {g['removed_direct_bytes']}-byte DIRECT layer removed; {g['input_prp_bytes']} -> {g['output_prp_bytes']} PRP bytes.")
    print(f"The remaining {g['preserved_bytes']} child/annex bytes were preserved exactly.")
    print('Counted copies: ingress 0; DIRECT 0; preparation 0; carrier 0.')
    print('Kernel counters record logical bytes copied at four specific operations:')
    print('receiving the packet, peeling DIRECT, preparing output, and carrier submission.')
    print('Zero means these operations avoided copying; it does not count all memory reads.')
    print('Independent captured frames are compared byte for byte after measurement.')
    witness=result['onion_peeling'].get('descriptor_witness')
    if witness and witness['state']=='PASS_CONDITIONAL_REPRESENTATION':
        print('The offline descriptor witness reads 20 control bytes and references the body.')
        print('Those 20 bytes describe that witness, not measured kernel reads or routing CPU cost.')
    print('Conclusion: the tested aggregator forwarded and peeled the onion without')
    print('the four instrumented PRP copy operations. No COPY treatment is executed.')
    print(f"Descriptive measurement: {row['verified_payload_bytes']} useful bytes in {row['elapsed_ns']/1e6:.3f} ms.")
    print('This does not measure all CPU reads, physical memory traffic or NIC offload.')
    print('No relative speedup is claimed. Annex checking is disabled; bytes are validated after measurement.')
    print('Evidence: '+str(directory))
