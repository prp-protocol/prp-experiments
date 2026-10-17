"""Offline transformation checks; not native access instrumentation."""
import contextlib
import io
import pathlib
import sys
import unittest
ROOT=pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'experiments/exp-002-none-forwarding/native-lab'))
import read_preliminary as reader
from presentation import comparison

class OnionTests(unittest.TestCase):
    def test_three_sizes_and_every_selected_sequence(self):
        for size in (256,512,1024):
            for index in range(128):
                a,b=reader.catalogue.packets(0,index,size)
                g=reader.onion_peel(a,b,index,size)
                self.assertEqual(g['preserved_bytes'],size+56)
                self.assertEqual(g['input_prp_bytes']-g['output_prp_bytes'],42)
                self.assertEqual(a[52:94],b[10:52])
                self.assertEqual(a[94:],b[52:])

    def test_mutated_ranges_truncation_and_wrong_sequence_refuse(self):
        a,b=reader.catalogue.packets(0,0)
        for side,original in enumerate((a,b)):
            for offset in (0,2,8,10,44,50,52,93,94,len(original)-1):
                changed=bytearray(original);changed[offset]^=1
                pair=[a,b];pair[side]=bytes(changed)
                with self.subTest(side=side,offset=offset),self.assertRaises(ValueError):
                    reader.onion_peel(*pair,0,1024)
        for pair in ((a,b[:-1]),(a[:-1],b),(a,a),(b,b),(a,reader.catalogue.packets(0,1)[1])):
            with self.assertRaises(ValueError):reader.onion_peel(*pair,0,1024)

    def test_presentation_separates_wire_proof_from_memory_access(self):
        a,b=reader.catalogue.packets(0,0)
        result=dict(state='PASS_PRELIMINARY_NATIVE_DELIVERY_COMPARISON',payload_bytes=1024,warmup=32,repetitions=1,
            runs=[],copy_over_reference_time=1,annex_verification=0,body_validation_timing='POST_MEASUREMENT',
            statistical_speedup=False,whole_stack_zero_copy=False,
            onion_peeling=dict(state='PASS_CAPTURED_ONION_PEEL',records=128,geometry=reader.onion_peel(a,b,0,1024)))
        with contextlib.redirect_stdout(io.StringIO()) as out:comparison(result,'fixture')
        self.assertIn('1,132 -> 1,090',out.getvalue())
        self.assertIn('1,080 child/annex bytes preserved',out.getvalue())
        self.assertIn('NOT ESTABLISHED',out.getvalue())
        del result['onion_peeling']
        with contextlib.redirect_stdout(io.StringIO()) as out:comparison(result,'old fixture')
        self.assertNotIn('ONION result:',out.getvalue())

    def test_witness_control_bound_and_native_output_equality(self):
        for size in (256,512,1024):
            a,b=reader.catalogue.packets(0,0,size)
            witness=reader.descriptor_witness(a,b)
            self.assertEqual(witness['control_read_intervals'],[[0,12],[44,52]])
            self.assertEqual(witness['control_bytes_read'],20)
            self.assertEqual(witness['annex_bytes_read_during_construction'],0)
            self.assertFalse(witness['kernel_read_count'])
            self.assertEqual(witness['routing_and_session_admission'],'EXTERNAL_PRECONDITION')
            with self.assertRaises(ValueError):reader.descriptor_witness(a,b[:-1])

    def test_witness_is_not_security_or_full_wire_acceptance(self):
        a,b=reader.catalogue.packets(0,0)
        a=a[:-1]+bytes([a[-1]^1]);b=b[:-1]+bytes([b[-1]^1])
        self.assertEqual(reader.descriptor_witness(a,b)['state'],'PASS_CONDITIONAL_REPRESENTATION')
        with self.assertRaises(ValueError):reader.onion_peel(a,b,0,1024)

    def test_scoped_copy_counts_both_modes_and_sizes(self):
        keys=('assembly_ingress_copied_bytes','assembly_direct_copied_bytes',
              'assembly_preparation_copied_bytes','assembly_carrier_accepted_copy_bytes')
        for size in (256,512,1024):
            for mode in (1,2):
                expected=(size+108,84,size+66 if mode==1 else 0,size+66)
                pre=dict.fromkeys(keys,17)
                post={k:17+64*v for k,v in zip(keys,expected)}
                result=reader.copy_stages(pre,post,64,size,mode)
                self.assertEqual(result['logical_copied_bytes_per_record'],
                                 3*size+324 if mode==1 else 2*size+258)
                self.assertFalse(result['all_cpu_reads_measured'])
                post[keys[0]]+=1
                with self.assertRaises(ValueError):reader.copy_stages(pre,post,64,size,mode)
                post[keys[0]]=16
                with self.assertRaises(ValueError):reader.copy_stages(pre,post,64,size,mode)
                del post[keys[0]]
                self.assertEqual(reader.copy_stages(pre,post,64,size,mode)['state'],'NOT_RECORDED')


    def test_console_distinguishes_model_and_accounted_native_copies(self):
        a,b=reader.catalogue.packets(0,0)
        keys=('assembly_ingress_copied_bytes','assembly_direct_copied_bytes',
              'assembly_preparation_copied_bytes','assembly_carrier_accepted_copy_bytes')
        result=dict(state='PASS_PRELIMINARY_NATIVE_DELIVERY_COMPARISON',payload_bytes=1024,warmup=32,repetitions=1,
            runs=[],copy_over_reference_time=1,annex_verification=0,body_validation_timing='POST_MEASUREMENT',
            statistical_speedup=False,whole_stack_zero_copy=False,
            onion_peeling=dict(state='PASS_CAPTURED_ONION_PEEL',records=128,geometry=reader.onion_peel(a,b,0,1024),
                              descriptor_witness=reader.descriptor_witness(a,b)))
        for mode in (1,2):
            pre=dict.fromkeys(keys,0);post=dict(zip(keys,(72448,5376,69760 if mode==1 else 0,69760)))
            result['runs'].append(dict(mode='COPY' if mode==1 else 'REFERENCE',verified_payload_bytes=32768,
                elapsed_ns=1000000,MiB_per_s=1,copy_stages=reader.copy_stages(pre,post,64,1024,mode),
                counters=dict(assembly_preparation_copied_bytes=post[keys[2]],assembly_vector_bytes=69760 if mode==2 else 0)))
        with contextlib.redirect_stdout(io.StringIO()) as out:comparison(result,'fixture')
        self.assertIn('NOT a native kernel access measurement',out.getvalue())
        self.assertIn('Ingress/carrier still copy whole units',out.getvalue())
        self.assertIn('external precondition',out.getvalue())
        del result['runs'][0]['copy_stages']
        with contextlib.redirect_stdout(io.StringIO()) as out:comparison(result,'fixture')
        self.assertIn('missing counters are not zero',out.getvalue())
        self.assertNotIn('Scoped logical copied bytes per',out.getvalue())
