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
