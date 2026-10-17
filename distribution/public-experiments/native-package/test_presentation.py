import contextlib
import io
import json
import unittest
from presentation import Events, comparison

class PresentationTests(unittest.TestCase):
    def test_progress_json_retained_console_human(self):
        raw,terminal=io.StringIO(),io.StringIO();stream=Events(raw,terminal)
        line=json.dumps({'event':'guest_observed','role':'dut','kernel':'fixture','elapsed_s':2.1})+'\n'
        stream.write(line[:10]);stream.write(line[10:]);stream.flush()
        self.assertEqual(raw.getvalue(),line)
        self.assertIn('Guest dut: kernel fixture observed',terminal.getvalue())
        self.assertNotIn('{',terminal.getvalue())

    def test_overlong_event_refuses(self):
        stream=Events(io.StringIO(),io.StringIO())
        with self.assertRaises(ValueError):stream.write('x'*65537)

    def test_comparison_retains_scope_and_numbers(self):
        runs=[{'mode':m,'verified_payload_bytes':32768,'elapsed_ns':n,'MiB_per_s':rate,'counters':{'assembly_preparation_copied_bytes':c,'assembly_vector_bytes':v}} for m,n,rate,c,v in [('COPY',16470315,1.8973529,69760,0),('REFERENCE',15973569,1.9563568,0,69760)]]
        result={'state':'PASS_PRELIMINARY_NATIVE_DELIVERY_COMPARISON','runs':runs,'payload_bytes':1024,'warmup':32,'repetitions':1,'copy_over_reference_time':1.0310979,'annex_verification':0,'body_validation_timing':'POST_MEASUREMENT','statistical_speedup':False,'whole_stack_zero_copy':False}
        with contextlib.redirect_stdout(io.StringIO()) as out:comparison(result,'fixture')
        for text in ('16.470','15.974','69,760','1.031','No statistical speedup','disabled','POST_MEASUREMENT','fixture'):
            self.assertIn(text,out.getvalue())
        self.assertNotIn('"state"',out.getvalue())
