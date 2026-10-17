import contextlib
import hashlib
import importlib.machinery
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import Mock, patch
import exp001
import public_entry

runner = importlib.machinery.SourceFileLoader('test_exp001_runner', str(exp001.ROOT/'tools/reproduce-exp-001')).load_module()
source = importlib.machinery.SourceFileLoader('test_exp001_source', str(exp001.EXP/'source_bundle.py')).load_module()

class Exp001Tests(unittest.TestCase):
    def test_public_source_complete_licensed_subset(self):
        manifest,files=source.verified_files()
        self.assertEqual(len(files),260)
        self.assertIn('debian/copyright',files)
        self.assertNotIn('internal', {n.split('/')[0] for n in files})
        self.assertTrue(all(not n.startswith('reference/') for n in files))
        self.assertEqual(manifest['commit'],runner.PIN)
        with tempfile.TemporaryDirectory() as d:
            source.extract(Path(d)/'source')
            self.assertEqual((Path(d)/'source/src/prp_app_v1_session.c').read_bytes(),files['src/prp_app_v1_session.c'])

    def test_modified_archive_refuses_before_extraction(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bad.gz';b=bytearray((source.HERE/'dependency/libprp-source.tar.gz').read_bytes());b[50]^=1;p.write_bytes(b)
            with self.assertRaisesRegex(ValueError,'binding'):source.extract(Path(d)/'out',p)
            self.assertFalse((Path(d)/'out').exists())

    def test_exp001_run_needs_no_vm_privilege_or_native_driver(self):
        mock=Mock(return_value=Mock(returncode=0))
        with patch.object(public_entry.os,'geteuid',return_value=1000),patch('host_tools.require',side_effect=AssertionError('VM tools')),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(public_entry.main('experiment',['run','exp-001','--directory','new run'],mock),0)
        self.assertIn('reproduce-exp-001',mock.call_args.args[0][1])
        self.assertEqual(mock.call_args.args[0][-2:],['--output','new run'])

    def test_install_has_no_download_or_experiment_effect(self):
        with patch.object(exp001.shutil,'which',return_value='/fixture/tool'),patch('release_download.fetch',side_effect=AssertionError('download')),contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(public_entry.main('install',['--experiment','exp-001']),0)
        self.assertIn('No system packages installed',output.getvalue())

    def test_missing_tool_refuses(self):
        with patch.object(exp001.shutil,'which',return_value=None),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError,'Missing host tools'):exp001.install([])

    def test_summary_not_json_or_performance_claim(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            runner.summary({'classification':'PASS'},'fixture')
        self.assertNotIn('"classification"',out.getvalue())
        self.assertIn('not a throughput',out.getvalue())
        self.assertIn('9 lifecycle',out.getvalue())

    def test_failed_summary_not_pass(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            runner.summary({'classification':'FAIL_REPOSITORY','error':'injected'},'fixture')
        self.assertNotIn('checks passed',out.getvalue())
        self.assertIn('injected',out.getvalue())

    def test_inventory_path_escape_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);(p/'inventory.json').write_text(json.dumps({'../outside':'0'*64}))
            with self.assertRaisesRegex(ValueError,'path'):runner.verify_evidence(p)

    def test_incomplete_inventory_cannot_claim_pass(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d);b=b'{"classification":"PASS"}';(p/'result.json').write_bytes(b)
            (p/'inventory.json').write_text(json.dumps({'result.json':hashlib.sha256(b).hexdigest()}))
            with self.assertRaisesRegex(ValueError,'Missing'):runner.verify_evidence(p)

    def test_optimized_oracle_refuses(self):
        with patch.object(runner.sys,'flags',Mock(optimize=1)):
            with self.assertRaisesRegex(RuntimeError,'without -O'):runner.validate_observations([], {})
