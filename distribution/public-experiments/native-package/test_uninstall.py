import json
import os
from pathlib import Path
import tempfile
import unittest
from uninstall import lifecycle, remove


class UninstallTests(unittest.TestCase):
    def test_remove_payload_preserve_runs_and_receipts(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'downloads').mkdir(); (root/'installation').mkdir()
            (root/'downloads/image.qcow2').write_bytes(b'base')
            os.link(root/'downloads/image.qcow2', root/'downloads/cache-image')
            (root/'installation/native-install.json').write_text('{"fixture":true}')
            (root/'run-001').mkdir(); (root/'run-001/evidence').write_text('retained')
            with lifecycle(root):
                receipt, count = remove(root)
            self.assertEqual(count, 3)
            self.assertFalse((root/'downloads').exists())
            self.assertFalse((root/'installation').exists())
            self.assertEqual((root/'run-001/evidence').read_text(), 'retained')
            result = json.loads(receipt.read_text())
            self.assertEqual(result['state'], 'INSTALLATION_REMOVED')
            self.assertEqual(result['installation_evidence']['installation/native-install.json'], '{"fixture":true}')

    def test_symlink_refuses_before_deletion(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'downloads').mkdir()
            (root/'downloads/base').write_bytes(b'keep')
            (root/'downloads/link').symlink_to(root/'downloads/base')
            with self.assertRaises(ValueError): remove(root)
            self.assertEqual((root/'downloads/base').read_bytes(), b'keep')

    def test_active_frontend_blocks_uninstall(self):
        with tempfile.TemporaryDirectory() as d:
            with lifecycle(d):
                with self.assertRaises(BlockingIOError):
                    with lifecycle(d): self.fail('lock admitted')

    def test_empty_install_is_explicit_noop(self):
        with tempfile.TemporaryDirectory() as d:
            receipt, count = remove(d)
            self.assertEqual(count, 0)
            self.assertEqual(json.loads(receipt.read_text())['state'], 'INSTALLATION_REMOVED')

    def test_partial_failure_has_receipt(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'downloads').mkdir(); (root/'downloads/base').write_bytes(b'keep')
            with patch.object(Path, 'unlink', side_effect=OSError('injected')):
                with self.assertRaises(OSError): remove(root)
            result = json.loads(next(root.glob('uninstall-*.json')).read_text())
            self.assertEqual(result['state'], 'INCOMPLETE')
            self.assertIn('injected', result['primary'])
            self.assertTrue((root/'downloads/base').exists())

    def test_frontend_uninstall_summary(self):
        import contextlib, io
        from unittest.mock import patch, Mock
        import public_entry
        with tempfile.TemporaryDirectory() as d, patch.object(public_entry, 'ROOT', Path(d)):
            root = Path(d)/'.exp002'; (root/'downloads').mkdir(parents=True)
            (root/'downloads/base').write_bytes(b'fixture')
            output = io.StringIO(); runner = Mock()
            with contextlib.redirect_stdout(output):
                rc = public_entry.main('experiment', ['uninstall'], runner)
            self.assertEqual(rc, 0); runner.assert_not_called()
            self.assertIn('Installation removed: 1 files', output.getvalue())
            self.assertNotIn('"state"', output.getvalue())
            self.assertFalse((root/'downloads').exists())
