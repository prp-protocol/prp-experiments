import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import Mock, patch
import full_cycle as c


def completed(root):
    def put(name,value):
        p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value))
    put('exp001/result.json',{'classification':'PASS','experiment':'EXP-001'})
    put('exp002/run.json',{'state':'PASS_FRESH_NATIVE_DELIVERY','primary':None})
    put('exp002/cleanup.json',{'state':'OWN_DISPOSABLE_FILES_REMOVED','primary':None})
    put('exp002/native/receipt.json',{'guests':{r:{'pid':p,'reaped':True,'terminal':[p,signal.SIGCHLD,os.CLD_EXITED,0,os.getuid()]} for r,p in [('dut',101),('endpoint',102)]}})
    put('installation/native-install.json',{'schema':'exp002-native-install-1','base':str(root/'downloads/image.qcow2'),'artifacts':str(root/'downloads')})
    (root/'downloads').mkdir();(root/'downloads/image.qcow2').write_bytes(b'fixture image')
    os.link(root/'downloads/image.qcow2',root/'downloads/cache-image')


class FullCycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.parent=Path(self.tmp.name)
        self.root=self.parent/'.prp-cycle-fixture';self.root.mkdir(mode=0o700)
        self.out=io.StringIO();self.err=io.StringIO()
        a=contextlib.redirect_stdout(self.out);a.__enter__();self.addCleanup(a.__exit__,None,None,None)
        b=contextlib.redirect_stderr(self.err);b.__enter__();self.addCleanup(b.__exit__,None,None,None)

    def operations(self, fail_at=None, make=True):
        calls=[]
        def record(*args):
            calls.append(args)
            if len(calls)==fail_at:return 7
            if len(calls)==6 and make:completed(self.root)
            return 0
        return calls,Mock(run=record,verify=record),record

    def test_complete_cycle_deletes_only_new_tree(self):
        old=self.parent/'.exp002';old.mkdir();(old/'old-evidence').write_bytes(b'keep')
        prior=self.parent/'run-001';prior.mkdir();(prior/'result.json').write_bytes(b'keep')
        calls,first,entry=self.operations()
        self.assertEqual(c.perform(self.root,first=first,entry=entry),0)
        self.assertEqual(len(calls),6);self.assertFalse(self.root.exists())
        self.assertEqual((old/'old-evidence').read_bytes(),b'keep')
        self.assertEqual((prior/'result.json').read_bytes(),b'keep')
        self.assertIn('files and evidence were removed',self.out.getvalue())
        self.assertIn(str(self.root/'installation'),calls[2][1])
        self.assertIn(str(self.root/'downloads'),calls[2][1])
        self.assertIn(str(self.root/'installation'),calls[3][1])

    def test_each_failed_stage_stops_without_retry_or_purge(self):
        for position in range(1,7):
            with self.subTest(position=position):
                calls,first,entry=self.operations(position);remove=Mock()
                self.assertEqual(c.perform(self.root,first=first,entry=entry,remover=remove),1)
                remove.assert_not_called();self.assertEqual(len(calls),position)
                record=json.loads((self.root/'cycle.json').read_text())
                self.assertEqual(record['state'],'INCOMPLETE');self.assertIn('exit 7',record['primary'])

    def test_success_exits_without_evidence_cannot_delete(self):
        calls,first,entry=self.operations(make=False)
        self.assertEqual(c.perform(self.root,first=first,entry=entry),1)
        self.assertTrue(self.root.exists())
        self.assertNotIn('PASS: EXP-001 and EXP-002 verified',self.out.getvalue())

    def test_unknown_guest_retains_all_evidence_and_image(self):
        completed(self.root)
        p=self.root/'exp002/native/receipt.json';r=json.loads(p.read_text());r['guests']['dut']['reaped']=False;p.write_text(json.dumps(r))
        with self.assertRaises(ValueError):c.purge(self.root,c.identity(self.root))
        self.assertTrue((self.root/'downloads/image.qcow2').exists())
        self.assertTrue((self.root/'exp001/result.json').exists())

    def test_external_base_binding_refuses(self):
        completed(self.root)
        p=self.root/'installation/native-install.json';r=json.loads(p.read_text());r['base']='/unrelated/base';p.write_text(json.dumps(r))
        with self.assertRaisesRegex(ValueError,'exclusively own'):c.purge(self.root,c.identity(self.root))
        self.assertTrue((self.root/'downloads/image.qcow2').exists())

    def test_symlink_refuses_before_any_deletion(self):
        completed(self.root);(self.root/'link').symlink_to(self.parent)
        with self.assertRaises(ValueError):c.purge(self.root,c.identity(self.root))
        self.assertTrue((self.root/'downloads/image.qcow2').exists())

    def test_changed_directory_identity_refuses(self):
        completed(self.root);before=c.identity(self.root);renamed=self.parent/'retained';self.root.rename(renamed);self.root.mkdir(mode=0o700)
        with self.assertRaises(ValueError):c.purge(self.root,before)
        self.assertTrue((renamed/'downloads/image.qcow2').exists())

    def test_failed_removal_is_incomplete_preserves_primary(self):
        calls,first,entry=self.operations()
        self.assertEqual(c.perform(self.root,first=first,entry=entry,remover=Mock(side_effect=OSError('injected removal failure'))),1)
        self.assertIn('injected removal failure',json.loads((self.root/'cycle.json').read_text())['primary'])
        self.assertTrue((self.root/'downloads/image.qcow2').exists())

    def test_secondary_receipt_error_does_not_replace_primary(self):
        calls,first,entry=self.operations()
        original=Path.write_text
        def write(p,*args,**kwargs):
            if '"primary": "RuntimeError:' in args[0]:raise OSError('receipt failure')
            return original(p,*args,**kwargs)
        first.run=Mock(side_effect=RuntimeError('first failure'))
        with patch.object(Path,'write_text',write):
            self.assertEqual(c.perform(self.root,first=first,entry=entry),1)
        self.assertIn('first failure',self.err.getvalue());self.assertIn('Secondary receipt error',self.err.getvalue())

    def test_nonroot_fails_without_directory_or_elevation(self):
        with patch.object(c.os,'geteuid',return_value=1000),patch.object(c,'ROOT',self.parent),patch.object(c,'perform') as perform:
            self.assertEqual(c.main([]),1);perform.assert_not_called()
        self.assertIn('sudo ./run',self.err.getvalue())

    def test_concurrent_cycle_refuses_without_side_effects(self):
        (self.parent/'run').write_text('fixture')
        with (self.parent/'run').open() as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with patch.object(c.os,'geteuid',return_value=0),patch.object(c,'ROOT',self.parent),patch.object(c.host_tools,'require') as require:
                self.assertEqual(c.main([]),1);require.assert_not_called()

    def test_main_preflight_then_owned_cycle(self):
        (self.parent/'run').write_text('fixture');before=os.environ.get('PYTHONDONTWRITEBYTECODE')
        def success(root):
            self.assertEqual(root.parent,self.parent);self.assertTrue(root.name.startswith('.prp-cycle-'))
            self.assertEqual(os.environ['PYTHONDONTWRITEBYTECODE'],'1')
            root.rmdir();return 0
        with patch.object(c.os,'geteuid',return_value=0),patch.object(c,'ROOT',self.parent),patch.object(c.host_tools,'require'),patch.object(c.os,'access',return_value=True),patch.object(c.Path,'exists',return_value=True),patch.object(c.exp001,'install',return_value=0),patch.object(c.public_entry,'commands',return_value=c.argparse.Namespace()),patch.object(c,'perform',side_effect=success) as perform:
            self.assertEqual(c.main([]),0);perform.assert_called_once()
        self.assertEqual(os.environ.get('PYTHONDONTWRITEBYTECODE'),before)

    def test_partial_unlink_failure_never_claims_full_removal(self):
        calls,first,entry=self.operations();original=Path.unlink;removed=[]
        def unlink(path,*args,**kwargs):
            if len(removed)==1:raise OSError('injected second unlink failure')
            original(path,*args,**kwargs);removed.append(str(path))
        with patch.object(Path,'unlink',unlink):
            self.assertEqual(c.perform(self.root,first=first,entry=entry),1)
        self.assertEqual(len(removed),1)
        self.assertTrue((self.root/'exp001/result.json').exists())
        result=json.loads((self.root/'cycle.json').read_text())
        self.assertIn('second unlink failure',result['primary'])
        self.assertEqual(result['state'],'INCOMPLETE')
        self.assertNotIn('PASS: EXP-001 and EXP-002 verified',self.out.getvalue())

    def test_missing_native_devices_refuses_before_workspace(self):
        (self.parent/'run').write_text('fixture')
        with patch.object(c.os,'geteuid',return_value=0),patch.object(c,'ROOT',self.parent),patch.object(c.host_tools,'require'),patch.object(c.os,'access',return_value=False),patch.object(c.tempfile,'mkdtemp') as create,patch.object(c.exp001,'install') as install:
            self.assertEqual(c.main([]),1);create.assert_not_called();install.assert_not_called()
