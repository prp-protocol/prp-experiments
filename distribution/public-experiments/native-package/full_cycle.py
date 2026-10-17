"""Finite composition of existing public commands in one exclusively owned tree."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

import cleanup
import exp001
import host_tools
import public_entry

ROOT = Path(__file__).resolve().parents[3]


def identity(path):
    s=path.lstat()
    return (s.st_dev,s.st_ino,s.st_uid,stat.S_IFMT(s.st_mode))


def read_record(path):
    if path.is_symlink() or path.stat().st_size>4*1024**2:
        raise ValueError('Invalid cycle receipt: '+str(path))
    return json.loads(path.read_text())


def completion(root):
    """Exit status alone cannot authorize evidence/base deletion."""
    first=read_record(root/'exp001/result.json')
    second=read_record(root/'exp002/run.json')
    clean=read_record(root/'exp002/cleanup.json')
    if (first.get('classification')!='PASS' or first.get('experiment')!='EXP-001'
            or second.get('state')!='PASS_FRESH_NATIVE_DELIVERY' or second.get('primary') is not None
            or clean.get('state')!='OWN_DISPOSABLE_FILES_REMOVED' or clean.get('primary') is not None):
        raise ValueError('Both verified experiments and cleanup must have succeeded')
    guests=cleanup.settled(root/'exp002')['guests']
    if any(g['terminal'][2]!=os.CLD_EXITED or g['terminal'][3]!=0 for g in guests.values()):
        raise ValueError('Guest termination was not successful')
    installed=read_record(root/'installation/native-install.json')
    if (installed.get('schema')!='exp002-native-install-1'
            or installed.get('base')!=str(root/'downloads/image.qcow2')
            or installed.get('artifacts')!=str(root/'downloads')):
        raise ValueError('Cycle does not exclusively own its selected base')


def purge(root, expected):
    """Remove only the new cycle tree, never pre-existing runs/installations."""
    root=Path(root)
    if (identity(root)!=expected or root.resolve()!=root or not root.name.startswith('.prp-cycle-')
            or root.stat().st_uid!=os.geteuid() or root.stat().st_mode&0o077):
        raise ValueError('Cycle directory identity changed')
    completion(root)
    files=[];directories=[];pending=[root]
    while pending:
        p=pending.pop();s=p.lstat()
        if p.resolve()!=p or s.st_uid!=os.geteuid() or s.st_dev!=expected[0]:
            raise ValueError('Foreign path, owner or filesystem in cycle')
        if stat.S_ISDIR(s.st_mode):
            directories.append((p,identity(p)));pending.extend(p.iterdir())
        elif stat.S_ISREG(s.st_mode):
            files.append((p,identity(p)+(s.st_size,s.st_mtime_ns)))
        else:raise ValueError('Unsupported cycle entry: '+str(p))
        if len(files)+len(directories)+len(pending)>10000:
            raise ValueError('Cycle inventory limit exceeded')
    # Large installation files first; diagnostic receipts last. Unlink, not erase.
    files.sort(key=lambda item: (item[0].suffix in ('.json','.jsonl','.txt','.log'),item[0].name=='cycle.json'))
    for p,expected_file in files:
        s=p.lstat()
        if p.resolve()!=p or identity(p)+(s.st_size,s.st_mtime_ns)!=expected_file:
            raise ValueError('Cycle file changed before removal')
        p.unlink()
    for p,expected_dir in sorted(directories,key=lambda item:len(item[0].parts),reverse=True):
        if p.resolve()!=p or identity(p)!=expected_dir:raise ValueError('Cycle directory changed before removal')
        p.rmdir()


def perform(root, *, entry=public_entry._main, first=exp001, remover=purge):
    """All operations use the new root; no default-installation locks are bypassed."""
    expected=identity(root)
    receipt={'state':'INCOMPLETE','stages':[],'primary':None,'secondary':[],
             'evidence_policy':'REMOVE_THIS_CYCLE_ONLY_AFTER_BOTH_VERIFIED_AND_SETTLED'}
    def save():
        # Local failure receipt, not a power-loss durability claim.
        if root.resolve()!=root or identity(root)!=expected:
            raise ValueError('Cycle ownership changed before receipt write')
        (root/'cycle.json').write_text(json.dumps(receipt,indent=2)+'\n')
    def stage(name, operation):
        print('\n'+name,flush=True)
        receipt['stages'].append({'name':name,'state':'STARTED'});save()
        rc=operation()
        if rc!=0:raise RuntimeError(f'{name} failed (exit {rc}); no automatic retry')
        receipt['stages'][-1]['state']='COMPLETED';save()
    try:
        save()
        stage('[1/7] Run EXP-001',lambda:first.run(['--directory',str(root/'exp001')],public_entry.subprocess.run))
        stage('[2/7] Verify EXP-001',lambda:first.verify(str(root/'exp001'),public_entry.subprocess.run))
        stage('[3/7] Prepare EXP-002',lambda:entry('install',['--directory',str(root/'installation'),'--download-directory',str(root/'downloads')]))
        stage('[4/7] Run EXP-002',lambda:entry('experiment',['run','--installation',str(root/'installation'),'--directory',str(root/'exp002')]))
        stage('[5/7] Verify EXP-002',lambda:entry('experiment',['verify',str(root/'exp002')]))
        stage('[6/7] Retire EXP-002 disposable files',lambda:entry('experiment',['clean',str(root/'exp002')]))
        print('\n[7/7] Remove this successful cycle, including downloads and evidence',flush=True)
        receipt['stages'].append({'name':'[7/7] Remove successful cycle','state':'STARTED'})
        receipt['state']='VERIFIED_PENDING_REMOVAL';save()
        remover(root,expected)
        print('\nPASS: EXP-001 and EXP-002 verified. This cycle\'s files and evidence were removed.')
        print('No new installation/cache remains. Existing runs and installations were not changed.')
        print('The summaries above remain in your terminal; a later rerun will download the base again.')
        return 0
    except (Exception,KeyboardInterrupt) as error:
        receipt['state']='INCOMPLETE';receipt['primary']=type(error).__name__+': '+str(error)
        try:
            if root.exists():save()
        except Exception as secondary:receipt['secondary'].append(type(secondary).__name__+': '+str(secondary))
        print('\nINCOMPLETE: '+receipt['primary'],file=sys.stderr)
        print('Remaining files preserved for diagnosis: '+str(root),file=sys.stderr)
        for secondary in receipt['secondary']:print('Secondary receipt error: '+secondary,file=sys.stderr)
        return 1


def main(argv=None):
    parser=argparse.ArgumentParser(description='Run both experiments; verify and remove this cycle on success. Failures retain evidence.')
    parser.parse_args(sys.argv[1:] if argv is None else argv)
    fd=None
    try:
        if os.geteuid()!=0:raise ValueError('Use sudo ./run: EXP-002 requires isolated namespace/TAP/vhost privileges')
        # Hold the existing entrypoint inode: no persistent lock/cache is created.
        fd=os.open(ROOT/'run',os.O_RDONLY|os.O_NOFOLLOW)
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        print('Complete cycle: EXP-001 + EXP-002, verification, then removal of all files created by this cycle.',flush=True)
        print('Failures retain diagnostic evidence. Existing installation/run directories remain untouched.',flush=True)
        print('EXP-002 downloads about 1.67 GB; two guests use 4 GiB RAM plus host overhead.',flush=True)
        print('Host packages must already be installed; no automatic package installation or privilege elevation.',flush=True)
        host_tools.require('install')
        if not os.access('/dev/kvm',os.R_OK|os.W_OK) or not Path('/dev/net/tun').exists() or not Path('/dev/vhost-net').exists():
            raise ValueError('KVM and isolated TAP/vhost devices are required; no download or VM started')
        first=exp001.install([])
        if first!=0:raise ValueError('EXP-001 prerequisites failed')
        selected=public_entry.commands('install',[])
        if not isinstance(selected,argparse.Namespace):raise ValueError('Pinned public download defaults required')
        root=Path(tempfile.mkdtemp(prefix='.prp-cycle-',dir=ROOT)).absolute()
        print('Temporary cycle directory: '+str(root),flush=True)
        # Children inherit this setting and do not leave new __pycache__ trees in the checkout.
        previous=os.environ.get('PYTHONDONTWRITEBYTECODE');os.environ['PYTHONDONTWRITEBYTECODE']='1'
        try:return perform(root)
        finally:
            if previous is None:os.environ.pop('PYTHONDONTWRITEBYTECODE',None)
            else:os.environ['PYTHONDONTWRITEBYTECODE']=previous
    except Exception as error:
        print('INCOMPLETE: '+str(error),file=sys.stderr);return 1
    finally:
        if fd is not None:os.close(fd)
