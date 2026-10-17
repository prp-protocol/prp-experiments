"""Local installation removal; never follows links or deletes run directories."""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import stat
import time


@contextlib.contextmanager
def lifecycle(root):
    root = Path(root).absolute()
    if root.resolve() != root:
        raise ValueError('Symlinked installation container')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(root / '.lifecycle.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if os.fstat(fd).st_uid != os.geteuid():
            raise ValueError('Installation lock owner differs')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def remove(root):
    root = Path(root).absolute()
    files, directories = [], []
    retained = {}
    # Only these two installation-owned trees. Runs and external inputs are excluded.
    for name in ('installation', 'downloads'):
        tree = root / name
        if not os.path.lexists(tree):
            continue
        pending = [tree]
        while pending:
            p = pending.pop()
            s = p.lstat()
            if s.st_uid != os.geteuid() or p.resolve() != p:
                raise ValueError('Foreign owner or symlink: ' + str(p))
            if stat.S_ISDIR(s.st_mode):
                directories.append(p)
                pending.extend(p.iterdir())
            elif stat.S_ISREG(s.st_mode):
                files.append((p, (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)))
                if p.name in ('native-install.json', 'install-commands.json', 'download-receipt.json', 'receipt.json'):
                    if s.st_size > 4 * 1024**2 or sum(len(v) for v in retained.values()) + s.st_size > 16 * 1024**2:
                        raise ValueError('Installation evidence exceeds retention limit')
                    retained[str(p.relative_to(root))] = p.read_text()
            else:
                raise ValueError('Unsupported installation file: ' + str(p))
            if len(files) + len(directories) + len(pending) > 10000:
                raise ValueError('Installation inventory exceeds limit')
    # Preserve receipts before deletion. Exclusive receipt also preserves previous attempts.
    record = root / ('uninstall-' + str(time.time_ns()) + '.json')
    result = {'state': 'INCOMPLETE', 'removed': [], 'primary': None,
              'installation_evidence': retained, 'run_directories_untouched': True}
    with record.open('x') as out:
        json.dump(result, out, indent=2); out.flush()
        try:
            for p, ident in files:
                s = p.lstat()
                if not stat.S_ISREG(s.st_mode) or (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns) != ident:
                    raise ValueError('Installation changed during removal')
                p.unlink(); result['removed'].append(str(p.relative_to(root)))
            for p in sorted(directories, key=lambda x: len(x.parts), reverse=True):
                p.rmdir()
            result['state'] = 'INSTALLATION_REMOVED'
        except Exception as error:
            result['primary'] = type(error).__name__ + ': ' + str(error)
            raise
        finally:
            out.seek(0); json.dump(result, out, indent=2); out.truncate()
    return record, len(files)
