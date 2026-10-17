#!/usr/bin/env python3
"""Repair CRLF-only checkout changes; refuse modified files before any write."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile


def repair(root):
    root = Path(root).resolve()
    manifest = root / 'RELEASE.json'
    if manifest.is_symlink() or manifest.stat().st_size > 262144:
        raise ValueError('Invalid release manifest')
    records = json.loads(manifest.read_text())['files']
    if len(records) > 256:
        raise ValueError('Release population exceeds bound')
    pending = []
    seen = set()
    total = 0
    for row in records:
        rel = Path(row['path'])
        if rel.is_absolute() or '..' in rel.parts or not rel.parts or rel in seen:
            raise ValueError('Invalid or duplicate release path')
        seen.add(rel)
        p = root / rel
        if p.resolve() != p or p.is_symlink() or not p.is_file():
            raise ValueError('Not a regular unlinked release file: ' + str(rel))
        if p.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('Oversized release file')
        b = p.read_bytes()
        total += len(b)
        if total > 16 * 1024 * 1024:
            raise ValueError('Release bytes exceed bound')
        if hashlib.sha256(b).hexdigest() == row['sha256'] and len(b) == row['bytes']:
            continue
        fixed = b.replace(b'\r\n', b'\n')
        if len(fixed) != row['bytes'] or hashlib.sha256(fixed).hexdigest() != row['sha256']:
            raise ValueError('Local edits or unexpected bytes; no files changed: ' + str(rel))
        pending.append((p, b, fixed, stat.S_IMODE(p.stat().st_mode)))
    for p, old, fixed, mode in pending:
        if p.read_bytes() != old:
            raise ValueError('File changed during repair: ' + str(p.relative_to(root)))
        fd, name = tempfile.mkstemp(prefix='.lf-repair-', dir=p.parent)
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(fixed)
                os.fchmod(f.fileno(), mode)
            os.replace(name, p)
        finally:
            if os.path.exists(name):
                os.unlink(name)
    return [str(p.relative_to(root)) for p, _, _, _ in pending]


if __name__ == '__main__':
    try:
        names = repair(Path(__file__).parent)
        print('Verified release bytes; normalized ' + str(len(names)) + ' CRLF files.')
        for name in names:
            print(name)
        print('Installation, downloaded artifacts and run directories were not touched.')
    except Exception as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
