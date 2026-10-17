"""Check executable prerequisites without executing tools or changing the host."""
import os
from pathlib import Path
import shutil


def require(action):
    if action not in ('install', 'run'):
        raise ValueError('Unknown prerequisite phase')
    names = ['qemu-img', 'genisoimage']
    if action == 'install':
        names += ['cc', 'readelf']
    missing = [name for name in names if shutil.which(name) is None]
    # boot_pair opens this exact executable, not an arbitrary PATH replacement.
    qemu = Path('/usr/bin/qemu-system-x86_64')
    if not qemu.is_file() or not os.access(qemu, os.X_OK):
        missing.append(str(qemu))
    if missing:
        raise ValueError('Missing host tools: ' + ', '.join(missing) +
                         '. Install the required host packages first; no download or VM started. '
                         'On Ubuntu/Debian, genisoimage is supplied by package genisoimage. '
                         'No automatic package installation is performed.')
