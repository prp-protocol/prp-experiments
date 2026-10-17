"""Explanatory frontend to the existing native driver; no implicit elevation."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DESCRIPTION = '''EXP-002 compares COPY and REFERENCE forwarding with the NONE suite.
COPY prepares a copied output body; REFERENCE reuses the selected body ranges.
The receiver checks useful bytes after measurement. This tests the opportunity
for offloading; it does not demonstrate NIC hardware acceleration or promise speedup.
Two isolated guests use one read-only base and two disposable thin overlays.
Each guest needs 2 GiB RAM and one vCPU, plus host overhead. Each overlay can grow
to 10 GiB. Runtime is bounded by the existing 600-second attempt schedule.
'''


def commands(kind, argv):
    parser = argparse.ArgumentParser(description=DESCRIPTION,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    if kind == 'install':
        parser.add_argument('--plan', action='store_true', help='Explain actions only (optional)')
        parser.add_argument('--release', default=str(ROOT / 'release/native-assets.json'))
        parser.add_argument('--release-sha256', help='Independently trusted exact release manifest digest')
        parser.add_argument('--artifacts', default=str(ROOT / 'artifacts'))
        parser.add_argument('--base', default=str(ROOT / 'artifacts/image.qcow2'))
        parser.add_argument('--directory', default=str(ROOT / '.exp002/installation'))
        parser.add_argument('--downloads', help='Pinned HTTPS artifact manifest')
        parser.add_argument('--downloads-sha256', help='Trusted download manifest digest')
        parser.add_argument('--download-seconds', type=float, help='Total installation download deadline')
        parser.add_argument('--download-directory', default=str(ROOT / '.exp002/downloads'))
        a = parser.parse_args(argv)
        if a.plan:
            return None
        defaults = ROOT / 'release/defaults.json'
        explicit = any(x.split('=', 1)[0] in {'--release', '--release-sha256', '--artifacts', '--base', '--downloads', '--downloads-sha256'} for x in argv)
        if defaults.is_file() and not explicit:
            raw = defaults.read_bytes()
            if len(raw) > 4096:
                raise ValueError('Release defaults too large')
            from release_download import deployment
            selected = json.loads(raw, object_pairs_hook=deployment.unique)
            if (set(selected) != {'version', 'release_sha256', 'downloads_sha256'}
                    or selected['version'] != '1.0.0'
                    or not deployment.digest(selected['release_sha256'])
                    or not deployment.digest(selected['downloads_sha256'])):
                raise ValueError('Invalid bundled release defaults')
            a.release_sha256 = selected['release_sha256']
            a.downloads = str(ROOT / 'release/downloads.json')
            a.downloads_sha256 = selected['downloads_sha256']
            if a.download_seconds is None:
                a.download_seconds = 1800.0
        if not a.release_sha256:
            raise ValueError('A trusted --release-sha256 is required. No native release digest is bundled yet.')
        if a.downloads:
            if not a.downloads_sha256 or a.download_seconds is None:
                raise ValueError('Download digest and total timeout required')
            from release_download import read_plan
            read_plan(a.downloads, a.downloads_sha256, a.release, a.release_sha256)
            return a
        if a.downloads_sha256 or a.download_seconds is not None:
            raise ValueError('--downloads is required for download options')
        if not Path(a.release).is_file() or not Path(a.base).is_file() or not Path(a.artifacts).is_dir():
            raise ValueError('Selected local release, module directory and read-only image are required. '
                             'This candidate has no cleared native download URLs; no download was attempted.')
        return ['install', '--release', a.release, '--release-sha256', a.release_sha256,
                '--artifacts', a.artifacts, '--base', a.base, '--directory', a.directory]
    subs = parser.add_subparsers(dest='action', required=True)
    subs.add_parser('explain', help='Explain the experiment and resources; no effects')
    run = subs.add_parser('run', help='Start a new isolated two-guest attempt')
    run.add_argument('--installation', default=str(ROOT / '.exp002/installation'))
    run.add_argument('--directory', required=True, help='New private output directory, never reused')
    for action in ('verify', 'clean'):
        sub = subs.add_parser(action)
        sub.add_argument('directory', help='Existing run directory')
    a = parser.parse_args(argv)
    if a.action == 'explain':
        return None
    if a.action == 'run':
        return ['run', '--installation', a.installation, '--directory', a.directory]
    return [a.action, a.directory]


def main(kind, argv=None, runner=subprocess.run):
    try:
        args = commands(kind, sys.argv[1:] if argv is None else argv)
        print(DESCRIPTION, flush=True)
        if args is None:
            print('Install compiles consumer helpers and verifies local artifacts; it starts no VM.\n'
                  'Run creates isolated networking and disposable guest identities.\n'
                  'Verify reads retained evidence. Clean removes only inventoried disposable files\n'
                  'after observed guest termination/reap, preserving evidence and the shared base.\n'
                  'No automatic package installation, privilege elevation or artifact publication.\n'
                  'Independent clean-host qualification is pending; installation and execution report actual outcomes.')
            return 0
        if isinstance(args, argparse.Namespace):
            if os.geteuid() != 0:
                raise ValueError('Install/run must use the same root owner; no automatic sudo')
            if os.path.lexists(args.directory) or os.path.lexists(args.download_directory):
                raise ValueError('Installation/download destination exists; no retry')
            from release_download import fetch
            print('Downloading eight exact pinned files over HTTPS; no redirects/retries. No VM starts.', flush=True)
            Path(args.download_directory).absolute().parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            base, artifacts = fetch(args.downloads, args.downloads_sha256, args.release,
                                    args.release_sha256, args.download_directory, args.download_seconds)
            args = ['install','--release',args.release,'--release-sha256',args.release_sha256,
                    '--artifacts',str(artifacts),'--base',str(base),'--directory',args.directory]
        if args[0] in ('install', 'run'):
            if os.geteuid() != 0:
                raise ValueError('This release requires install and run under root on a '
                                 'dedicated supported Linux host (isolated namespace/TAP/vhost). '
                                 'It never invokes sudo or changes host permissions automatically.')
            # Parent creation occurs only after CLI validation and explicit action.
            # The native driver exclusively creates the leaf; never reuse a failed installation/run.
            destination = Path(args[args.index('--directory') + 1]).absolute()
            if os.path.lexists(destination):
                raise ValueError('Destination already exists; no implicit retry or overwrite')
            if args[0] == 'install':
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            print('Installation verifies and compiles only; run is a separate command.' if args[0] == 'install'
                  else 'Starting a fresh local attempt; receipts will distinguish incomplete delivery.', flush=True)
        return runner([sys.executable, str(HERE / 'native'), *args], check=False).returncode
    except Exception as error:
        print('INCOMPLETE: ' + str(error), file=sys.stderr)
        return 1
