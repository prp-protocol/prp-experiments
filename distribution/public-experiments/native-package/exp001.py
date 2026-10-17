"""Public EXP-001 dispatch: no private checkout, VM, elevation or download."""
import argparse
import importlib.machinery
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[3]
EXP = ROOT/'experiments/exp-001-relationship-dataplane-separation'
DESCRIPTION = '''EXP-001: session setup and packet processing.
Two real libprp endpoints exchange authenticated encrypted packets in memory.
Native function-entry observations distinguish setup from receive-phase work.
This is not a performance benchmark. No VM, kernel module, network or sudo.
The exact licensed source subset is bundled; no artifact download is needed.'''


def install(argv):
    parser=argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--plan',action='store_true')
    args=parser.parse_args(argv)
    print(DESCRIPTION)
    print('Run compiles the instrumented library in a temporary directory, then removes the build.')
    print('Required: Linux, Python 3.12+, C/C++ compilers, Make, CMake 3.22+ and nm.')
    if args.plan:return 0
    if not sys.platform.startswith('linux') or sys.version_info < (3,12):
        raise ValueError('EXP-001 requires Linux and Python 3.12+')
    missing=[name for name in ('cc','c++','make','cmake','nm') if not shutil.which(name)]
    if missing:raise ValueError('Missing host tools: '+', '.join(missing))
    source=importlib.machinery.SourceFileLoader('exp001_public_source',str(EXP/'source_bundle.py')).load_module()
    manifest,files=source.verified_files()
    print(f"Source verified: {len(files)} files, {manifest['bytes']:,} compressed bytes.")
    print('No system packages installed. Ready to attempt: ./experiment run exp-001 --directory RUN')
    return 0


def run(argv,runner):
    parser=argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('--directory',required=True)
    args=parser.parse_args(argv)
    print(DESCRIPTION,flush=True)
    return runner([sys.executable,str(ROOT/'tools/reproduce-exp-001'),'--summary','--output',args.directory],check=False).returncode


def verify(directory,runner):
    return runner([sys.executable,str(ROOT/'tools/reproduce-exp-001'),'--summary','--verify',directory],check=False).returncode
