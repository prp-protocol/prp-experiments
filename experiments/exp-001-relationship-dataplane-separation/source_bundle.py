"""Verify the exact finite source subset before extraction or compilation."""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile

HERE = Path(__file__).resolve().parent
PIN = 'b0d68882b37045231325843ac23f035f4ff901a2'

def verified_files(archive=None):
    manifest_path = HERE/'dependency/libprp-source.json'
    if manifest_path.stat().st_size > 256*1024: raise ValueError('Source manifest size')
    manifest = json.loads(manifest_path.read_text())
    path = Path(archive) if archive else HERE/'dependency/libprp-source.tar.gz'
    if path.stat().st_size != manifest['bytes'] or not 0 < manifest['bytes'] <= 4*1024**2:
        raise ValueError('Source archive size')
    body = path.read_bytes()
    if manifest['commit'] != PIN or hashlib.sha256(body).hexdigest() != manifest['sha256']:
        raise ValueError('Source archive binding')
    expected = manifest['files']
    if not 0 < len(expected) <= 512: raise ValueError('Source file count')
    files = {}; total = 0
    with tarfile.open(fileobj=io.BytesIO(body), mode='r:gz') as tar:
        for member in tar:
            name = member.name; rel = PurePosixPath(name)
            if (not member.isfile() or rel.is_absolute() or '..' in rel.parts or str(rel) != name
                    or name in files or name not in expected or not 0 <= member.size <= 1024**2):
                raise ValueError('Unsupported source member')
            total += member.size
            if total > 8*1024**2: raise ValueError('Expanded source limit')
            data = tar.extractfile(member).read(member.size + 1)
            if len(data) != expected[name]['bytes'] or hashlib.sha256(data).hexdigest() != expected[name]['sha256']:
                raise ValueError('Source member binding: '+name)
            files[name] = data
    if set(files) != set(expected): raise ValueError('Incomplete source archive')
    return manifest, files

def extract(destination, archive=None):
    manifest, files = verified_files(archive)
    root = Path(destination); root.mkdir()
    for name, data in files.items():
        p = root/name; p.parent.mkdir(parents=True, exist_ok=True)
        with p.open('xb') as out: out.write(data)
    return manifest
