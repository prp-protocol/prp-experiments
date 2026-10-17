"""Pinned finite release downloads using the existing verified cache reader."""
import hashlib
import importlib.machinery
import json
import math
import os
import re
from pathlib import Path
import sys
import time

HERE = Path(__file__).resolve().parent
PKG = HERE.parent / 'package'
sys.path.insert(0, str(PKG))
import image_cache
import deployment

NAMES = {'image.qcow2', *(name+'.ko' for name in deployment.MODULES),
         'module-sources.tar.gz', 'image-notices.tar.gz'}


def read_plan(path, pin, release, release_pin):
    raw = deployment.bounded(path, 32768)
    if not deployment.digest(pin) or hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('Download manifest digest')
    plan = json.loads(raw, object_pairs_hook=deployment.unique)
    if (type(plan) is not dict or set(plan) != {'schema', 'release_sha256', 'files'}
            or plan['schema'] != 'exp002-native-downloads-1'
            or plan['release_sha256'] != release_pin):
        raise ValueError('Download/release binding')
    release_raw = deployment.bounded(release, 32768)
    if not deployment.digest(release_pin) or hashlib.sha256(release_raw).hexdigest() != release_pin:
        raise ValueError('Deployment manifest digest')
    assets = json.loads(release_raw, object_pairs_hook=deployment.unique)
    # Validate all metadata before any retrieval. Full module validation is also
    # performed by deployment.load after fetching and again at installation.
    if (type(assets) is not dict or set(assets) != {'schema','kernel','source_commit','image','modules'}
            or assets['schema'] != 'exp002-native-assets-1' or assets['kernel'] != deployment.KERNEL
            or set(assets['modules']) != deployment.MODULES):
        raise ValueError('Deployment shape')
    if (type(assets['source_commit']) is not str or not re.fullmatch('[0-9a-f]{40}', assets['source_commit'])
            or type(assets['image']) is not dict or set(assets['image']) != {'bytes','sha256','virtual_bytes'}
            or type(assets['image']['virtual_bytes']) is not int or assets['image']['virtual_bytes'] <= 0):
        raise ValueError('Deployment source/image metadata')
    for record in [assets['image'], *assets['modules'].values()]:
        if (type(record) is not dict or type(record.get('bytes')) is not int
                or record['bytes'] <= 0 or not deployment.digest(record.get('sha256'))):
            raise ValueError('Deployment artifact metadata')
    for module in assets['modules'].values():
        if type(module) is not dict or set(module) != {'file','bytes','sha256'}:
            raise ValueError('Deployment module metadata')
    if type(plan['files']) is not list or len(plan['files']) != 8:
        raise ValueError('Exactly eight release files required')
    rows = {}; total = 0
    for row in plan['files']:
        if type(row) is not dict or set(row) != {'name','bytes','sha256','url'}:
            raise ValueError('Download row shape')
        name = row['name']
        if type(name) is not str or name not in NAMES or name in rows:
            raise ValueError('Unknown or duplicate artifact')
        ceiling = 2*1024**3 if name == 'image.qcow2' else (16*1024**2 if name.endswith('.ko') else 32*1024**2)
        if type(row['bytes']) is not int or not 0 < row['bytes'] <= ceiling or not deployment.digest(row['sha256']):
            raise ValueError('Artifact size/hash')
        image_cache.https_url(row['url'])
        if name == 'image.qcow2':
            expected = assets['image']
        elif name.endswith('.ko'):
            expected = assets['modules'][name[:-3]]
            if expected.get('file') != name: raise ValueError('Module name binding')
        else: expected = row
        if row['bytes'] != expected['bytes'] or row['sha256'] != expected['sha256']:
            raise ValueError('Download bytes differ from deployment')
        total += row['bytes']; rows[name] = row
    if set(rows) != NAMES or sum(r['bytes'] for n,r in rows.items() if n.endswith('.ko')) > 16*1024**2:
        raise ValueError('Artifact population/module cap')
    return rows, total


def fetch(plan, pin, release, release_pin, destination, seconds,
          *, downloader=image_cache.download, clock=time.monotonic):
    rows, total = read_plan(plan, pin, release, release_pin)
    if type(seconds) not in (int,float) or not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('Finite positive download timeout required')
    start = clock(); end = start + seconds; last = start
    if not math.isfinite(start) or not math.isfinite(end): raise ValueError('Download origin')
    def remaining():
        nonlocal last
        now = clock()
        if not math.isfinite(now) or now < last or now >= end:
            raise ValueError('Release download deadline/regression')
        last = now
        return end-now
    root = Path(destination).absolute()
    if root.resolve() != root: raise ValueError('Symlinked download destination')
    remaining(); root.mkdir(mode=0o700) # Exclusive attempt; never reuse/overwrite.
    reader = importlib.machinery.SourceFileLoader('release_disk_reader', str(PKG/'install')).load_module()
    receipt = {'state':'INCOMPLETE', 'declared_bytes':total,'files':[], 'primary':None,'secondary':[],
               'deadline':end,'download_manifest_sha256':pin,'release_sha256':release_pin}
    failure = None
    try:
        for name in sorted(rows):
            row = rows[name]
            spec = {'image_sha256':row['sha256'],'image_bytes':row['bytes'],'image_url':row['url']}
            cached = Path(downloader(spec, root/'cache'/name, remaining(), reader.digest_file))
            actual, _ = reader.digest_file(cached, row['bytes'])
            if actual != row['sha256']: raise ValueError('Returned cache digest mismatch')
            remaining()
            os.link(cached, root/name) # No second image copy, no archive extraction.
            receipt['files'].append({'name':name,'bytes':row['bytes'],'sha256':actual})
            remaining()
        deployment.load(release, release_pin, root)
        remaining(); receipt['state']='VERIFIED_RELEASE_FILES'
    except Exception as exc:
        failure = exc; receipt['primary'] = type(exc).__name__+': '+str(exc)[:2048]
    finally:
        try:
            with (root/'download-receipt.json').open('x') as out:
                json.dump(receipt,out,indent=2);out.write('\n')
        except Exception as exc:
            if failure is None: failure = exc
            else: failure.add_note('Secondary receipt failure: '+str(exc)[:2048])
    if failure is not None: raise failure
    return root/'image.qcow2', root
