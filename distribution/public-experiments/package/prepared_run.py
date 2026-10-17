"""Read-only bridge from disk preparation to exact pre-launch disk identities.

This checks a separately pinned local preparation receipt, not a public signature
or fresh base hash. The owner must keep directories/base exclusively controlled
and recheck before launch. No image parsing, QEMU, device or process operation.
"""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat


class Refusal(ValueError):
    pass


def require(ok, message):
    if not ok: raise Refusal(message)


def unique(items):
    result = {}
    for key,value in items:
        require(key not in result, 'Duplicate receipt field')
        result[key]=value
    return result


def identity(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def integers(value,n):
    return type(value) is list and len(value)==n and all(type(x) is int and x>=0 for x in value)


def disk(path, expected, readonly=False):
    info=os.stat(path,follow_symlinks=False)
    require(stat.S_ISREG(info.st_mode) and (readonly or info.st_nlink==1), 'Regular base/single-link overlay required')
    require(identity(info)==tuple(expected), 'Disk changed since preparation')
    require(not readonly or not info.st_mode & 0o222, 'Base became writable')
    return info


@dataclass(frozen=True)
class Prepared:
    directory: Path
    directory_identity: tuple
    base: Path
    base_identity: tuple
    overlays: tuple
    receipt_sha256: str
    image_sha256: str

    def recheck(self, role=None):
        require(role in (None, "endpoint", "dut"), "Unknown disk role")
        info=os.stat(self.directory,follow_symlinks=False)
        require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o077
                and info.st_uid==os.geteuid()
                and (info.st_dev,info.st_ino)==self.directory_identity,
                'Private preparation directory replaced or exposed')
        require(self.directory.resolve()==self.directory, 'Symlinked run directory')
        disk(self.base,self.base_identity,True)
        for name,path,pin in self.overlays:
            if role is None or role == name: disk(path,pin)
        return self

    def summary(self):
        return {'state':'PREPARATION_IDENTITIES_MATCH','directory':str(self.directory),
                'base':str(self.base),'receipt_sha256':self.receipt_sha256,
                'image_sha256':self.image_sha256,
                'overlays':{role:str(path) for role,path,pin in self.overlays},
                'fresh_base_hash':False,'runtime_ready':False,'guest_started':False}


def load(directory, receipt_sha256, image_sha256):
    for pin in (receipt_sha256,image_sha256):
        require(type(pin) is str and re.fullmatch('[0-9a-f]{64}',pin), 'Independent exact digest required')
    root=Path(directory).absolute()
    require(root.resolve()==root,'Symlinked run directory')
    info=os.stat(root,follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o077 and info.st_uid==os.geteuid(),
            'Private owned preparation directory required')
    fd=os.open(root/'installation.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size<=65536,
                'Bounded regular preparation receipt required')
        raw=stream.read(65537)
        require(len(raw)==before.st_size and identity(os.fstat(stream.fileno()))==identity(before),
                'Receipt changed during read')
    require(hashlib.sha256(raw).hexdigest()==receipt_sha256,'Receipt digest mismatch')
    value=json.loads(raw,object_pairs_hook=unique)
    require(type(value) is dict and set(value)=={'schema','state','base','image_sha256','base_identity',
        'overlays','guest_started','runtime_ready','primary','directory_identity','overlay_identities'}, 'Receipt schema')
    require(value['schema']=='prp-install-v2' and value['state']=='DISK_PREPARATION_COMPLETE'
            and value['primary'] is None and value['guest_started'] is False
            and value['runtime_ready'] is False,'Incomplete/legacy/activated preparation')
    require(value['image_sha256']==image_sha256,'Foreign base release')
    require(integers(value['base_identity'],5) and integers(value['directory_identity'],2),'Identity schema')
    require(tuple(value['directory_identity'])==(info.st_dev,info.st_ino),'Directory association')
    require(type(value['base']) is str and Path(value['base']).is_absolute(),'Absolute base path required')
    require(value['overlays']==['endpoint.qcow2','dut.qcow2']
            and type(value['overlay_identities']) is dict
            and set(value['overlay_identities'])==set(value['overlays']),'Exact two overlay roles required')
    objects=[];seen={tuple(value['base_identity'][:2])}
    for role in ('endpoint','dut'):
        name=role+'.qcow2';pin=value['overlay_identities'][name]
        require(integers(pin,5),'Overlay identity schema')
        require(tuple(pin[:2]) not in seen,'Disk aliases are forbidden')
        seen.add(tuple(pin[:2]));objects.append((role,root/name,tuple(pin)))
    result=Prepared(root,tuple(value['directory_identity']),Path(value['base']),tuple(value['base_identity']),
                    tuple(objects),receipt_sha256,image_sha256)
    return result.recheck()
