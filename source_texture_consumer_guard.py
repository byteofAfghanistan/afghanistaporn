                                                                           

                                                                              
                                                                       
                                                                       
   
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

from wrs4_archive import decompress_lzss, ArchiveError

ROOT=Path(__file__).resolve().parents[1]
ELITE_MANIFEST=(ROOT/'resources/elite_texture_recovery.json' if (ROOT/'resources/elite_texture_recovery.json').is_file()
                else ROOT/'logs/re_elite_texture_recovery.json')
ELITE_MANIFEST_SHA256='e00729022c38e1a9a65422c1bbd9075ce34e3e7d12024481b3d05aa589ee87c7'
MAX_MANIFEST_BYTES=128*1024
MAX_ARCHIVES=512
MAX_ENTRIES=200000
MAX_DIRECTORY_BYTES=40*65536
MAX_DIRECTORY_COMPRESSED=MAX_DIRECTORY_BYTES*2
MAX_PROTECTED_COMPRESSED=32*1024*1024
MAX_PUBLICATION_BYTES=32*1024*1024
MAX_ARCHIVE_BYTES=2**32-1
HEX=re.compile(r'^[0-9a-f]{64}$')


class SourceTextureGuardError(ValueError):
    pass


def _fail(message):raise SourceTextureGuardError(message)
def _sha(raw):return hashlib.sha256(raw).hexdigest()
def _integer(value,minimum,maximum,label):
    if type(value) is not int or not minimum<=value<=maximum:_fail('Invalid '+label)
    return value
def _hash(value):
    if type(value) is not str or HEX.fullmatch(value) is None:_fail('Expected an exact lowercase SHA256')
    return value
def _relative(value,filename=False):
    if type(value) is not str or not value or len(value)>240 or any(ord(c)<32 or ord(c)>126 for c in value) or '\\' in value or ':' in value:
        _fail('Invalid relative source path')
    parts=value.split('/')
    if any(part in ('','.','..') or part[-1] in '. ' for part in parts) or filename and len(parts)!=1:
        _fail('Invalid relative source path')
    return value
def _ordinary(info,directory=False):
    return not (getattr(info,'st_file_attributes',0)&0x400) and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
def _signature(info):
                                                                            
                                                                            
    stamp=getattr(info,'st_birthtime_ns',info.st_ctime_ns)
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,stamp)
def _stat(path,directory=False):
    info=path.lstat()
    if not _ordinary(info,directory):_fail('Source path is not an ordinary '+('directory' if directory else 'file'))
    return info
def _root(value):
    path=Path(value).resolve(strict=True)
    _stat(path,True)
    return path
def _contained(root,relative):
    target=root
    parts=_relative(relative).split('/')
    for component in parts[:-1]:target=target/component;_stat(target,True)
    target=target/parts[-1]
    if not target.is_relative_to(root):_fail('Source escaped its root')
    return target


def _read_stable(path,limit):
    before=_stat(path)
    if before.st_size>limit:_fail('Source file exceeds its bounded size')
    with path.open('rb') as stream:
        opened=os.fstat(stream.fileno())
        if not _ordinary(opened) or _signature(opened)!=_signature(before):_fail('Source changed while opening')
        raw=stream.read(limit+1)
        if len(raw)!=before.st_size or len(raw)>limit:_fail('Source changed while reading')
        if _signature(os.fstat(stream.fileno()))!=_signature(opened):_fail('Source changed during verification')
    if _signature(_stat(path))!=_signature(before):_fail('Source was replaced during verification')
    return raw,_signature(before)


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:_fail('Duplicate manifest key')
        result[key]=value
    return result


def _manifest(path,expected_hash):
    expected_hash=_hash(expected_hash)
    raw,identity=_read_stable(Path(path),MAX_MANIFEST_BYTES)
    if _sha(raw)!=expected_hash:_fail('Elite consumer manifest hash does not match the reviewed policy')
    try:manifest=json.loads(raw.decode('utf-8'),object_pairs_hook=_object,parse_constant=lambda _: _fail('Non-finite manifest number'))
    except (UnicodeError,json.JSONDecodeError) as error:raise SourceTextureGuardError('Malformed consumer manifest') from error
    if type(manifest) is not dict or type(manifest.get('version')) is not int or manifest['version']!=1 or manifest.get('kind')!='current-installation-elite-source-normal-alias':
        _fail('Unsupported consumer manifest')
    guards=manifest.get('sourceGuards')
    if type(guards) is not dict or guards.get('rejectLooseOverrides') is not True:_fail('Loose source overrides must be rejected')
    protected=guards.get('protectedMemberNames')
    if type(protected) is not list or not 1<=len(protected)<=32:_fail('Invalid protected member list')
    protected=[_relative(name,True).casefold() for name in protected]
    if len(set(protected))!=len(protected):_fail('Duplicate protected member')
    expected=guards.get('exactProviders')
    if type(expected) is not list or not 1<=len(expected)<=512:_fail('Invalid provider list')
    providers={}
    for row in expected:
        if type(row) is not dict:_fail('Invalid provider entry')
        archive=_relative(row.get('archive'));member=_relative(row.get('member'),True)
        if not archive.casefold().endswith('.gen') or member.casefold() not in protected:_fail('Unexpected protected provider')
        key=(archive.casefold(),member.casefold())
        if key in providers:_fail('Duplicate protected provider')
        providers[key]=(_integer(row.get('compressedBytes'),1,MAX_PROTECTED_COMPRESSED,'protected compressed size'),
                        _integer(row.get('declaredBytes'),1,MAX_PUBLICATION_BYTES,'protected decoded size'),_hash(row.get('compressedSha256')))
    publication=guards.get('publicationInputs')
    if type(publication) is not list or not 1<=len(publication)<=32:_fail('Invalid publication input list')
    inputs={}
    for row in publication:
        if type(row) is not dict:_fail('Invalid publication input')
        name=_relative(row.get('file'))
        if name.casefold() in inputs:_fail('Duplicate publication input')
        inputs[name.casefold()]=(name,_hash(row.get('sha256')))
    return set(protected),providers,list(inputs.values()),identity


def _inventory(game,protected):
    pending=[game];archives={};count=0
    while pending:
        directory=pending.pop();_stat(directory,True)
        with os.scandir(directory) as entries:
            for entry in entries:
                count+=1
                if count>MAX_ENTRIES:_fail('Game source tree exceeds bounded entry count')
                path=Path(entry.path);info=entry.stat(follow_symlinks=False)
                if getattr(info,'st_file_attributes',0)&0x400 or stat.S_ISLNK(info.st_mode):_fail('Reparse/link source trees are not verified')
                if entry.name.casefold() in protected:_fail('Loose protected source override exists')
                if stat.S_ISDIR(info.st_mode):pending.append(path)
                elif path.suffix.casefold()=='.gen':
                    if not _ordinary(info):_fail('Archive is not an ordinary file')
                    relative=str(path.relative_to(game)).replace('\\','/');key=relative.casefold()
                    if key in archives:_fail('Case-ambiguous archive paths')
                                                                             
                                                                            
                                                       
                    archives[key]=(relative,path,_signature(_stat(path)))
                    if len(archives)>MAX_ARCHIVES:_fail('Too many source archives')
    return archives


def _directory(stream,file_size):
    if not 16<=file_size<=MAX_ARCHIVE_BYTES:_fail('Invalid WRS4 file size')
    header=stream.read(8)
    if len(header)!=8 or header[:4]!=b'WRS4':_fail('Malformed or unsupported source archive')
    offset=struct.unpack_from('>I',header,4)[0]
    if not 8<=offset<=file_size-8:_fail('Archive directory is outside the file')
    stream.seek(offset);sizes=stream.read(8)
    if len(sizes)!=8:_fail('Truncated directory header')
    compressed,unpacked=struct.unpack('>2I',sizes)
    if compressed>MAX_DIRECTORY_COMPRESSED or unpacked>MAX_DIRECTORY_BYTES or unpacked%40 or offset+8+compressed!=file_size:
        _fail('Malformed or oversized archive directory')
    data=stream.read(compressed)
    if len(data)!=compressed:_fail('Truncated archive directory')
    try:directory=decompress_lzss(data,unpacked)
    except ArchiveError as error:raise SourceTextureGuardError('Malformed compressed archive directory') from error
    at=8;names=set();members=[]
    for cursor in range(0,len(directory),40):
        record=directory[cursor:cursor+40]
        encoded=record[:32].split(b'\0',1)[0]
        try:name=bytes(value^0xaa for value in encoded).decode('ascii')
        except UnicodeError as error:raise SourceTextureGuardError('Invalid archive member encoding') from error
        _relative(name)
        key=name.replace('\\','/').casefold()
        if key in names:_fail('Duplicate archive member names')
        names.add(key)
        packed,size=struct.unpack_from('>2I',record,32)
        if at+packed>offset:_fail('Archive member overlaps directory')
        members.append((name,at,packed,size));at+=packed
    if at!=offset:_fail('Archive member extents do not cover data')
    return members


def verify_texture_consumer_manifest(game_directory,*,workspace_directory,manifest_path,expected_manifest_sha256):
                                                                           

                                                                            
                                                                               
       
    try:
        game=_root(game_directory);workspace=_root(workspace_directory)
        protected,expected,publication,manifest_identity=_manifest(manifest_path,expected_manifest_sha256)
        inventory=_inventory(game,protected)
        observed={};snapshots=[]
        for key,(relative,path,identity) in sorted(inventory.items()):
            before=_stat(path)
            if _signature(before)!=identity:_fail('Archive inventory changed before verification')
            with path.open('rb') as stream:
                opened=os.fstat(stream.fileno())
                if not _ordinary(opened) or _signature(opened)!=identity:_fail('Archive changed while opening')
                members=_directory(stream,opened.st_size)
                for name,offset,packed,size in members:
                                                                            
                                                                               
                    if name.rsplit('/',1)[-1].casefold() not in protected:continue
                    provider_key=(key,name.casefold())
                    spec=expected.get(provider_key)
                    if spec is None:_fail('New or unexpected protected source provider')
                    if (packed,size)!=spec[:2]:_fail('Protected source provider sizes changed')
                    stream.seek(offset);data=stream.read(packed)
                    if len(data)!=packed or _sha(data)!=spec[2]:_fail('Protected source provider bytes changed')
                    observed[provider_key]=spec
                if _signature(os.fstat(stream.fileno()))!=identity:_fail('Archive changed during verification')
            snapshots.append((path,identity))
        if observed!=expected:_fail('Required protected source providers are missing')
        for relative,expected_hash in publication:
            path=_contained(workspace,relative);raw,identity=_read_stable(path,MAX_PUBLICATION_BYTES)
            if _sha(raw)!=expected_hash:_fail('Server publication input changed; consumer scope must be reviewed')
            snapshots.append((path,identity))
                                                                           
                                                                              
                                                                      
        if _inventory(game,protected)!=inventory:_fail('Game source inventory changed during verification')
        for path,identity in snapshots:
            if _signature(_stat(path))!=identity:_fail('Verified source changed before completion')
        if _signature(_stat(Path(manifest_path)))!=manifest_identity:_fail('Consumer manifest changed during verification')
        return {'version':1,'manifestSha256':expected_manifest_sha256,
                'archivesChecked':len(inventory),'providersChecked':len(observed),'publicationInputsChecked':len(publication)}
    except SourceTextureGuardError:raise
    except (OSError,ValueError,TypeError,struct.error) as error:
        raise SourceTextureGuardError('Consumer scope could not be verified') from error


def verify_elite_consumers(game_directory,*,workspace_directory=ROOT):
                                                                                
    return verify_texture_consumer_manifest(game_directory,workspace_directory=workspace_directory,
        manifest_path=ELITE_MANIFEST,expected_manifest_sha256=ELITE_MANIFEST_SHA256)
