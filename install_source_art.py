                                                                     

                                                                              
                                                                              
                                                                         
   
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile

from wrs4_archive import Wrs4Archive

SOURCE_NAME = 'nc_big_2678.dds'
SOURCE_SHA = '6f6c12319d85d42885ef2586e145c8eb92f9f952eb29db376ca8f2ced77dccb4'
ALIASES = ('nc_weap_hd2678.dds', 'weap_hd2678.dds')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Asset target must be an ordinary file: ' + str(path))
    return info.st_dev, info.st_ino


def verified(path, *, source_sha=SOURCE_SHA, byte_size=37088):
    owner = identity(path)
    if path.stat().st_size != byte_size or digest(path.read_bytes()) != source_sha:
        raise ValueError('Existing source-art alias differs: ' + str(path))
    return owner


def install(game_directory, *, check=False, source_reader=None):
    return install_exact_aliases(game_directory, archive_name='pnl_nor7.gen', source_name=SOURCE_NAME,
        source_sha=SOURCE_SHA, aliases=ALIASES, byte_size=37088, dimensions=(55,168),
        check=check, source_reader=source_reader)


def install_exact_aliases(game_directory, *, archive_name, source_name, source_sha, aliases,
                          byte_size, dimensions, check=False, source_reader=None):
                                                                             
                                                                           
    names = (archive_name, source_name, *aliases)
    if not aliases or len(set(aliases)) != len(aliases) or any(
            not isinstance(name,str) or not name or name in ('.','..') or
            any(char in name for char in '/\\:\0') or name[-1] in '. ' for name in names):
        raise ValueError('Source asset manifest requires exact filenames')
    if len(source_sha) != 64 or any(char not in '0123456789abcdef' for char in source_sha):
        raise ValueError('Source asset manifest requires an exact SHA256')
    if type(byte_size) is not int or not 128 <= byte_size <= 32*1024*1024:
        raise ValueError('Source asset byte size is out of bounds')
    verify = lambda path: verified(path, source_sha=source_sha, byte_size=byte_size)
    game = Path(game_directory).resolve(strict=True)
    if not game.is_dir():
        raise ValueError('Game directory is missing')
    paths = [game / name for name in aliases]
                                                                         
    present = {path: verify(path) for path in paths if os.path.lexists(path)}
    if check:
        if len(present) != len(paths):
            raise ValueError('Exact source-art aliases are not installed')
        return {'version': 1, 'gameDirectory': str(game), 'sha256': source_sha,
                'files': [{'path': str(path), 'created': False} for path in paths]}
    data = (source_reader or (lambda archive, member: Wrs4Archive(archive).read(member)))(
        game / 'data' / archive_name, source_name)
    if len(data) != byte_size or data[:4] != b'DDS ' or digest(data) != source_sha or struct.unpack_from('<II', data, 12) != dimensions:
        raise ValueError('Original same-item source art changed; audit required')
    created, temporary = {}, []
    try:
        for path in paths:
            if path in present:
                continue
            handle, temp_name = tempfile.mkstemp(prefix='.zula-art-', suffix='.tmp', dir=game)
            temp = Path(temp_name)
            temporary.append(temp)
            with os.fdopen(handle, 'wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            owner = identity(temp)
                                                                               
                                                                             
            try:
                os.link(temp, path)
                created[path] = owner
            except FileExistsError:
                verify(path)
            temp.unlink()
            temporary.remove(temp)
        for path in paths:
            verify(path)
        return {'version': 1, 'gameDirectory': str(game), 'sourceMember': source_name,
                'sha256': source_sha, 'bytes': len(data),
                'files': [{'path': str(path), 'created': path in created,
                           'fileIdentity': list(identity(path))} for path in paths]}
    finally:
                                                                                
                                                                               
                                                                                
        for temp in temporary:
            try:
                temp.unlink()
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-dir', required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    print(json.dumps(install(args.game_dir, check=args.check), ensure_ascii=False))


if __name__ == '__main__':
    main()
