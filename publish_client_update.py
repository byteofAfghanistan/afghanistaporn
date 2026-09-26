                                                                             

                                                                                
                                                                               
   
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from client_enrollment import protect

ROOT = Path(__file__).resolve().parents[1]
KEY_DIRECTORY = Path.home() / '.zula-update-signing'
KEY_ID = 'zula-test-key-v1'
HOST = 'apitest.zulaoyun.com'
SERVER_ADDRESS = '172.31.205.20'
CERTIFICATE_SHA256 = '8uDkBnjiJ9eLbGDd/8W50v9uj/Tl+zVivsZ6wde90JA='
MAX_PAYLOAD, MAX_ENVELOPE, MAX_FILE = 512*1024, 768*1024, 512*1024*1024
HEX = re.compile(r'[0-9a-f]{64}\Z')
MANIFEST = 'client-payload-manifest.json'
DEFAULT_FILES = ('Zula-Loader.exe', 'tools/frida_play_connect.py', MANIFEST)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode('ascii')


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError('Duplicate JSON member')
            result[key] = value
        return result
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def ordinary(path, directory=False):
    info = path.lstat()
    if (not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            or getattr(info, 'st_file_attributes', 0) & 0x400):
        raise ValueError('Ordinary path required')
    return info


def safe_path(name):
    if type(name) is not str or not 1 <= len(name) <= 240 or not re.fullmatch(r'[A-Za-z0-9_. /-]+', name):
        raise ValueError('Invalid managed path')
    parts = name.split('/')
    devices = {'CON', 'PRN', 'AUX', 'NUL', *('COM'+str(i) for i in range(1, 10)), *('LPT'+str(i) for i in range(1, 10))}
    if any(not part or part in {'.', '..'} or part.startswith('.') or part.endswith((' ', '.'))
           or part.split('.')[0].upper() in devices for part in parts):
        raise ValueError('Ambiguous managed path')
    if parts[0].lower() in {'data', 'logs', 'config', 'updates', '.ssh'}:
        raise ValueError('Private or runtime-owned path')
    if name.lower().endswith(('.pem', '.pfx', '.p12', '.key')) and name not in {'Game/ANet.key', 'Game/ca.pem'}:
        raise ValueError('Private key path')
    if any(part.lower() in {'server.env', 'client-installation.json', 'client-enrollment.json'}
           or part.lower().startswith('remote-client') for part in parts):
        raise ValueError('Private configuration path')
    return name


def source_file(root, name):
    safe_path(name); path = Path(root).absolute(); ordinary(path, True)
    for index, part in enumerate(name.split('/')):
        path = path / part
        ordinary(path, index < len(name.split('/')) - 1)
    return path


def stream_copy(source, target=None):
    before = ordinary(source)
    if not 0 <= before.st_size <= MAX_FILE:
        raise ValueError('File exceeds bound')
    sha = hashlib.sha256(); count = 0
    output = target.open('xb') if target is not None else None
    try:
        with source.open('rb') as incoming:
            while chunk := incoming.read(1024*1024):
                count += len(chunk)
                if count > MAX_FILE:
                    raise ValueError('Source exceeds bound')
                sha.update(chunk)
                if output is not None: output.write(chunk)
        if output is not None: output.flush(); os.fsync(output.fileno())
    finally:
        if output is not None: output.close()
    after = ordinary(source)
    if count != before.st_size or (before.st_ino, before.st_mtime_ns, before.st_size) != (after.st_ino, after.st_mtime_ns, after.st_size):
        raise ValueError('Source changed')
    return count, sha.hexdigest()


def checked_parent(directory):
    directory = Path(directory).absolute()
    for parent in (directory, *directory.parents):
        ordinary(parent, True)
    return directory


def key_pair(directory=KEY_DIRECTORY, create=False):
    directory = Path(directory).absolute()
    if directory == ROOT or ROOT in directory.parents:
        raise ValueError('Signing key must be outside workspace')
    checked_parent(directory.parent)
    if not directory.exists():
        if not create: raise ValueError('Signing key absent')
        directory.mkdir(mode=0o700)
    checked_parent(directory); protect(directory, True)
    key_path = directory / 'private.pem'
    try:
        ordinary(key_path)
    except FileNotFoundError:
        if not create: raise ValueError('Signing key absent')
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
                                                                               
        with key_path.open('xb') as output:
            protect(key_path); output.write(raw); output.flush(); os.fsync(output.fileno())
    if ordinary(key_path).st_size > 16384:
        raise ValueError('Invalid signing key')
    protect(key_path)
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072 or key.public_key().public_numbers().e != 65537:
        raise ValueError('Unexpected signing algorithm')
    return key


def public_document(key):
    public = key.public_key(); numbers = public.public_numbers()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {'version': 1, 'keyId': KEY_ID, 'algorithm': 'RS256', 'bits': 3072,
            'modulus': base64.b64encode(numbers.n.to_bytes(384, 'big')).decode('ascii'),
            'exponent': 'AQAB', 'spkiSha256': digest(der), 'host': HOST, 'serverAddress': SERVER_ADDRESS,
            'certificateSha256': CERTIFICATE_SHA256}


def initialize_key():
    public = public_document(key_pair(create=True))
    destination = ROOT / 'loader/update-public-key.json'
    if destination.exists() and strict_json(destination.read_bytes()) != public:
        raise ValueError('Existing public trust differs')
    destination.write_bytes(encoded(public))
    constants = {'KeyId': KEY_ID, 'PublicModulusBase64': public['modulus'], 'PublicExponentBase64': public['exponent'],
                 'CertificateSha256': CERTIFICATE_SHA256, 'Host': HOST, 'ServerAddress': SERVER_ADDRESS,
                 'FeedPath': '/updates/v1/stable.json', 'BlobPrefix': '/updates/v1/blobs/'}
    text = 'namespace ZulaLoader\n{\n    internal static class UpdateTrust\n    {\n'
    for name, value in constants.items():
        text += '        internal const string '+name+' = "'+value+'";\n'
    text += '    }\n}\n'
    (ROOT / 'loader/UpdateTrust.cs').write_text(text, encoding='utf-8')
    return public


def validate_rows(rows, remove=False):
    if type(rows) is not list or len(rows) > 512:
        raise ValueError('Invalid member count')
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != ({'path', 'sha256'} if remove else {'path', 'size', 'sha256'}):
            raise ValueError('Invalid file record')
        name = safe_path(row['path'])
        if name.lower() in seen: raise ValueError('Duplicate managed path')
        seen.add(name.lower())
        if remove:
            if name != 'Zula-Test.exe' or type(row['sha256']) is not list or not 1 <= len(row['sha256']) <= 32:
                raise ValueError('Unsupported obsolete entry')
            values = row['sha256']
        else:
            if type(row['size']) is not int or not 0 <= row['size'] <= MAX_FILE:
                raise ValueError('Invalid file size')
            values = [row['sha256']]
        if any(type(value) is not str or not HEX.fullmatch(value) for value in values):
            raise ValueError('Invalid digest')
    return seen


def validate_payload(payload):
    if type(payload) is not dict or set(payload) != {'version', 'product', 'channel', 'sequence', 'release', 'files', 'remove'}:
        raise ValueError('Invalid payload shape')
    if type(payload['version']) is not int or payload['version'] != 1 or payload['product'] != 'zula-test' or payload['channel'] != 'stable':
        raise ValueError('Invalid product')
    if type(payload['sequence']) is not int or not 1 <= payload['sequence'] <= 2147483647:
        raise ValueError('Invalid sequence')
    if type(payload['release']) is not str or not re.fullmatch(r'[0-9][0-9A-Za-z._-]{0,63}', payload['release']):
        raise ValueError('Invalid release')
    managed = validate_rows(payload['files']); removed = validate_rows(payload['remove'], True)
    if not managed or managed & removed:
        raise ValueError('Conflicting or empty update')


def sign_payload(payload, key):
    validate_payload(payload); raw = encoded(payload)
    if len(raw) > MAX_PAYLOAD: raise ValueError('Payload exceeds bound')
    signature = key.sign(raw, padding.PKCS1v15(), hashes.SHA256())
    envelope = encoded({'version': 1, 'keyId': KEY_ID, 'algorithm': 'RS256',
                        'payload': base64.b64encode(raw).decode('ascii'),
                        'signature': base64.b64encode(signature).decode('ascii')})
    if len(envelope) > MAX_ENVELOPE: raise ValueError('Envelope exceeds bound')
    return envelope


def verify_envelope(raw, key):
    if len(raw) > MAX_ENVELOPE: raise ValueError('Envelope exceeds bound')
    envelope = strict_json(raw)
    if (type(envelope) is not dict or set(envelope) != {'version', 'keyId', 'algorithm', 'payload', 'signature'}
            or type(envelope['version']) is not int or envelope['version'] != 1
            or envelope['keyId'] != KEY_ID or envelope['algorithm'] != 'RS256'):
        raise ValueError('Invalid envelope')
    payload = base64.b64decode(envelope['payload'], validate=True)
    signature = base64.b64decode(envelope['signature'], validate=True)
    if len(payload) > MAX_PAYLOAD or len(signature) != 384: raise ValueError('Invalid signed lengths')
    key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    value = strict_json(payload); validate_payload(value)
    return value


def build_update(payload_root, stage, sequence, release, names=DEFAULT_FILES, remove_hashes=(), key=None):
    payload_root = checked_parent(payload_root); stage = Path(stage).absolute()
    if stage.exists(): raise ValueError('Use a fresh output stage')
    inventory_path = source_file(payload_root, MANIFEST)
    if inventory_path.stat().st_size > MAX_PAYLOAD: raise ValueError('Inventory exceeds bound')
    inventory_raw = inventory_path.read_bytes(); inventory = strict_json(inventory_raw)
    if type(inventory) is not dict or inventory.get('entryPoint') != 'Zula-Loader.exe':
        raise ValueError('Target entry point must be the single loader')
    owned = inventory.get('files') if type(inventory) is dict else None
    validate_rows(owned)
    owned = {row['path']: row for row in owned}
    if 'Zula-Test.exe' in owned: raise ValueError('Target inventory still owns obsolete entry')
    if len(set(names)) != len(names) or not set(DEFAULT_FILES) <= set(names):
        raise ValueError('Missing mandatory managed files')
    rows = []; originals = {}
    for name in sorted(names):
        path = source_file(payload_root, name); size, sha = stream_copy(path)
        row = {'path': name, 'size': size, 'sha256': sha}
        if name != MANIFEST and owned.get(name) != row:
            raise ValueError('Selected source differs from target inventory')
        rows.append(row); originals[name] = path
    payload = {'version': 1, 'product': 'zula-test', 'channel': 'stable', 'sequence': sequence,
               'release': release, 'files': rows,
               'remove': [{'path': 'Zula-Test.exe', 'sha256': sorted(set(remove_hashes))}] if remove_hashes else []}
    key = key or key_pair(); envelope = sign_payload(payload, key)
    verify_envelope(envelope, key.public_key())
    stage.mkdir(parents=True); blobs = stage / 'blobs'; blobs.mkdir()
    for row in rows:
        target = blobs / row['sha256']
        if not target.exists():
            actual = stream_copy(originals[row['path']], target)
            if actual != (row['size'], row['sha256']): raise ValueError('Source changed while publishing')
        elif stream_copy(target) != (row['size'], row['sha256']):
            raise ValueError('Blob collision')
    for row in rows:
        if stream_copy(originals[row['path']]) != (row['size'], row['sha256']):
            raise ValueError('Source changed after publishing')
    (stage / 'stable.json').write_bytes(envelope)
    receipt = {'version': 1, 'sequence': sequence, 'release': release, 'feedSha256': digest(envelope),
               'payloadSha256': digest(base64.b64decode(strict_json(envelope)['payload'])),
               'publicKeySpkiSha256': public_document(key)['spkiSha256'], 'files': rows, 'remove': payload['remove'],
               'installedManifestSha256': digest(inventory_raw), 'remoteActivated': False}
    (stage / 'publish-receipt.json').write_bytes(encoded(receipt))
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('init-key')
    build = commands.add_parser('build'); build.add_argument('--payload', type=Path, required=True)
    build.add_argument('--stage', type=Path, required=True); build.add_argument('--sequence', type=int, required=True)
    build.add_argument('--release', required=True); build.add_argument('--file', action='append')
    build.add_argument('--remove-bootstrap-hash', action='append', default=[])
    args = parser.parse_args(argv)
    if args.command == 'init-key':
        public = initialize_key(); print(json.dumps({'keyId': KEY_ID, 'publicKeySpkiSha256': public['spkiSha256']})); return
    receipt = build_update(args.payload, args.stage, args.sequence, args.release,
                           args.file or DEFAULT_FILES, args.remove_bootstrap_hash)
    print(json.dumps(receipt))


if __name__ == '__main__':
    main()
