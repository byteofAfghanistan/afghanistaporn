                                                                          

                                                                              
                                                                        
   
import argparse
from contextlib import contextmanager
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import secrets
import stat
import tempfile
import unicodedata
import sys

from client_capability_lease import PinnedEmulatorTransport, ClientCapabilityTransportError

ROUTE = '/local/ClientEnrollment/Create'
MAX_FILE = 65536


class EnrollmentError(Exception):
    pass


def present(path):
                                                                           
                                                    
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def ordinary(path, directory=False):
    info = path.lstat()
    expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not expected or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise EnrollmentError('INVALID_LOCAL_STATE')
    return info


def _private_windows(path, directory=False):
                                                                    
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    token, needed, sid_text, descriptor = wintypes.HANDLE(), wintypes.DWORD(), ctypes.c_void_p(), ctypes.c_void_p()
    try:
        if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
            raise EnrollmentError('LOCAL_PROTECTION_FAILED')
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not 1 <= needed.value <= MAX_FILE:
            raise EnrollmentError('LOCAL_PROTECTION_FAILED')
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise EnrollmentError('LOCAL_PROTECTION_FAILED')
        sid = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise EnrollmentError('LOCAL_PROTECTION_FAILED')
        value = ctypes.wstring_at(sid_text)
        inherit = 'OICI' if directory else ''
        sddl = 'D:P(A;%s;FA;;;SY)(A;%s;FA;;;%s)' % (inherit, inherit, value)
        if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
            raise EnrollmentError('LOCAL_PROTECTION_FAILED')
        if not advapi.SetFileSecurityW(str(path), 4 | 0x80000000, descriptor):
            raise EnrollmentError('LOCAL_PROTECTION_FAILED')
    finally:
        if descriptor: kernel.LocalFree(descriptor)
        if sid_text: kernel.LocalFree(sid_text)
        if token: kernel.CloseHandle(token)


def protect(path, directory=False):
    ordinary(path, directory)
    if os.name == 'nt':
        _private_windows(path, directory)
    else:
        path.chmod(0o700 if directory else 0o600)


def read_json(path):
    if ordinary(path).st_size > MAX_FILE:
        raise EnrollmentError('INVALID_LOCAL_STATE')
    protect(path)
    with path.open('rb') as source:
        raw = source.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        raise EnrollmentError('INVALID_LOCAL_STATE')
    try:
        return json.loads(raw.decode('utf-8-sig'))
    except Exception:
        raise EnrollmentError('INVALID_LOCAL_JSON') from None


def write_private(path, document):
                                                                                 
    raw = (json.dumps(document, ensure_ascii=True, separators=(',', ':')) + '\n').encode('ascii')
    if len(raw) > MAX_FILE:
        raise EnrollmentError('INVALID_LOCAL_STATE')
    if present(path): ordinary(path)
    descriptor, temporary = tempfile.mkstemp(prefix='.enrollment-', suffix='.tmp', dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            protect(temporary)
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        protect(path)
    finally:
        if present(temporary): temporary.unlink()


@contextmanager
def installation_lock(directory):
    path = directory / '.client-enrollment.lock'
    if present(path): ordinary(path)
    with path.open('a+b') as handle:
        protect(path)
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b'\0'); handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise EnrollmentError('ENROLLMENT_BUSY') from None
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


def valid_identity(value):
    return (type(value) is dict and type(value.get('Id')) is int and 1 <= value['Id'] <= 2147483647
            and type(value.get('NickName')) is str and 1 <= len(value['NickName']) <= 64 and bool(value['NickName'].strip())
            and not any(unicodedata.category(c).startswith('C') for c in value['NickName'])
            and len(value['NickName'].encode('utf-16-le')) <= 128
            and type(value.get('Token')) is str and re.fullmatch(r'[\x21-\x7e]{32,128}', value['Token']) is not None)


def ensure_identity(root, server, transport=None, *, new_account=False):
    root = Path(root).absolute()
    ordinary(root, True)
    directory = root / 'data'
    directory.mkdir(exist_ok=True)
    protect(directory, True)                                                   
    with installation_lock(directory):
        candidates = [path for path in directory.glob('remote-client*.json')
                      if re.fullmatch(r'remote-client[A-Za-z0-9_-]*\.json', path.name)]
        for path in candidates if not new_account else []:
            try:
                if valid_identity(read_json(path)):
                    return read_json(path)
            except EnrollmentError as error:
                if str(error) != 'INVALID_LOCAL_JSON': raise
        state_path = directory / ('client-new-account.json' if new_account else 'client-enrollment.json')
        if present(state_path):
            state = read_json(state_path)
            if (type(state) is not dict or set(state) != {'version', 'server', 'secret'}
                    or type(state['version']) is not int or state['version'] != 1 or state['server'] != server
                    or type(state['secret']) is not str or not re.fullmatch('[0-9a-f]{64}', state['secret'])):
                raise EnrollmentError('INVALID_LOCAL_STATE')
        else:
            if candidates and not new_account:
                raise EnrollmentError('INVALID_LOCAL_STATE')
            state = {'version': 1, 'server': server, 'secret': secrets.token_hex(32)}
            write_private(state_path, state)
        if transport is None:
            transport = PinnedEmulatorTransport(server, root / 'certs/server.crt', timeout_seconds=4)
        response = None
        for attempt in range(2):
            try:
                response = transport.request('POST', ROUTE, {'Version': 1, 'InstallSecret': state['secret']})
            except ClientCapabilityTransportError:
                if attempt == 0: continue
                raise EnrollmentError('ENROLLMENT_UNAVAILABLE') from None
            if type(response) is dict and type(response.get('status')) is int and response['status'] >= 500 and attempt == 0:
                continue
            break
        if type(response) is not dict or type(response.get('status')) is not int or response['status'] != 200:
            raise EnrollmentError('ENROLLMENT_UNAVAILABLE')
        body = response.get('body')
        if (type(body) is not dict or set(body) != {'httpcode', 'version', 'Identity'}
                or type(body['httpcode']) is not int or body['httpcode'] != 200
                or type(body['version']) is not int or body['version'] != 1):
            raise EnrollmentError('INVALID_ENROLLMENT_RESPONSE')
        identity = body['Identity']
        if (not valid_identity(identity) or set(identity) != {'Id', 'NickName', 'Token'}
                or not re.fullmatch(r'Test[1-9][0-9]{0,9}', identity['NickName'])
                or not re.fullmatch('[0-9a-f]{48}', identity['Token'])):
            raise EnrollmentError('INVALID_ENROLLMENT_RESPONSE')
        target = directory / ('remote-client-' + str(identity['Id']) + '.json')
        if present(target):
            try:
                existing = read_json(target)
            except EnrollmentError as error:
                if str(error) != 'INVALID_LOCAL_JSON': raise
                existing = None
            if valid_identity(existing) and existing != identity:
                raise EnrollmentError('IDENTITY_CONFLICT')
        write_private(target, identity)
        if new_account:
            write_private(directory / 'loader-account-selection.json', {'version': 1, 'id': identity['Id']})
                                                                           
                                                                         
            if read_json(state_path) != state:
                raise EnrollmentError('INVALID_LOCAL_STATE')
            state_path.unlink()
        return identity


def select_account(root, identifier):
    root = Path(root).absolute(); ordinary(root, True)
    directory = root / 'data'; ordinary(directory, True); protect(directory, True)
    if type(identifier) is not int or not 1 <= identifier <= 2147483647:
        raise EnrollmentError('INVALID_ACCOUNT_SELECTION')
    with installation_lock(directory):
        matches = []
        for path in sorted(directory.glob('remote-client*.json')):
            if not re.fullmatch(r'remote-client[A-Za-z0-9_-]*\.json', path.name):
                continue
            value = read_json(path)
            if valid_identity(value) and value['Id'] == identifier:
                matches.append(value)
        if not matches or any(value['Token'] != matches[0]['Token'] for value in matches):
            raise EnrollmentError('INVALID_ACCOUNT_SELECTION')
        write_private(directory / 'loader-account-selection.json', {'version': 1, 'id': identifier})
        return matches[0]


def login_account(root, server, credentials, transport=None):
    if (type(credentials) is not dict or set(credentials) != {'UserName', 'Password'}
            or type(credentials['UserName']) is not str or not 1 <= len(credentials['UserName']) <= 64
            or any(unicodedata.category(c).startswith('C') for c in credentials['UserName'])
            or type(credentials['Password']) is not str or not re.fullmatch(r'[\x21-\x7e]{32,128}', credentials['Password'])):
        raise EnrollmentError('INVALID_LOGIN')
    root = Path(root).absolute(); ordinary(root, True)
    directory = root / 'data'; directory.mkdir(exist_ok=True); protect(directory, True)
    with installation_lock(directory):
        if transport is None:
            transport = PinnedEmulatorTransport(server, root / 'certs/server.crt', timeout_seconds=4)
        response = transport.request('POST', '/local/ClientEnrollment/Login', {'Version': 1, **credentials})
        body = response.get('body') if type(response) is dict and response.get('status') == 200 else None
        if (type(body) is not dict or set(body) != {'httpcode', 'version', 'Identity'}
                or type(body['httpcode']) is not int or body['httpcode'] != 200
                or type(body['version']) is not int or body['version'] != 1):
            raise EnrollmentError('INVALID_LOGIN')
        identity = body['Identity']
        if not valid_identity(identity) or set(identity) != {'Id', 'NickName', 'Token'} or identity['Token'] != credentials['Password']:
            raise EnrollmentError('INVALID_LOGIN')
        target = directory / ('remote-client-' + str(identity['Id']) + '.json')
        if present(target):
            existing = read_json(target)
            if not valid_identity(existing) or (existing['Id'], existing['Token']) != (identity['Id'], identity['Token']):
                raise EnrollmentError('IDENTITY_CONFLICT')
        write_private(target, identity)
        write_private(directory / 'loader-account-selection.json', {'version': 1, 'id': identity['Id']})
        return identity


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Prepare this installation for online play.')
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--server', required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--login', action='store_true')
    mode.add_argument('--new-account', action='store_true')
    mode.add_argument('--select-account', type=int)
    args = parser.parse_args(arguments)
    try:
        if args.login:
            raw = sys.stdin.buffer.read(2049)
            if len(raw) > 2048:
                raise EnrollmentError('INVALID_LOGIN')
            identity = login_account(args.root, args.server, json.loads(raw.decode('utf-8')))
        elif args.select_account is not None:
            identity = select_account(args.root, args.select_account)
        else:
            identity = ensure_identity(args.root, args.server, new_account=args.new_account)
    except Exception:
        print('CLIENT_ACCOUNT_UNAVAILABLE')
        return 1
    print('CLIENT_ACCOUNT_READY' + (' ' + str(identity['Id']) if args.login or args.new_account or args.select_account is not None else ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
