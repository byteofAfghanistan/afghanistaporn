                                                                                  
import hashlib
import hmac
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
import time
import uuid

HOST = 'apitest.zulaoyun.com'
MAX_RESPONSE = 64 * 1024
MAX_HEADERS = 16 * 1024
MAX_REQUEST = 8192
PATHS = frozenset(('/local/LauncherStatus', '/local/ClientEnrollment/Create', '/local/ClientEnrollment/Login', '/local/ClientCapabilities/Begin', '/local/ClientCapabilities/End', '/local/ClientCapabilities/Register',
                   '/local/ClientCapabilities/Renew', '/local/ClientCapabilities/Revoke'))


class ClientCapabilityTransportError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ClientCapabilityTransportError(code)


def begin_client_launch(transport, original_token, launch_id):
                                                                                 
    if type(original_token) is not str or not re.fullmatch(r'[\x21-\x7e]{32,128}', original_token):
        _fail('INVALID_LAUNCH_IDENTITY')
    try:
        parsed = uuid.UUID(launch_id)
        if str(parsed) != launch_id or parsed.variant != uuid.RFC_4122 or parsed.version not in range(1, 9):
            _fail('INVALID_LAUNCH_IDENTITY')
        result = transport.request('POST', '/local/ClientCapabilities/Begin', {'Token': original_token, 'LaunchId': launch_id})
        if type(result) is not dict or type(result.get('status')) is not int or result['status'] != 200:
            _fail('LAUNCH_IDENTITY_UNAVAILABLE')
        body = result.get('body')
        if (type(body) is not dict or set(body) != {'httpcode', 'version', 'LaunchId', 'Token'}
                or type(body['httpcode']) is not int or body['httpcode'] != 200
                or type(body['version']) is not int or body['version'] != 1 or body['LaunchId'] != launch_id
                or type(body['Token']) is not str or not re.fullmatch(r'[a-f0-9]{31}', body['Token'])):
            _fail('INVALID_LAUNCH_IDENTITY_RESPONSE')
        return body['Token']
    except ClientCapabilityTransportError:
        raise
    except Exception:
        raise ClientCapabilityTransportError('LAUNCH_IDENTITY_UNAVAILABLE') from None


class PinnedEmulatorTransport:
                                                                              

                                                                             
                                                                                                                     
                                                                               
                                                                           
                                                                   
       
    def __init__(self, server, certificate_file, timeout_seconds=3.0):
        try:
            address = ipaddress.IPv4Address(server)
            if str(address) != server or address.is_multicast or address.is_unspecified or str(address) == '255.255.255.255':
                _fail('INVALID_EMULATOR_ADDRESS')
            if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not math.isfinite(timeout_seconds) or not 0 < timeout_seconds <= 10:
                _fail('INVALID_EMULATOR_TIMEOUT')
            with Path(certificate_file).open('rb') as source:
                pem = source.read(MAX_RESPONSE + 1)
            if len(pem) > MAX_RESPONSE or pem.count(b'-----BEGIN CERTIFICATE-----') != 1 or pem.count(b'-----END CERTIFICATE-----') != 1:
                _fail('INVALID_EMULATOR_CERTIFICATE')
            der = ssl.PEM_cert_to_DER_cert(pem.decode('ascii').strip())
            self._pin = hashlib.sha256(der).digest()
        except ClientCapabilityTransportError:
            raise
        except Exception:
            raise ClientCapabilityTransportError('INVALID_EMULATOR_CONFIGURATION') from None
        self.server = server
        self.timeout_seconds = float(timeout_seconds)

    def request(self, method, path, payload=None):
        if path not in PATHS or method not in ('GET', 'POST') or (path == '/local/LauncherStatus') != (method == 'GET'):
            _fail('INVALID_EMULATOR_REQUEST')
        if method == 'GET' and payload is not None:
            _fail('INVALID_EMULATOR_REQUEST')
        try:
            if method == 'POST' and type(payload) is not dict:
                _fail('INVALID_EMULATOR_REQUEST')
            body = b'' if payload is None else json.dumps(payload, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
            if len(body) > MAX_REQUEST:
                _fail('EMULATOR_REQUEST_TOO_LARGE')
        except ClientCapabilityTransportError:
            raise
        except Exception:
            raise ClientCapabilityTransportError('INVALID_EMULATOR_REQUEST') from None
        deadline = time.monotonic() + self.timeout_seconds
        raw = wrapped = None

        def remaining():
            value = deadline - time.monotonic()
            if value <= 0:
                _fail('EMULATOR_TIMEOUT')
            return value

        def receive(count):
            wrapped.settimeout(remaining())
            result = wrapped.recv(count)
            remaining()
            return result

        try:
                                                                           
                                                                            
                                                                             
                                                                             
            for attempt in range(3):
                try:
                    raw = socket.create_connection((self.server, 443), timeout=min(1.0, remaining()))
                    break
                except (TimeoutError, socket.timeout):
                    if attempt == 2:
                        raise
                    remaining()
            raw.settimeout(remaining())
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            wrapped = context.wrap_socket(raw, server_hostname=HOST)
            raw = None
            remaining()
            certificate = wrapped.getpeercert(binary_form=True)
            if not certificate or not hmac.compare_digest(hashlib.sha256(certificate).digest(), self._pin):
                _fail('EMULATOR_CERTIFICATE_MISMATCH')
            headers = ('%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nAccept: application/json\r\n'
                       'Content-Type: application/json\r\nContent-Length: %d\r\n\r\n') % (method, path, HOST, len(body))
            wrapped.settimeout(remaining())
            wrapped.sendall(headers.encode('ascii') + body)
            remaining()
            received = bytearray()
            while b'\r\n\r\n' not in received:
                chunk = receive(4096)
                if not chunk:
                    _fail('INCOMPLETE_EMULATOR_RESPONSE')
                received.extend(chunk)
                marker = received.find(b'\r\n\r\n')
                if (marker < 0 and len(received) > MAX_HEADERS) or marker > MAX_HEADERS:
                    _fail('EMULATOR_HEADERS_TOO_LARGE')
            header, _, initial_body = bytes(received).partition(b'\r\n\r\n')
            rows = header.split(b'\r\n')
            status_line = re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9][0-9])(?: [\x20-\x7e]*)?', rows[0])
            if not status_line:
                _fail('INVALID_EMULATOR_RESPONSE')
            status = int(status_line.group(1))
            if status < 200 or 300 <= status < 400:
                _fail('EMULATOR_REDIRECT_OR_INTERIM_RESPONSE')
            fields = {}
            for row in rows[1:]:
                name, separator, value = row.partition(b':')
                if not separator or not re.fullmatch(rb'[A-Za-z0-9-]+', name) or any(byte < 32 or byte > 126 for byte in value):
                    _fail('INVALID_EMULATOR_HEADERS')
                key = name.lower()
                if key in fields:
                    _fail('DUPLICATE_EMULATOR_HEADER')
                fields[key] = value.strip()
            length = fields.get(b'content-length', b'')
            if b'transfer-encoding' in fields or not re.fullmatch(rb'[0-9]{1,6}', length):
                _fail('INVALID_EMULATOR_FRAMING')
            length = int(length)
            if length < 2 or length > MAX_RESPONSE:
                _fail('EMULATOR_RESPONSE_TOO_LARGE')
            if fields.get(b'content-type', b'').lower().split(b';', 1)[0].strip() != b'application/json':
                _fail('INVALID_EMULATOR_CONTENT_TYPE')
            result = bytearray(initial_body)
            if len(result) > length:
                _fail('INVALID_EMULATOR_FRAMING')
            while len(result) < length:
                chunk = receive(min(4096, length - len(result)))
                if not chunk:
                    _fail('INCOMPLETE_EMULATOR_RESPONSE')
                result.extend(chunk)
            parsed = json.loads(result.decode('utf8'), parse_constant=lambda _: _fail('INVALID_EMULATOR_JSON'))
            if type(parsed) is not dict:
                _fail('INVALID_EMULATOR_JSON')
            remaining()
            return {'status': status, 'body': parsed}
        except ClientCapabilityTransportError:
            raise
        except (TimeoutError, socket.timeout):
            raise ClientCapabilityTransportError('EMULATOR_TIMEOUT') from None
        except Exception:
            raise ClientCapabilityTransportError('EMULATOR_TRANSPORT_FAILURE') from None
        finally:
            for connection in (wrapped, raw):
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass


class ClientCapabilityLease:
                                                                            

                                                                           
                                                                              
                                                                             
                                                                        
       
    def __init__(self, transport, token, feature, proof_hash, launch_id, now=time.monotonic):
        if (not callable(getattr(transport, 'request', None)) or not callable(now)
                or type(token) is not str or not (re.fullmatch(r'[\x21-\x7e]{32,128}', token) or re.fullmatch(r'[a-f0-9]{31}', token))
                or type(feature) is not str or not re.fullmatch(r'[a-z][a-z0-9_.-]{0,63}', feature)
                or type(proof_hash) is not str or not re.fullmatch(r'[a-f0-9]{64}', proof_hash)):
            _fail('INVALID_CAPABILITY_CLIENT')
        try:
            parsed = uuid.UUID(launch_id)
            if str(parsed) != launch_id or parsed.variant != uuid.RFC_4122 or parsed.version not in range(1, 9):
                _fail('INVALID_CAPABILITY_CLIENT')
        except Exception:
            raise ClientCapabilityTransportError('INVALID_CAPABILITY_CLIENT') from None
        self._transport, self._token, self._now = transport, token, now
        self._feature, self._proof_hash, self._launch_id = feature, proof_hash, launch_id
        self._phase, self._reason = 'inactive', None
        self._last_clock = None
        self._next_request = 0.0
        self._valid_until = None
        self._failures = 0
        self._registered = False
        self._member_id = None

    def _clock(self):
        try:
            value = self._now()
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0 or self._last_clock is not None and value < self._last_clock:
                raise ValueError()
        except Exception:
            self._phase, self._reason = 'unavailable', 'invalid_clock'
            return None
        self._last_clock = float(value)
        return self._last_clock

    def _snapshot(self, at):
        return {'state': self._phase, 'reason': self._reason, 'feature': self._feature, 'launchId': self._launch_id,
                'expiresInMs': max(0, math.floor((self._valid_until - at) * 1000)) if self._valid_until is not None else 0}

    def snapshot(self):
        if self._phase == 'closed':
            return self._snapshot(self._last_clock or 0)
        at = self._clock()
        if at is not None and self._phase == 'active' and at >= self._valid_until:
            self._phase, self._reason = 'unavailable', 'lease_expired'
        return self._snapshot(at if at is not None else self._last_clock or 0)

    def activate(self, report):
        if (type(report) is not dict or report.get('active') is not True or report.get('feature') != self._feature
                or report.get('proofHash') != self._proof_hash or report.get('launchId') != self._launch_id):
            return False
        if self._phase in ('closed', 'unavailable'):
            return False
        if self._phase != 'inactive':
            return True
        at = self._clock()
        if at is None:
            return False
        self._phase, self._reason, self._next_request = 'registering', None, at
        return True

    def _accept(self, result, started, finished):
        if type(result) is not dict or type(result.get('status')) is not int:
            return False
        body = result.get('body')
        if (result['status'] != 200 or type(body) is not dict or type(body.get('httpcode')) is not int or body['httpcode'] != 200
                or type(body.get('version')) is not int or body['version'] != 1):
            return False
        lease = body.get('lease')
        if type(lease) is not dict or type(lease.get('version')) is not int or lease['version'] != 1 or lease.get('launchId') != self._launch_id:
            return False
        if type(lease.get('memberId')) is not int or not 1 <= lease['memberId'] <= 10000:
            return False
        if self._member_id is not None and lease['memberId'] != self._member_id:
            return False
        features = lease.get('features')
        if (type(features) is not list or len(features) != 1 or type(features[0]) is not dict
                or features[0].get('active') is not True or features != [{'name': self._feature, 'proofHash': self._proof_hash, 'active': True}]):
            return False
        for name in ('registeredAt', 'checkedAt', 'expiresAt'):
            if type(lease.get(name)) is not int or not 0 <= lease[name] <= 9007199254740991:
                return False
        remaining_ms = lease['expiresAt'] - lease['checkedAt']
        if lease['registeredAt'] > lease['checkedAt'] or not 0 < remaining_ms <= 3600000:
            return False
                                                                             
                                                                              
        valid_until = started + remaining_ms / 1000.0
        if finished >= valid_until:
            self._phase, self._reason = 'unavailable', 'lease_expired'
            return False
        self._phase, self._reason, self._registered = 'active', None, True
        self._member_id = lease['memberId']
        self._valid_until, self._failures = valid_until, 0
        self._next_request = finished + min(30.0, (valid_until - finished) / 3.0)
        return True

    def poll(self):
        if self._phase == 'closed':
            return self._snapshot(self._last_clock or 0)
        started = self._clock()
        if started is None:
            return self._snapshot(self._last_clock or 0)
        if self._phase == 'active' and started >= self._valid_until:
            self._phase, self._reason = 'unavailable', 'lease_expired'
        if self._phase in ('inactive', 'unavailable', 'closed') or started < self._next_request:
            return self._snapshot(started)
        action = 'Renew' if self._registered else 'Register'
        payload = {'Token': self._token, 'LaunchId': self._launch_id}
        if action == 'Register':
            payload['Features'] = [{'name': self._feature, 'proofHash': self._proof_hash, 'active': True}]
        try:
            result = self._transport.request('POST', '/local/ClientCapabilities/' + action, payload)
        except Exception:
            result = None
        finished = self._clock()
        if finished is None:
            return self._snapshot(self._last_clock or 0)
        status = result.get('status') if type(result) is dict else None
        if status == 200:
            if not self._accept(result, started, finished) and self._phase != 'unavailable':
                self._phase, self._reason = 'unavailable', 'invalid_lease_response'
        elif type(status) is int and 400 <= status < 500:
            self._phase, self._reason = 'unavailable', 'lease_rejected'
        else:
            self._failures = min(6, self._failures + 1)
            self._reason = 'transport_unavailable'
            if self._registered and finished >= self._valid_until:
                self._phase, self._reason = 'unavailable', 'lease_expired'
            else:
                delay = min(30.0, 2.0 ** (self._failures - 1))
                if self._registered:
                    delay = min(delay, (self._valid_until - finished) / 3.0)
                self._next_request = finished + delay
        return self._snapshot(finished)

    def close(self):
        if self._phase == 'closed':
            return self._snapshot(self._last_clock or 0)
                                                                             
                                                                          
        attempted = self._phase != 'inactive'
        self._phase, self._reason = 'closed', None
        self._valid_until = None
        if attempted:
            try:
                self._transport.request('POST', '/local/ClientCapabilities/Revoke',
                                        {'Token': self._token, 'LaunchId': self._launch_id})
            except Exception:
                pass
        return self._snapshot(self._last_clock or 0)
