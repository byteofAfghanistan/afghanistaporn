                                                                                   
import base64
import hashlib
from pathlib import Path
import ssl

CURL_SHA256 = '4b8d3703b737cf294a486dbb0fd1a2bee4961ae6a55b56ece45ee8687977b7f1'
MAX_CERTIFICATE_BYTES = 65536


def _tlv(data, offset, limit):
    start = offset
    if offset + 2 > limit:
        raise ValueError('Truncated certificate DER')
    tag, length = data[offset:offset + 2]
    offset += 2
    if tag & 31 == 31:
        raise ValueError('Unsupported certificate DER tag')
    if length & 128:
        size = length & 127
        if not 1 <= size <= 4 or offset + size > limit or data[offset] == 0:
            raise ValueError('Invalid certificate DER length')
        length = int.from_bytes(data[offset:offset + size], 'big')
        if length < 128:
            raise ValueError('Noncanonical certificate DER length')
        offset += size
    end = offset + length
    if end > limit:
        raise ValueError('Truncated certificate DER content')
    return tag, start, offset, end


def _children(data, content, end):
    rows = []
    while content < end:
        if len(rows) >= 32:
            raise ValueError('Certificate DER structure exceeds limit')
        row = _tlv(data, content, end)
        rows.append(row)
        content = row[3]
    return rows


def spki_pin(pem):
    if not isinstance(pem, bytes) or len(pem) > MAX_CERTIFICATE_BYTES:
        raise ValueError('Invalid public certificate size')
    text = pem.decode('ascii').strip()
    if text.count('-----BEGIN CERTIFICATE-----') != 1 or text.count('-----END CERTIFICATE-----') != 1:
        raise ValueError('Exactly one public certificate is required')
    der = ssl.PEM_cert_to_DER_cert(text)
    outer = _tlv(der, 0, len(der))
    if outer[0] != 0x30 or outer[3] != len(der):
        raise ValueError('Invalid certificate DER envelope')
    certificate = _children(der, outer[2], outer[3])
    if [row[0] for row in certificate] != [0x30, 0x30, 3]:
        raise ValueError('Invalid certificate DER fields')
    tbs = _children(der, certificate[0][2], certificate[0][3])
    if tbs and tbs[0][0] == 0xa0:
        tbs = tbs[1:]
    if len(tbs) < 6 or [row[0] for row in tbs[:6]] != [2, 0x30, 0x30, 0x30, 0x30, 0x30]:
        raise ValueError('Missing certificate SubjectPublicKeyInfo')
    spki = tbs[5]
    key = _children(der, spki[2], spki[3])
    if [row[0] for row in key] != [0x30, 3] or key[1][3] - key[1][2] < 2 or der[key[1][2]] != 0:
        raise ValueError('Invalid SubjectPublicKeyInfo')
    return 'sha256//' + base64.b64encode(hashlib.sha256(der[spki[1]:spki[3]]).digest()).decode('ascii')


def prepare_remote_tls(root, game_directory):
                                                                               
                                                                              
    with (Path(root) / 'certs' / 'server.crt').open('rb') as source:
        pem = source.read(MAX_CERTIFICATE_BYTES + 1)
    with (Path(game_directory) / 'libcurl.dll').open('rb') as source:
        binary = source.read(2 * 1024 * 1024 + 1)
    if len(binary) > 2 * 1024 * 1024 or hashlib.sha256(binary).hexdigest() != CURL_SHA256:
        raise ValueError('Remote TLS pin requires the verified native libcurl build')
    return {'pin': spki_pin(pem), 'curlSha256': CURL_SHA256,
            'curlPath': str((Path(game_directory) / 'libcurl.dll').resolve())}
