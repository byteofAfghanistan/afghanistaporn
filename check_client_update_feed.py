                                                                                  
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import socket
import ssl
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import publish_client_update as publisher

PUBLIC_SPKI_SHA256='UPDATE_SPKI_SHA256_REQUIRED'


def request(path,limit,keep_body=False,seconds=20):
    if path!='/updates/v1/stable.json' and not re.fullmatch(r'/updates/v1/blobs/[0-9a-f]{64}',path):
        raise ValueError('Fixed public endpoint required')
    deadline=time.monotonic()+seconds
    def remaining():
        value=deadline-time.monotonic()
        if value<=0:raise TimeoutError('Public request deadline')
        return min(15,value)
    raw=socket.create_connection((publisher.SERVER_ADDRESS,443),timeout=min(5,remaining()))
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
    raw.settimeout(remaining())
    with raw:
        with context.wrap_socket(raw,server_hostname=publisher.HOST) as tls:
            if publisher.digest(tls.getpeercert(binary_form=True))!=publisher.CERTIFICATE_SHA256:
                raise ValueError('Public certificate pin mismatch')
            tls.settimeout(remaining());tls.sendall(('GET '+path+' HTTP/1.1\r\nHost: '+publisher.HOST+
                '\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii'))
            received=bytearray()
            while b'\r\n\r\n' not in received:
                tls.settimeout(remaining());chunk=tls.recv(4096)
                if not chunk:raise ValueError('Incomplete public header')
                received.extend(chunk)
                if len(received)>20480:raise ValueError('Public header bound')
            header,_,initial=bytes(received).partition(b'\r\n\r\n')
            if len(header)>16384:raise ValueError('Public header bound')
            lines=header.decode('ascii').split('\r\n');match=re.fullmatch(r'HTTP/1\.[01] ([1-5][0-9]{2})(?: [ -~]*)?',lines[0])
            if not match:raise ValueError('Invalid public status')
            fields={}
            for line in lines[1:]:
                name,separator,value=line.partition(':');name=name.lower()
                if not separator or not re.fullmatch(r'[a-z0-9!#$%&\x27*+.^_`|~-]+',name):raise ValueError('Public header name')
                fields.setdefault(name,[]).append(value.strip())
            if 'transfer-encoding' in fields or 'content-encoding' in fields:raise ValueError('Encoded public response')
            lengths=fields.get('content-length',[])
            if len(lengths)!=1 or not re.fullmatch(r'[0-9]+',lengths[0]):raise ValueError('Public response length')
            length=int(lengths[0])
            if not 0<=length<=limit or len(initial)>length:raise ValueError('Public response bound')
            count=len(initial);digest=hashlib.sha256(initial);body=bytearray(initial) if keep_body else None
            while count<length:
                tls.settimeout(remaining());chunk=tls.recv(min(65536,length-count))
                if not chunk:raise ValueError('Incomplete public body')
                count+=len(chunk);digest.update(chunk)
                if keep_body:body.extend(chunk)
            return {'status':int(match.group(1)),'size':count,'sha256':digest.hexdigest(),'body':bytes(body) if keep_body else None}


def public_key():
    value=publisher.strict_json((publisher.ROOT/'loader/update-public-key.json').read_bytes())
    key=rsa.RSAPublicNumbers(int.from_bytes(base64.b64decode(value['exponent'],validate=True),'big'),
        int.from_bytes(base64.b64decode(value['modulus'],validate=True),'big')).public_key()
    der=key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    if publisher.digest(der)!=PUBLIC_SPKI_SHA256:raise ValueError('Local public trust changed')
    return key


def check(expect_unpublished=False):
    response=request('/updates/v1/stable.json',publisher.MAX_ENVELOPE,True)
    if expect_unpublished:
        if response['status']!=404:raise ValueError('Unexpected published feed')
        missing=request('/updates/v1/blobs/'+'0'*64,1024)
        if missing['status']!=404:raise ValueError('Unknown blob exposed')
        return {'certificatePinned':True,'feedStatus':404,'unknownBlobStatus':404,'encodedResponse':False}
    if response['status']!=200:raise ValueError('Feed not available')
    value=publisher.verify_envelope(response['body'],public_key());verified=[]
    for row in value['files']:
        blob=request('/updates/v1/blobs/'+row['sha256'],row['size'],seconds=600)
        if (blob['status'],blob['size'],blob['sha256'])!=(200,row['size'],row['sha256']):raise ValueError('Public blob mismatch')
        verified.append({'path':row['path'],'size':row['size'],'sha256':row['sha256']})
    return {'certificatePinned':True,'signatureVerified':True,'sequence':value['sequence'],
        'feedSha256':response['sha256'],'files':verified,'encodedResponse':False}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--expect-unpublished',action='store_true')
    parser.add_argument('--report',type=Path);args=parser.parse_args();result=check(args.expect_unpublished)
    if args.report:args.report.write_bytes(publisher.encoded(result))
    print(json.dumps(result))
