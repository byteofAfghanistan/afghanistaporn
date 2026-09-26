                                                                   

                                                                           
                                                                             
   
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import threading
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
FEATURE='escort_target_pose_v1'
INSTALLER='tools/frida_escort_pose.js'
CLIENT_MANIFEST='resources/escort_client_patch.json'
SOURCE_MANIFEST='server/escort_client_patch.json'
MAX_MANIFEST=128*1024
MAX_INSTALLER=256*1024
REASONS=frozenset(('installed','fingerprint','not_initial_lobby','allocation_failed','protection_failed',
                  'quiescence_lost','rollback_failed','write_failed','timeout','discovery_failed',
                  'platform_or_pin','installer_unavailable','launcher_stopped'))


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode('utf-8')


def _bounded(file,limit):
    with Path(file).open('rb') as source:raw=source.read(limit+1)
    if not raw or len(raw)>limit:raise ValueError('manifest_invalid')
    return raw


def _manifest_path(root):
                                                                            
                                                                            
                                                                              
                                                                              
    for relative in (CLIENT_MANIFEST,SOURCE_MANIFEST):
        candidate=root/relative
        try:directory=candidate.parent.lstat()
        except FileNotFoundError:continue
        if not stat.S_ISDIR(directory.st_mode) or getattr(directory,'st_file_attributes',0)&0x400:
            raise ValueError('manifest_invalid')
        try:info=candidate.lstat()
        except FileNotFoundError:continue
        if not stat.S_ISREG(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
            raise ValueError('manifest_invalid')
        return candidate
    raise ValueError('manifest_invalid')


def read_manifest(root=ROOT):
    root=Path(root)
    document=json.loads(_bounded(_manifest_path(root),MAX_MANIFEST))
    if type(document) is not dict or type(document.get('version')) is not int or document['version']!=1 or document.get('feature')!=FEATURE:raise ValueError('manifest_invalid')
    payload={key:value for key,value in document.items() if key!='proofHash'}
    if hashlib.sha256(_canonical(payload)).hexdigest()!=document.get('proofHash'):raise ValueError('manifest_invalid')
    if document.get('installer',{}).get('file')!=INSTALLER:raise ValueError('manifest_invalid')
    script=_bounded(root/INSTALLER,MAX_INSTALLER)
    if hashlib.sha256(script).hexdigest()!=document['installer'].get('sha256'):raise ValueError('installer_changed')
    return document,script.decode('utf-8')


def validate_status(value,expected_server):
    if type(value) is not dict or set(value)!={'version','serverHost','port','portCount','readyPorts','ready'}:raise ValueError('pin_failed')
    port,count=value['port'],value['portCount'];ports=value['readyPorts']
    if type(value['version']) is not int or value['version']!=1 or value['serverHost']!=expected_server or value['ready'] is not True:raise ValueError('pin_failed')
    if type(port) is not int or type(count) is not int or not 1<=port<=65535 or not 1<=count<=64 or port+count-1>65535:raise ValueError('pin_failed')
    if type(ports) is not list or len(ports)!=count or any(type(n) is not int for n in ports) or sorted(ports)!=list(range(port,port+count)):raise ValueError('pin_failed')
    return copy.deepcopy(value)


class EmulatorPosePatch:
    def __init__(self,enabled=False,server=None,root=ROOT,launch_id=None,on_report=None,on_authenticated=None,
                 transport=None,clock=time.monotonic,advertised_server=None):
        self.enabled=enabled is True;self.server=server or '127.0.0.1';self.root=Path(root)
        self.launch_id=str(uuid.UUID(launch_id)) if launch_id is not None else str(uuid.uuid4())
        self.on_report=on_report;self.on_authenticated=on_authenticated;self.transport=transport;self.clock=clock
                                                                                
                                                                                
        self.expected_server=advertised_server or (server if server else os.environ.get('ZULA_GAME_HOST','127.0.0.1'))
        self.manifest=None;self._script='';self._prepared=False;self._started=None;self._report=None
        self._pending=[];self._authenticated=False;self._auth_dispatched=False;self._lock=threading.Lock()
        self.callback_failed=False

    def _queue(self,report):
        with self._lock:
            if self._report is not None:return
            self._report=copy.deepcopy(report);self._pending.append(copy.deepcopy(report))

    def unavailable(self,reason):
        self._queue(dict(kind='escort_pose_patch',version=1,feature=FEATURE,
                         proofHash=self.manifest['proofHash'] if self.manifest else None,
                         launchId=self.launch_id,active=False,reason=reason))

    def prepare(self):
        if not self.enabled:self.unavailable('disabled');return False
        try:
            self.manifest,self._script=read_manifest(self.root)
        except Exception:
            self.unavailable('manifest_invalid');return False
        try:
            for text in (self.server,self.expected_server):
                address=ipaddress.IPv4Address(text)
                if str(address)!=text or int(text.split('.')[0])==0 or int(text.split('.')[0])>=224:raise ValueError('pin_failed')
            if self.transport is None:
                from client_capability_lease import PinnedEmulatorTransport
                self.transport=PinnedEmulatorTransport(self.server,self.root/'certs/server.crt')
            response=self.transport.request('GET','/local/LauncherStatus')
            if response.get('status')!=200:raise ValueError('pin_failed')
            validate_status(response.get('body'),self.expected_server)
        except Exception:
            self.unavailable('pin_failed');return False
        self._prepared=True;return True

    def script_source(self):
        if not self._prepared:return ''
        if self._started is None:self._started=self.clock()
        config=dict(enabled=True,pinned=True,manifest=self.manifest,launchId=self.launch_id)
        fallback=dict(kind='escort_pose_patch',version=1,feature=FEATURE,proofHash=self.manifest['proofHash'],
                      launchId=self.launch_id,active=False,reason='installer_unavailable')
        return self._script+'\ntry { startZulaEscortPosePatch('+_canonical(config).decode()+'); } catch (_) { send('+_canonical(fallback).decode()+'); }\n'

    def accept_message(self,message):
        payload=message.get('payload') if type(message) is dict and message.get('type')=='send' else None
        if type(payload) is not dict or payload.get('kind')!='escort_pose_patch':return False
                                                                               
                                                                          
        try:
            allowed={'kind','version','feature','proofHash','launchId','active','reason','sourceHashes','anchor','sites'}
            if not self._prepared or len(_canonical(payload))>4096 or set(payload)-allowed:return True
            if type(payload.get('version')) is not int or payload['version']!=1 or payload.get('feature')!=FEATURE or payload.get('proofHash')!=self.manifest['proofHash'] or payload.get('launchId')!=self.launch_id:return True
            if type(payload.get('active')) is not bool or payload.get('reason') not in REASONS:return True
            if payload['active']:
                expected={row['name']:row['sha256'] for row in self.manifest['source']['functions']}
                if payload['reason']!='installed' or payload.get('sourceHashes')!=expected:return True
                if not re.fullmatch(r'0x[0-9a-f]{1,8}',payload.get('anchor','')):return True
                sites=payload.get('sites')
                if type(sites) is not list or len(sites)!=3 or not all(type(s) is str and re.fullmatch(r'0x[0-9a-f]{1,8}',s) for s in sites):return True
            elif payload['reason']=='installed' or set(payload)&{'sourceHashes','anchor','sites'}:return True
            self._queue(payload)
        except Exception:pass
        return True

    def notify_authenticated(self):
        self._authenticated=True

    def poll(self):
        if self._prepared and self._started is not None and self.clock()-self._started>=95:self.unavailable('timeout')
        with self._lock:pending=self._pending;self._pending=[];report=copy.deepcopy(self._report)
        for value in pending:
            if self.on_report is not None:
                try:self.on_report(value)
                except Exception:self.callback_failed=True
        if self._authenticated and report and report['active'] and not self._auth_dispatched and self.on_authenticated is not None:
            self._auth_dispatched=True
            try:self.on_authenticated(copy.deepcopy(report))
            except Exception:self.callback_failed=True
        return report

    def close(self):
        self.unavailable('launcher_stopped');return self.poll()
