                                                                      

                                                                              
                                                        
   
from dataclasses import dataclass,field
import ipaddress
import os
import re
from pathlib import Path
import uuid

from client_capability_lease import PinnedEmulatorTransport,ClientCapabilityTransportError,begin_client_launch
from emulator_pose_patch import validate_status

ROOT=Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class EmulatorLaunch:
    launch_id:str
    transport:object=field(repr=False)
    token:str=field(repr=False)

    def end(self, *, native_ended=False):
                                                                               

                                                                              
                                                                              
                                                                           
           
        if native_ended is not True:
            return False
        for _ in range(2):
            try:
                response=self.transport.request('POST','/local/ClientCapabilities/End',
                    {'Token':self.token,'LaunchId':self.launch_id})
                body=response.get('body') if type(response) is dict else None
                if (type(response) is dict and type(response.get('status')) is int and response['status']==200
                        and type(body) is dict and set(body)=={'httpcode','version','LaunchId','Ended'}
                        and type(body['httpcode']) is int and body['httpcode']==200
                        and type(body['version']) is int and body['version']==1
                        and body['LaunchId']==self.launch_id and body['Ended'] is True):
                    return True
            except Exception:
                pass
        return False

    def game_arguments(self,arguments):
        result=list(arguments)
        for flag in ('-ip','-pl'):
            if result.count(flag)!=1 or result.index(flag)+1>=len(result):
                raise ClientCapabilityTransportError('INVALID_EMULATOR_LAUNCH_ARGUMENTS')
            result[result.index(flag)+1]=self.token
        return result


class LauncherStop:
                                                                             
    def __init__(self):
        self.handle=None
        name=os.environ.get('ZULA_LAUNCHER_STOP_EVENT','')
        if not re.fullmatch(r'Local\\ZulaLoader-Stop-[a-f0-9]{32}',name):
            return
        try:
            import ctypes
            from ctypes import wintypes
            self.kernel=ctypes.WinDLL('kernel32',use_last_error=True)
            self.kernel.OpenEventW.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.LPCWSTR]
            self.kernel.OpenEventW.restype=wintypes.HANDLE
            self.kernel.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
            self.kernel.WaitForSingleObject.restype=wintypes.DWORD
            self.kernel.CloseHandle.argtypes=[wintypes.HANDLE]
            self.kernel.CloseHandle.restype=wintypes.BOOL
            self.handle=self.kernel.OpenEventW(0x00100000,False,name) or None
        except Exception:
            self.handle=None

    def requested(self):
        return self.handle is not None and self.kernel.WaitForSingleObject(self.handle,0)==0

    def close(self):
        if self.handle is not None:
            handle,self.handle=self.handle,None
            self.kernel.CloseHandle(handle)


def prepare_emulator_launch(original_token,server=None,root=ROOT,launch_id=None,transport=None,advertised_server=None):
                                                                              

                                                                            
                                                                               
                                                                              
       
    try:
        identifier=str(uuid.UUID(launch_id)) if launch_id is not None else str(uuid.uuid4())
        selected=server or '127.0.0.1'
        expected=advertised_server or (server if server else os.environ.get('ZULA_GAME_HOST','127.0.0.1'))
        for value in (selected,expected):
            address=ipaddress.IPv4Address(value)
            if str(address)!=value or int(value.split('.')[0])==0 or int(value.split('.')[0])>=224:
                raise ValueError('invalid address')
        if transport is None:transport=PinnedEmulatorTransport(selected,Path(root)/'certs/server.crt')
        response=transport.request('GET','/local/LauncherStatus')
        if type(response) is not dict or type(response.get('status')) is not int or response['status']!=200:
            raise ValueError('not ready')
        validate_status(response.get('body'),expected)
    except Exception:
        raise ClientCapabilityTransportError('EMULATOR_LAUNCH_NOT_READY') from None
                                                                              
                                                                        
    token=begin_client_launch(transport,original_token,identifier)
    return EmulatorLaunch(identifier,transport,token)
