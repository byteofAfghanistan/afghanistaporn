# -*- coding: utf-8 -*-
    
                                                                                               

                                                                    
                                                                          
                                                                                                    
                                                                                                            
                                                                                                      
                                      
                                                                         
                                                                              
                                                                            
                                                                                   
                                                        

                                                            
                                                                                                               
                                                                                    
   
import argparse
import ipaddress
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid
try:
    import frida
except ImportError:
    print("[FATAL] frida yok. Kur: pip install frida frida-tools", flush=True); sys.exit(1)

GAME_DIR = r"C:\Program Files (x86)\Steam\steamapps\common\Zula EU\Game"
GAME_DIR = os.path.abspath(os.environ.get("ZULA_GAME_DIR", GAME_DIR))
GAME_EXE = os.path.join(GAME_DIR, "zula.exe")
TOKEN = ""                                                                             
WANT_PARSE = "--parse" in sys.argv

                                                                                                              
ARGS = ["-diag", "-d", "defLOG=1", "-nx", "280",
        "-d", "defGSQ_0", "-d", "defGTQ_0", "-d", "defGMQ_0", "-d", "defGPQ_1", "-d", "defLENG",
        "-ip", TOKEN, "-pl", TOKEN, "-nc"]

JS = r"""
'use strict';
var WANT_PARSE = %PARSE%;
var done = {};
function log(tag, msg){ send({tag: tag, msg: msg}); }

                                                                                              
function findExp(mods, name){
  try { if (typeof Module.findGlobalExportByName === 'function'){ var g = Module.findGlobalExportByName(name); if (g && !g.isNull()) return g; } } catch(e){}
  for (var i=0;i<mods.length;i++){
    try {
      var m = (typeof Process.findModuleByName === 'function') ? Process.findModuleByName(mods[i]) : null;
      if (m){
        if (typeof m.findExportByName === 'function'){ var p=m.findExportByName(name); if(p && !p.isNull()) return p; }
        if (typeof m.getExportByName === 'function'){ try{ var q=m.getExportByName(name); if(q) return q; }catch(e){} }
      }
    } catch(e){}
    try { if (typeof Module.findExportByName === 'function'){ var r=Module.findExportByName(mods[i], name); if(r) return r; } } catch(e){}
  }
  return null;
}

var SSL_MODS = ['ssleay32.dll','libssl-1_1.dll','libssl.dll','libssl-3.dll'];
var CRY_MODS = ['libeay32.dll','libcrypto-1_1.dll','libcrypto.dll','libcrypto-3.dll'];

function hookTLS(){
  ['SSL_CTX_set_verify','SSL_set_verify'].forEach(function(fn){
    if(done[fn]) return;
    var p = findExp(SSL_MODS, fn);
    if(p){ Interceptor.attach(p, { onEnter: function(a){ a[1]=ptr(0); a[2]=ptr(0); } });
           done[fn]=1; log('TLS','hooked '+fn+' (verify-off)'); }
  });
  if(!done['SSL_get_verify_result']){
    var g = findExp(SSL_MODS,'SSL_get_verify_result');
    if(g){ Interceptor.attach(g,{ onLeave:function(r){ r.replace(0); } }); done['SSL_get_verify_result']=1; log('TLS','hooked SSL_get_verify_result->0'); }
  }
  if(!done['X509_verify_cert']){
    var x = findExp(CRY_MODS,'X509_verify_cert');
    if(x){ Interceptor.attach(x,{ onLeave:function(r){ r.replace(1); } }); done['X509_verify_cert']=1; log('TLS','hooked X509_verify_cert->1'); }
  }
}

function hookCurl(){
  if(done['curl']) return;
                                                                            
                                                                             
  if(globalThis.zulaRemoteTLS){ done['curl']=1; return; }
  var p = findExp(['libcurl.dll'],'curl_easy_setopt');
  if(!p) return;
  Interceptor.attach(p, { onEnter: function(a){
    var opt = a[1].toInt32();
    if(opt === 10002){                                                  
      try {
        var url = a[2].readCString();
        if (typeof globalThis.zulaRemoteURL === 'function') {
          var mapped = globalThis.zulaRemoteURL(url);
          if (mapped !== null) { this.remoteURL = Memory.allocUtf8String(mapped); a[2] = this.remoteURL; url = mapped; }
        }
        log('CURL', url);
      } catch(e){}
    }
  }});
  done['curl']=1; log('CURL','hooked curl_easy_setopt (CURLOPT_URL)');
}

function hookParse(){
  if(!WANT_PARSE || done['parse']) return;
  var jl = findExp(['Jansson.dll'],'json_loads');
  if(!jl) return;
  Interceptor.attach(jl, { onEnter:function(a){ try{ log('PARSE','json_loads <- '+a[0].readCString().substr(0,200)); }catch(e){} } });
  var as = findExp(['Jansson.dll'],'json_array_size');
  if(as) Interceptor.attach(as,{ onLeave:function(r){ log('PARSE','json_array_size = '+r.toInt32()); } });
  var sv = findExp(['Jansson.dll'],'json_string_value');
  if(sv) Interceptor.attach(sv,{ onLeave:function(r){ try{ log('PARSE','json_string_value = '+(r.isNull()?'NULL':r.readCString().substr(0,80))); }catch(e){} } });
  done['parse']=1; log('PARSE','Jansson hook kuruldu (DIKKAT: curl-multi bozabilir)');
}

                                                       
var tries=0;
var iv = setInterval(function(){
  tries++;
  hookTLS(); hookCurl(); hookParse();
  if(tries>200) clearInterval(iv);          
}, 50);
log('BOOT','frida script yuklendi, hook-poll basladi (parse='+WANT_PARSE+')');
""".replace("%PARSE%", "true" if WANT_PARSE else "false")

                                                                             
                                                                              
EMULATOR_NETWORK_JS = r"""
(function (root) {
  'use strict';
  const SOURCE = [
    {name:'CURL_Load_ServerList',offset:0x990,relative:27860557,length:3797,sha256:'e0480d40920dcc63780b0914fe0664aa4d02aa8a537f25af505c093a1c558ce9'},
    {name:'anet_cl_start',offset:0x3f14,relative:35128010,length:23979,sha256:'b1498a3f7f8089b146e91bd4a1e7a3d412d7452b6634ba3def6c3a22756bfff4'},
    {name:'cl_game_loop',offset:0x4068,relative:35127745,length:265,sha256:'26d98191376974d0ed587a5780f1111e6bbc5e49fd1ce2d5b28122a445413b78'},
    {name:'anet_main_run',offset:0x3f1c,relative:26637035,length:1795,sha256:'7c1615312b4e3d2d1b699e4ad18ab9425b801589e1cadbdfab76de64d9b421c3'},
    {name:'anet_cl_exit',offset:0x3f10,relative:35127483,length:262,sha256:'6e2cfbb199bca5be7fe922e107b14c634c74f8a13f26bd7607299b95a9a75b81'}
  ];
  const SITES = [
    {offset:19862,original:[0xff,0xd0],replacement:[0x90,0x90]},
    {offset:19870,original:[0x8b,0x83,0x74,0x6e,0x91,0x01],replacement:[0xb8,0,0,0,0,0x90]}
  ];
  const ZERO_GLOBALS = [0x17f1acc,0x17f19e4,0x14e40,25106984,0x17ef2fc,0x17ef304,0x17ef300];
  const equal=(a,b)=>a.length===b.length&&a.every((value,index)=>value===b[index]);
  function createInstaller(env,enabled) {
    let finished=false,active=false,installing=false;
    function publish(code) {
      finished=true;active=code==='INSTALLED';
      try{env.report(code);}catch(_){}
      return active;
    }
    function quiescent(anchor) {return ZERO_GLOBALS.every(offset=>env.read32(anchor+offset)===0);}
    function verify(anchor) {
      for(const row of SOURCE) {
        const address=env.read32(anchor+row.offset);
        if(address!==anchor+row.relative||!env.executable(address,row.length)||
          env.hash(address,row.length)!==row.sha256)throw Error('SOURCE_REJECTED');
      }
      return env.read32(anchor+0x3f14);
    }
    function attempt(anchor,returnAddress) {
      if(!enabled||finished||installing)return false;
                                                                          
                                                                             
      try{if(returnAddress!==env.read32(anchor+0x990)+659)return false;}catch(_){return false;}
      installing=true;
      const written=[];
      try {
        if(!quiescent(anchor))throw Error('SOURCE_REJECTED');
        const target=verify(anchor);
        for(const site of SITES) {
          const address=target+site.offset;
          if(!quiescent(anchor)||!equal(env.read(address,site.original.length),site.original))throw Error('SOURCE_REJECTED');
          written.push({address,site});                                     
          env.patch(address,site.replacement);
          if(!equal(env.read(address,site.replacement.length),site.replacement)||!env.flush(address,site.replacement.length))
            throw Error('INSTALL_FAILED');
        }
        if(!quiescent(anchor))throw Error('INSTALL_FAILED');
        return publish('INSTALLED');
      }catch(error) {
        let restored=true;
        for(const entry of written.reverse()) {
          try {
            if(!quiescent(anchor))throw Error('not_quiescent');
            const actual=env.read(entry.address,entry.site.original.length);
            if(!equal(actual,entry.site.original)&&!equal(actual,entry.site.replacement))throw Error('not_owned');
            if(!equal(actual,entry.site.original))env.patch(entry.address,entry.site.original);
            if(!equal(env.read(entry.address,entry.site.original.length),entry.site.original)||
              !env.flush(entry.address,entry.site.original.length))throw Error('not_restored');
          }catch(_){restored=false;}
        }
        return publish(!restored?'ROLLBACK_FAILED':error.message==='SOURCE_REJECTED'?'SOURCE_REJECTED':'INSTALL_FAILED');
      }finally{installing=false;}
    }
    return {attempt,status:()=>({finished,active}),timeout:()=>{if(!finished)publish('DISCOVERY_TIMEOUT');}};
  }
  function start(config) {
    if(!config||config.emulator!==true||config.pinned!==true)return null;
    if(root.zulaEmulatorNetwork)return root.zulaEmulatorNetwork;
    let discovery=null,timer=null,expiry=null;
    function detach() {
      if(timer!==null){clearInterval(timer);timer=null;}
      if(expiry!==null){clearTimeout(expiry);expiry=null;}
      if(discovery){discovery.detach();discovery=null;}
    }
    function report(code) {
      try{send({tag:'EMULATOR-NET',msg:code});}finally{setImmediate(detach);}
    }
    try {
      if(Process.platform!=='windows'||Process.arch!=='ia32'||Process.pointerSize!==4)throw Error('platform');
      const kernel=Process.getModuleByName('kernel32.dll');
      const options={abi:'stdcall',scheduling:'exclusive',traps:'none'};
      const flush=new NativeFunction(kernel.getExportByName('FlushInstructionCache'),'bool',['pointer','pointer','uint'],options);
      const current=new NativeFunction(kernel.getExportByName('GetCurrentProcess'),'pointer',[],options)();
      const env={
        read32:address=>ptr(address).readU32(),read:(address,length)=>Array.from(new Uint8Array(ptr(address).readByteArray(length))),
        executable:(address,length)=>{const r=Process.findRangeByAddress(ptr(address));return !!r&&r.protection.includes('x')&&address+length<=r.base.toUInt32()+r.size;},
        hash:(address,length)=>Checksum.compute('sha256',ptr(address).readByteArray(length)),
        patch:(address,value)=>{
          const target=ptr(address),original=Memory.queryProtection(target);
          try{Memory.patchCode(target,value.length,writable=>writable.writeByteArray(value));}
          finally{if(Memory.queryProtection(target)!==original&&(!Memory.protect(target,value.length,original)||Memory.queryProtection(target)!==original))throw Error('protection');}
        },flush:(address,length)=>flush(current,ptr(address),length),report
      };
      const installer=createInstaller(env,true);root.zulaEmulatorNetwork=installer;
      function discover() {
        if(installer.status().finished||discovery)return;
        const module=Process.enumerateModules().find(value=>value.name.toLowerCase()==='jansson.dll');if(!module)return;
        const target=module.findExportByName('json_loads');if(!target)return;
        discovery=Interceptor.attach(target,{onEnter(){installer.attempt(this.context.ebx.toUInt32(),this.returnAddress.toUInt32());}});
      }
      discover();timer=setInterval(()=>{try{discover();}catch(_){installer.timeout();}},100);
      expiry=setTimeout(()=>installer.timeout(),90000);
      return installer;
    }catch(_){report('INSTALL_FAILED');return null;}
  }
  root.startZulaEmulatorNetwork=start;
  if(typeof module==='object'&&module.exports)module.exports={SOURCE,SITES,ZERO_GLOBALS,createInstaller,start};
})(globalThis);
"""

                                                                                   
                                                                      
EMULATOR_ROOM_JS = r"""
(function(root){
  'use strict';
  const SOURCE=[
    {name:'CURL_Load_ServerList',offset:0x990,relative:27860557,length:3797,sha256:'e0480d40920dcc63780b0914fe0664aa4d02aa8a537f25af505c093a1c558ce9'},
    {name:'CURL_Handle_UpdateMemberRoomState',offset:0x8ec,relative:27797310,length:628,sha256:'9246708e80ac5f5bc6ac6b9176414c02328df4502eaf4d539c4861d2787a502f'},
    {name:'CURL_UpdateMemberRoomState',offset:0xaa0,relative:27797938,length:847,sha256:'1a3fe99d86bda160777adaa693b85a1d2d59df2b58ce27b828671092b67df577'},
    {name:'CURL_Process_GetRoomPlayers',offset:0xa00,relative:27772597,length:24509,sha256:'47a3f5d417c523ca42cbfccee1673979b0d799e15b7f86e3df31d9a9a6fa9b28'},
    {name:'CURL_MemberState_Loop',offset:0x9b0,relative:27501385,length:4798,sha256:'2da0bd910dad3cb0b53708c16aaab65ceb219d7febca30a60bdc386b0382b219'}
  ];
  const SITE={offset:605,original:[0x8b,0x83,0xbc,0x2c,0x8b,0x01]};
  const GLOBALS={state:0x17f1acc,connection:0x17edc90,socket:0x17edc7c,ready:0x182a7e4,given:0x182a498,interval:0x182a7e8,timer:0x17edc6c};
  const equal=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  const word=v=>[v&255,(v>>>8)&255,(v>>>16)&255,(v>>>24)&255];
  function thunk(){
    const bytes=[0x9c,0x50],branches=[];
    const emit=(...items)=>bytes.push(...items),jump=op=>{emit(op,0);branches.push(bytes.length-1);};
                                                                             
                                                                              
    emit(0x83,0xbb,...word(GLOBALS.state),0);jump(0x75);
    emit(0x83,0xbb,...word(GLOBALS.connection),2);jump(0x75);
    emit(0x80,0xbb,...word(GLOBALS.socket),0);jump(0x75);
    emit(0x8b,0x83,...word(GLOBALS.ready),0x83,0xf8,2);jump(0x77);
    emit(0x85,0xc0,0x0f,0x95,0xc0,0x0f,0xb6,0xc0,0xc1,0xe0,10,0x89,0x83,...word(GLOBALS.given));
                                                                            
                                                                              
    emit(0x8b,0x83,...word(GLOBALS.interval),0x85,0xc0);jump(0x7e);
    emit(0x3d,...word(60000*1024));jump(0x77);
    emit(0x8d,0x84,0x00,...word(1024),0x89,0x83,...word(GLOBALS.timer));
    const end=bytes.length;emit(0x58,0x9d,...SITE.original,0xc3);
    for(const at of branches){const distance=end-at-1;if(distance>127)throw Error('thunk');bytes[at]=distance;}
    return bytes;
  }
  function createInstaller(env,enabled){
    let finished=false,active=false,installing=false;
    const publish=code=>{finished=true;active=code==='INSTALLED';try{env.report(code);}catch(_){}return active;};
    const quiet=anchor=>env.read32(anchor+GLOBALS.state)===0&&env.read32(anchor+0x17f19e4)===0&&env.read32(anchor+0x14e40)===0;
    function attempt(anchor,returnAddress){
      if(!enabled||finished||installing)return false;
      try{if(returnAddress!==env.read32(anchor+0x990)+659)return false;}catch(_){return false;}
      installing=true;let address=null,replacement=null,written=false;
      try{
        if(!quiet(anchor)||env.read32(anchor+0x18b2cbc)!==0)throw Error('SOURCE_REJECTED');
        for(const row of SOURCE){const p=env.read32(anchor+row.offset);if(p!==anchor+row.relative||!env.executable(p,row.length)||env.hash(p,row.length)!==row.sha256)throw Error('SOURCE_REJECTED');}
        address=env.read32(anchor+0x8ec)+SITE.offset;
        if(!equal(env.read(address,6),SITE.original))throw Error('SOURCE_REJECTED');
        const code=thunk(),target=env.allocate(code);
        if(!Number.isInteger(target)||target<1||target>0xffffffff-code.length||!env.executable(target,code.length)||!equal(env.read(target,code.length),code)||!env.flush(target,code.length))throw Error('INSTALL_FAILED');
        replacement=[0xe8,...word((target-address-5)>>>0),0x90];
        if(!quiet(anchor)||!equal(env.read(address,6),SITE.original))throw Error('SOURCE_REJECTED');
        written=true;env.patch(address,replacement);
        if(!equal(env.read(address,6),replacement)||!env.flush(address,6)||!quiet(anchor))throw Error('INSTALL_FAILED');
        return publish('INSTALLED');
      }catch(error){
        let restored=true;
        if(written)try{const current=env.read(address,6);if(!quiet(anchor)||(!equal(current,SITE.original)&&!equal(current,replacement)))throw Error('ownership');env.patch(address,SITE.original);if(!equal(env.read(address,6),SITE.original)||!env.flush(address,6))throw Error('restore');}catch(_){restored=false;}
        return publish(!restored?'ROLLBACK_FAILED':error.message==='SOURCE_REJECTED'?'SOURCE_REJECTED':'INSTALL_FAILED');
      }finally{installing=false;}
    }
    return {attempt,status:()=>({finished,active}),timeout:()=>{if(!finished)publish('DISCOVERY_TIMEOUT');}};
  }
  function start(config){
    if(!config||config.emulator!==true||config.pinned!==true)return null;
    if(root.zulaEmulatorRoom)return root.zulaEmulatorRoom;
    let discovery=null,timer=null,expiry=null;const allocations=[];
    const detach=()=>{if(timer!==null){clearInterval(timer);timer=null;}if(expiry!==null){clearTimeout(expiry);expiry=null;}if(discovery){discovery.detach();discovery=null;}};
    const report=code=>{try{send({tag:'EMULATOR-ROOM',msg:code});}finally{setImmediate(detach);}};
    try{
      if(Process.platform!=='windows'||Process.arch!=='ia32'||Process.pointerSize!==4)throw Error('platform');
      const kernel=Process.getModuleByName('kernel32.dll'),options={abi:'stdcall',scheduling:'exclusive',traps:'none'};
      const flush=new NativeFunction(kernel.getExportByName('FlushInstructionCache'),'bool',['pointer','pointer','uint'],options);
      const current=new NativeFunction(kernel.getExportByName('GetCurrentProcess'),'pointer',[],options)();
      const env={read32:a=>ptr(a).readU32(),read:(a,n)=>Array.from(new Uint8Array(ptr(a).readByteArray(n))),
        executable:(a,n)=>{const r=Process.findRangeByAddress(ptr(a));return !!r&&r.protection.includes('x')&&a+n<=r.base.toUInt32()+r.size;},
        hash:(a,n)=>Checksum.compute('sha256',ptr(a).readByteArray(n)),
        allocate:bytes=>{const code=Memory.alloc(Process.pageSize);allocations.push(code);code.writeByteArray(bytes);if(!Memory.protect(code,Process.pageSize,'r-x'))throw Error('protect');return code.toUInt32();},
        patch:(a,bytes)=>{const p=ptr(a),before=Memory.queryProtection(p);try{Memory.patchCode(p,bytes.length,w=>w.writeByteArray(bytes));}finally{if(Memory.queryProtection(p)!==before&&(!Memory.protect(p,bytes.length,before)||Memory.queryProtection(p)!==before))throw Error('protect');}},
        flush:(a,n)=>flush(current,ptr(a),n),report};
      const installer=createInstaller(env,true);root.zulaEmulatorRoom=installer;
      function discover(){if(discovery||installer.status().finished)return;const m=Process.enumerateModules().find(x=>x.name.toLowerCase()==='jansson.dll');if(!m)return;const p=m.findExportByName('json_loads');if(p)discovery=Interceptor.attach(p,{onEnter(){installer.attempt(this.context.ebx.toUInt32(),this.returnAddress.toUInt32());}});}
      discover();timer=setInterval(()=>{try{discover();}catch(_){installer.timeout();}},100);expiry=setTimeout(()=>installer.timeout(),90000);return installer;
    }catch(_){report('INSTALL_FAILED');return null;}
  }
  root.startZulaEmulatorRoom=start;
  if(typeof module==='object'&&module.exports)module.exports={SOURCE,SITE,GLOBALS,thunk,createInstaller,start};
})(globalThis);
"""

EMULATOR_BLOOD_JS = r"""
                                                                               
                                                                                    
(function(root) {
  'use strict';
  const SOURCE = [
    {name:'CURL_Load_ServerList',offset:2448,relative:27860557,length:3797,sha256:'e0480d40920dcc63780b0914fe0664aa4d02aa8a537f25af505c093a1c558ce9'},
    {name:'cl_user_spawn',offset:16752,relative:34858477,length:25512,sha256:'e348122fba44089cd7cdc9bb233cdb5b053614541f4ffbf199d3382a07040ddf'},
    {name:'EP_kanframe_close',offset:3328,relative:28179311,length:330,sha256:'9ed7fc61a69a6d84dcdb52bf88cbde8cb9bb27bc72521fc8953ceb543ec48206'},
    {name:'EP_kanframe_anim',offset:3324,relative:28179641,length:1468,sha256:'f48334ed2dc377d0959715fd2371bc9870965633089657ee8e0d454260fb0787'},
    {name:'EP_kanframe_death',offset:3332,relative:28181109,length:2495,sha256:'f44a64e615ba000ffbd1c0f9532f8054fcadeb7e05d34a48e5d8fc337393a49f'},
    {name:'RP_Kapat',offset:13648,relative:28559844,length:319,sha256:'3cc1c223ee6c62d6e983eb463037d286a7241941d5b3a683392a99364bbbea0b'}
  ];
  const SITE = {offset:18573,original:[0xe8,0x65,0x9b,0x9f,0xff]};
                                                                         
                                                                               
                                                                              
  const THUNK = [0x9c,0x60,0xff,0x93,0x00,0x0d,0,0,0x61,0x9d,0xff,0xa3,0x50,0x35,0,0];
  const equal=(a,b)=>a.length===b.length&&a.every((v,i)=>v===b[i]);
  const word=n=>[n&255,(n>>>8)&255,(n>>>16)&255,(n>>>24)&255];
  function createInstaller(env,enabled) {
    let finished=false,active=false,installing=false;
    const quiet=a=>[0x17f1acc,0x17f19e4,0x14e40].every(o=>env.read32(a+o)===0);
    const publish=code=>{finished=true;active=code==='INSTALLED';try{env.report(code);}catch(_){}return active;};
    function attempt(anchor,returnAddress) {
      if(!enabled||finished||installing)return false;
      try {if(returnAddress!==env.read32(anchor+2448)+659)return false;}catch(_){return false;}
      installing=true;let address=null,replacement=null,written=false;
      try {
        if(!quiet(anchor))throw Error('SOURCE_REJECTED');
        for(const row of SOURCE) {
          const target=env.read32(anchor+row.offset);
          if(target!==anchor+row.relative||!env.executable(target,row.length)||env.hash(target,row.length)!==row.sha256)
            throw Error('SOURCE_REJECTED');
        }
        address=env.read32(anchor+16752)+SITE.offset;
        if(!equal(env.read(address,5),SITE.original))throw Error('SOURCE_REJECTED');
        const target=env.allocate(THUNK);
        if(!Number.isInteger(target)||target<1||target>0xffffffff-THUNK.length||!env.executable(target,THUNK.length)||
          !equal(env.read(target,THUNK.length),THUNK)||!env.flush(target,THUNK.length))throw Error('INSTALL_FAILED');
        replacement=[0xe8,...word((target-address-5)>>>0)];
        if(!quiet(anchor)||!equal(env.read(address,5),SITE.original))throw Error('SOURCE_REJECTED');
        written=true;env.patch(address,replacement);
        if(!equal(env.read(address,5),replacement)||!env.flush(address,5)||!quiet(anchor))throw Error('INSTALL_FAILED');
        return publish('INSTALLED');
      }catch(error) {
        let restored=true;
        if(written)try {
          const actual=env.read(address,5);
          if(!quiet(anchor)||(!equal(actual,SITE.original)&&!equal(actual,replacement)))throw Error('ownership');
          env.patch(address,SITE.original);
          if(!equal(env.read(address,5),SITE.original)||!env.flush(address,5))throw Error('restore');
        }catch(_){restored=false;}
        return publish(!restored?'ROLLBACK_FAILED':error.message==='SOURCE_REJECTED'?'SOURCE_REJECTED':'INSTALL_FAILED');
      }finally{installing=false;}
    }
    return {attempt,status:()=>({finished,active}),timeout:()=>{if(!finished)publish('DISCOVERY_TIMEOUT');}};
  }
  function start(config) {
    if(!config||config.emulator!==true||config.pinned!==true)return null;
    if(root.zulaEmulatorBlood)return root.zulaEmulatorBlood;
    let discovery=null,timer=null,expiry=null;const allocations=[];
    function detach() {
      if(timer!==null){clearInterval(timer);timer=null;}
      if(expiry!==null){clearTimeout(expiry);expiry=null;}
      if(discovery){discovery.detach();discovery=null;}
    }
    const report=code=>{try{send({tag:'EMULATOR-BLOOD',msg:code});}finally{setImmediate(detach);}};
    try {
      if(Process.platform!=='windows'||Process.arch!=='ia32'||Process.pointerSize!==4)throw Error('platform');
      const kernel=Process.getModuleByName('kernel32.dll'),options={abi:'stdcall',scheduling:'exclusive',traps:'none'};
      const flush=new NativeFunction(kernel.getExportByName('FlushInstructionCache'),'bool',['pointer','pointer','uint'],options);
      const current=new NativeFunction(kernel.getExportByName('GetCurrentProcess'),'pointer',[],options)();
      const env={read32:a=>ptr(a).readU32(),read:(a,n)=>Array.from(new Uint8Array(ptr(a).readByteArray(n))),
        executable:(a,n)=>{const r=Process.findRangeByAddress(ptr(a));return !!r&&r.protection.includes('x')&&a+n<=r.base.toUInt32()+r.size;},
        hash:(a,n)=>Checksum.compute('sha256',ptr(a).readByteArray(n)),
        allocate:bytes=>{const p=Memory.alloc(Process.pageSize);allocations.push(p);p.writeByteArray(bytes);if(!Memory.protect(p,Process.pageSize,'r-x'))throw Error('protect');return p.toUInt32();},
        patch:(a,bytes)=>{const p=ptr(a),before=Memory.queryProtection(p);try{Memory.patchCode(p,bytes.length,w=>w.writeByteArray(bytes));}finally{if(Memory.queryProtection(p)!==before&&(!Memory.protect(p,bytes.length,before)||Memory.queryProtection(p)!==before))throw Error('protect');}},
        flush:(a,n)=>flush(current,ptr(a),n),report};
      const installer=createInstaller(env,true);root.zulaEmulatorBlood=installer;
      function discover(){if(discovery||installer.status().finished)return;const m=Process.enumerateModules().find(x=>x.name.toLowerCase()==='jansson.dll');if(!m)return;const p=m.findExportByName('json_loads');if(p)discovery=Interceptor.attach(p,{onEnter(){installer.attempt(this.context.ebx.toUInt32(),this.returnAddress.toUInt32());}});}
      discover();timer=setInterval(()=>{try{discover();}catch(_){installer.timeout();}},100);expiry=setTimeout(()=>installer.timeout(),90000);return installer;
    }catch(_){report('INSTALL_FAILED');return null;}
  }
  root.startZulaEmulatorBlood=start;
  if(typeof module==='object'&&module.exports)module.exports={SOURCE,SITE,THUNK,createInstaller,start};
})(globalThis);
"""

def on_message(message, data):
    if message.get("type") == "send":
        p = message["payload"]
        print("  [%s] %s" % (p.get("tag"), p.get("msg")), flush=True)
    elif message.get("type") == "error":
        print("  [frida-err] %s" % message.get("stack", message), flush=True)

def launch_options():
    parser = argparse.ArgumentParser(description="Zula spawn + TLS hooks; optional late schema capture.")
    parser.add_argument("--parse", action="store_true", help="Legacy early parser hooks (can disturb filecheck).")
    parser.add_argument("--schema", action="store_true", help="Load a bounded schema probe after GetServerList, in the same session.")
    parser.add_argument("--diagnostics", action="store_true", help="Record process memory, exit status and bounded exception/exit observations to logs/client_health.jsonl.")
    parser.add_argument("--identity", type=Path, help="Use a separate local player identity JSON created by tools/create_player.js.")
    parser.add_argument("--server", type=remote_server_address, help="Explicit remote IPv4 API target; requires prepared hosts and ready remote backend.")
    parser.add_argument("--emulator", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--schema-output", type=Path,
                        default=Path(__file__).resolve().parents[1] / "logs" / "schema_probe.jsonl",
                        help="Append schema JSONL here (only with --schema).")
    return parser.parse_args()


def remote_server_address(value):
    try:
        address = ipaddress.IPv4Address(value)
        if int(str(address).split('.')[0]) == 0 or int(str(address).split('.')[0]) >= 224:
            raise ValueError()
        return str(address)
    except ValueError:
        raise argparse.ArgumentTypeError("Server must be a dotted IPv4 unicast address") from None


class LateSchemaCapture:
                                                                                    

    def __init__(self, session, output_path):
                                                                                
                                                                               
        from frida_schema_probe import JS_TEMPLATE
        self.session = session
        self.template = JS_TEMPLATE
        self.output_path = output_path
        self.script = None
        self.output = None
        self.lock = threading.Lock()
        self.run_id = uuid.uuid4().hex[:12]
        self.started_at = None
        self.stopped = False

    def write_events(self, events):
        lines = "".join(json.dumps({"run_id": self.run_id, **event}, ensure_ascii=False) + "\n" for event in events)
        with self.lock:
            if self.output is not None and not self.output.closed:
                self.output.write(lines)
                self.output.flush()

    def on_message(self, message, data):
        if message.get("type") == "send":
            events = message.get("payload", {}).get("events", [])
            self.write_events(events)
            for event in events:
                if event.get("op") == "probe_ready":
                    print("  [SCHEMA] hazir; ilk sunucu/envanter/market akisi kaydediliyor.", flush=True)
                elif event.get("op") == "hook_missing":
                    print("  [SCHEMA] hook bulunamadi: %s" % event.get("name"), flush=True)
        elif message.get("type") == "error":
            self.write_events([{"op": "frida_error", "message": message}])
            print("  [SCHEMA-ERR] %s" % message.get("stack", message), flush=True)

    def start(self, pid):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        self.output = self.output_path.open("a", encoding="utf-8")
        self.write_events([{"op": "run_start", "pid": pid, "duration": 600,
                            "mode": "same_session_after_getserverlist", "time_ms": int(time.time() * 1000)}])
        config = {"maxEvents": 25000, "arrayLimit": 3, "maxNodes": 20000,
                  "previewBytes": 2048, "textLimit": 180,
                  "rootLifetimeMs": 600000, "renderCounters": True}
        self.script = self.session.create_script(self.template.replace("__CONFIG__", json.dumps(config)))
        self.script.on("message", self.on_message)
        self.script.load()
        self.started_at = time.monotonic()
        print("  [SCHEMA] JSONL: %s (en fazla 600sn)" % self.output_path, flush=True)

    def stop(self, connected=True):
        if self.stopped:
            return
        self.stopped = True
        if self.script is not None and connected:
            try:
                summary = self.script.exports_sync.stop()
                self.write_events([{"op": "capture_stopped", "summary": summary, "time_ms": int(time.time() * 1000)}])
            except Exception as exc:
                self.write_events([{"op": "stop_error", "error": str(exc)}])
            try:
                self.script.unload()
            except Exception:
                pass

    def close(self):
        with self.lock:
            if self.output is not None and not self.output.closed:
                self.output.close()


def main(*, on_patch_report=None, on_authenticated=None):
    options = launch_options()
    if not options.identity:
        print("[FATAL] Oyuncu kimligi gerekli: --identity DOSYA", flush=True)
        raise SystemExit(1)
    launch_args = list(ARGS)
    if options.identity:
        identity = json.loads(options.identity.read_text(encoding="utf-8-sig"))
        ticket = identity.get("Token")
        if not isinstance(ticket, str) or not 32 <= len(ticket) <= 128 or not all(33 <= ord(char) <= 126 for char in ticket):
            raise ValueError("Identity file contains an invalid player ticket")
        for flag in ("-ip", "-pl"):
            launch_args[launch_args.index(flag) + 1] = ticket
    if not os.path.exists(GAME_EXE):
        print("[FATAL] zula.exe yok: %s" % GAME_EXE, flush=True); sys.exit(1)
                                                                                
                                                                              
    tools_directory = Path(__file__).resolve().parent
    remote_tls = None
    if options.server:
                                                                              
                                                                            
        from remote_client_route import verify_remote_client_route
        verify_remote_client_route(options.server)
        from native_tls_pin import prepare_remote_tls
        remote_tls = prepare_remote_tls(tools_directory.parent, GAME_DIR)
    emulator_patch = None
    emulator_launch = None
    capability_lease = None
    last_capability_state = None
    if options.emulator:
        from emulator_launch import prepare_emulator_launch
        from client_capability_lease import ClientCapabilityTransportError
        try:
            emulator_launch = prepare_emulator_launch(launch_args[launch_args.index('-ip') + 1],
                server=options.server, root=tools_directory.parent)
            launch_args = emulator_launch.game_arguments(launch_args)
                                                                               
                                                                               
                                                                              
                                                                                
            launch_args.extend(['-d', 'defWWLC=3031'])
        except ClientCapabilityTransportError as error:
            print("[FATAL] Emulator launch identity unavailable: " + error.code, flush=True)
            raise SystemExit(1) from None
        from emulator_pose_patch import EmulatorPosePatch
        def patch_report(report):
            print("  [CLIENT-PATCH] " + json.dumps(report, ensure_ascii=True), flush=True)
            if on_patch_report is not None:
                on_patch_report(report)
        emulator_patch = EmulatorPosePatch(enabled=True, server=options.server,
            root=tools_directory.parent, launch_id=emulator_launch.launch_id, transport=emulator_launch.transport,
            on_report=patch_report, on_authenticated=on_authenticated)
        if emulator_patch.prepare():
            from client_capability_lease import ClientCapabilityLease
            capability_lease = ClientCapabilityLease(emulator_patch.transport,
                launch_args[launch_args.index('-ip') + 1], emulator_patch.manifest['feature'],
                emulator_patch.manifest['proofHash'], emulator_patch.launch_id)
            def authenticated_patch(report):
                                                                                 
                                                                                
                capability_lease.activate(report)
                if on_authenticated is not None:
                    on_authenticated(report)
            emulator_patch.on_authenticated = authenticated_patch
            emulator_patch.notify_authenticated()
        emulator_patch.poll()
    remote_source = ""
    if options.server:
        remote_source = (tools_directory / "frida_remote_url.js").read_text(encoding="utf-8")
        remote_source += "\nglobalThis.zulaRemoteURL = makeZulaRemoteURL(%s);\n" % json.dumps(options.server)
        remote_source += (tools_directory / "frida_remote_tls.js").read_text(encoding="utf-8")
        remote_source += "\nglobalThis.zulaRemoteTLS = installZulaRemoteTLS({pin:%s,curlPath:%s,rewrite:globalThis.zulaRemoteURL,report:function(value){send(value);}});\n" % (json.dumps(remote_tls['pin']), json.dumps(remote_tls['curlPath']))
        remote_source += "rpc.exports.remotetlsstatus = function(){return globalThis.zulaRemoteTLS.status();};\n"
    market_fixes = "\n".join((tools_directory / name).read_text(encoding="utf-8")
                             for name in ("frida_market_sort.js", "frida_market_scroll.js", "frida_card_refresh.js"))
    market_fixes += r"""
rpc.exports.stopmarketfixes = async function () {
  if (globalThis.zulaCardRefreshPatch) await globalThis.zulaCardRefreshPatch.stop();
  if (globalThis.zulaMarketScrollPatch) await globalThis.zulaMarketScrollPatch.stop();
  if (globalThis.zulaMarketSortPatch) {
    for (let attempt = 0; attempt < 200; attempt++) {
      try { globalThis.zulaMarketSortPatch.stop(); return; }
      catch (error) {
        if (attempt === 199) throw error;
        await new Promise(resolve => setTimeout(resolve, 25));
      }
    }
  }
};
rpc.exports.marketfixstatus = function () {
  return {
    sort: globalThis.zulaMarketSortPatch ? globalThis.zulaMarketSortPatch.status() : null,
    scroll: globalThis.zulaMarketScrollPatch ? globalThis.zulaMarketScrollPatch.status() : null,
    cards: globalThis.zulaCardRefreshPatch ? globalThis.zulaCardRefreshPatch.status() : null
  };
};
"""
    market_log = tools_directory.parent / "logs" / "market_patch.jsonl"
    market_log.parent.mkdir(parents=True, exist_ok=True)
    print("=== ZULA EU spawn (Steam YOK, TLS-skip + market fix%s) ===" % (" + PARSE" if WANT_PARSE else ""), flush=True)
    dev = frida.get_local_device()
    pid = dev.spawn([GAME_EXE] + launch_args, cwd=GAME_DIR)
                                                                             
                                                                              
                                                                              
                                                                           
    exit_metrics = None
    native_exit_code = None
    try:
        from client_health import WinProcessMetrics
        exit_metrics = WinProcessMetrics(pid)
    except Exception:
        print("  [CLIENT-EXIT] OBSERVER_UNAVAILABLE", flush=True)
    launcher_stop = None
    if emulator_launch is not None:
        from emulator_launch import LauncherStop
        launcher_stop = LauncherStop()
    print("  [SYS] zula PID=%d spawn edildi" % pid, flush=True)
    closed = threading.Event()
    emulator_network_failed = threading.Event()
    detached = {"reason": "launcher-ended", "crash": None}
    sess = None
    scr = None
    health = None
    anet_log = None
    from anet_connection_diagnostics import AnetConnectionLog, diagnostics_enabled
    if options.diagnostics or diagnostics_enabled(options.emulator):
        anet_log = AnetConnectionLog(tools_directory.parent / "logs" / "anet_connection.jsonl", pid)
    schema = None
    schema_attempted = False
    server_list_seen = threading.Event()

    def on_detached(reason, crash=None):
        detached.update(reason=reason, crash=crash)
        print("  [SYS] oyun oturumu ayrildi: %s" % reason, flush=True)
        if crash is not None:
            from client_health import safe_crash_metadata
            print("  [CRASH] %s" % json.dumps(safe_crash_metadata(crash)), flush=True)
        closed.set()

    def on_launch_message(message, data):
                                                                           
                                                                                     
        payload = message.get("payload", {}) if message.get("type") == "send" else {}
        if emulator_launch is not None and isinstance(payload, dict) and payload.get("tag") in ("EMULATOR-NET", "EMULATOR-ROOM", "EMULATOR-BLOOD"):
            code = payload.get("msg")
            if code in ("INSTALLED", "SOURCE_REJECTED", "INSTALL_FAILED", "ROLLBACK_FAILED", "DISCOVERY_TIMEOUT"):
                print("  [" + payload["tag"] + "] " + code, flush=True)
                if code != "INSTALLED":
                    emulator_network_failed.set()
            return
        if isinstance(payload, dict) and payload.get("tag") == "HEALTH":
            event = payload.get("event", {})
            if isinstance(event, dict) and event.get("op") == "anet_diagnostic":
                if anet_log is not None:
                    anet_log.record(event)
                return
        if emulator_patch is not None and emulator_patch.accept_message(message):
            return
        if payload.get("kind") in {"market_sort", "market_scroll", "card_refresh"}:
            record = {"time_ms": int(time.time() * 1000), "pid": pid, **payload}
            with market_log.open("a", encoding="utf-8") as output:
                output.write(json.dumps(record, ensure_ascii=False) + "\n")
            print("  [MARKET] " + json.dumps(payload, ensure_ascii=False), flush=True)
            return
        if health is not None and payload.get("tag") == "HEALTH":
            event = payload.get("event", {})
            health.record(event)
            if event.get("op") == "native_exception":
                print("  [HEALTH] %s at %s: %s" % (event.get("exception_type"),
                      event.get("fault", {}).get("address"), event.get("instruction", "")), flush=True)
            elif event.get("op") != "exception_budget_exhausted":
                print("  [HEALTH] %s" % json.dumps(event, ensure_ascii=False), flush=True)
            return
        if health is not None and message.get("type") == "error":
            health.record({"op": "diagnostic_script_error", "error": str(message.get("stack", ""))[:1200]})
        if schema is not None and payload.get("tag") == "CURL":
            url = str(payload.get("msg", "")).split("?", 1)[0].rstrip("/").lower()
            if url.endswith("/getserverlist"):
                server_list_seen.set()
        on_message(message, data)

    try:
        script_source = remote_source + "\n" + JS + "\n" + market_fixes
        if emulator_launch is not None:
            script_source += "\n" + EMULATOR_NETWORK_JS + "\nstartZulaEmulatorNetwork({emulator:true,pinned:true});\n"
            script_source += "\n" + EMULATOR_ROOM_JS + "\nstartZulaEmulatorRoom({emulator:true,pinned:true});\n"
            script_source += "\n" + EMULATOR_BLOOD_JS + "\nstartZulaEmulatorBlood({emulator:true,pinned:true});\n"
        if emulator_patch is not None:
            script_source += "\n" + emulator_patch.script_source()
        if anet_log is not None:
            script_source += "\n" + (tools_directory / "frida_anet_diagnostics.js").read_text(encoding="utf-8")
            print("  [ANET] bounded diagnostics -> logs/anet_connection.jsonl", flush=True)
        if options.diagnostics:
            try:
                from client_health import ClientHealth, DIAGNOSTICS_JS
                                                                                
                                                                                
                health = ClientHealth(pid)
                health.poll()
                script_source += DIAGNOSTICS_JS
                script_source += "\n" + (tools_directory / "frida_startup_request_audit.js").read_text(encoding="utf-8")
                print("  [HEALTH] diagnostics -> logs/client_health.jsonl", flush=True)
            except Exception as exc:
                print("  [HEALTH] diagnostics unavailable: %s" % exc, flush=True)
        sess = dev.attach(pid)
        sess.on("detached", on_detached)
        if options.schema:
            schema = LateSchemaCapture(sess, options.schema_output)
        scr = sess.create_script(script_source)
        scr.on("message", on_launch_message)
        scr.load()
        if emulator_network_failed.is_set():
            raise RuntimeError('EMULATOR_NETWORK_SETUP_FAILED')
        if options.server:
            status = scr.exports_sync.remotetlsstatus()
                                                                             
                                                                               
            if not isinstance(status, dict) or status.get('armed') is not True or status.get('failed') is not False:
                raise RuntimeError('Remote TLS enforcement was not armed')
        dev.resume(pid)
        print("  [SYS] resume -> lobiye giriliyor. Lobi gelince sunucu-sec + Ekran-2. Kapat: Ctrl+C / oyunu kapat", flush=True)
                                                                             
                                                                 
        if schema is None and health is None and emulator_patch is None:
            closed.wait()
        else:
            next_health_poll = time.monotonic() + 1
            last_scroll_status = None
            status_poll_failed = False
            while not closed.is_set():
                if emulator_network_failed.is_set():
                    raise RuntimeError('EMULATOR_NETWORK_SETUP_FAILED')
                if launcher_stop is not None and launcher_stop.requested():
                    raise KeyboardInterrupt()
                if emulator_patch is not None:
                    emulator_patch.poll()
                if capability_lease is not None:
                    capability_status = capability_lease.poll()
                    capability_state = (capability_status['state'], capability_status['reason'])
                    if capability_state != last_capability_state:
                        last_capability_state = capability_state
                        print("  [CLIENT-CAPABILITY] %s%s" % (capability_state[0],
                            (": " + capability_state[1]) if capability_state[1] else ""), flush=True)
                if schema is not None and not schema_attempted and server_list_seen.is_set():
                    schema_attempted = True
                    try:
                        schema.start(pid)
                    except Exception as exc:
                        schema.write_events([{"op": "capture_start_error", "error": str(exc)}])
                        print("  [SCHEMA-ERR] baslatilamadi: %s" % exc, flush=True)
                        schema.stop(connected=not closed.is_set())
                if schema is not None and schema.started_at is not None and not schema.stopped and time.monotonic() - schema.started_at >= 600:
                    schema.stop(connected=not closed.is_set())
                    print("  [SCHEMA] 600sn tamamlandi; oyun/TLS oturumu devam ediyor.", flush=True)
                now = time.monotonic()
                if health is not None and now >= next_health_poll:
                    next_health_poll = now + 1
                    if health.poll().get("exited"):
                                                                             
                                                                            
                        closed.wait(0.1)
                        if not closed.is_set():
                            detached["reason"] = "process-exited"
                        break
                    try:
                        scroll_status = None if status_poll_failed else scr.exports_sync.marketfixstatus().get("scroll")
                        if scroll_status and scroll_status != last_scroll_status:
                            last_scroll_status = scroll_status
                            record = {"time_ms": int(time.time() * 1000), "pid": pid,
                                      "kind": "market_scroll", "action": "status", **scroll_status}
                            with market_log.open("a", encoding="utf-8") as output:
                                output.write(json.dumps(record) + "\n")
                    except Exception as exc:
                                                                               
                        status_poll_failed = True
                        health.record({"op": "market_status_unavailable", "error": str(exc)[:300]})
                delay = max(0.01, next_health_poll - time.monotonic()) if health is not None else None
                if schema is not None and not schema.stopped:
                    delay = min(delay, 0.02) if delay is not None else 0.02
                if emulator_patch is not None:
                    delay = min(delay, 0.25) if delay is not None else 0.25
                closed.wait(delay)
    except KeyboardInterrupt:
        detached["reason"] = "launcher-interrupted"
    finally:
                                                                               
                                                                               
                                                                          
        owned_native_ended = detached["reason"] == "process-terminated"
        if exit_metrics is not None:
            try:
                if detached["reason"] == "process-terminated":
                    exit_metrics.wait_for_exit(2000)
                native_state = exit_metrics.read()
                owned_native_ended = native_state.get('exited') is True
                if native_state.get('exited') and detached["reason"] != "launcher-interrupted":
                    native_exit_code = native_state.get('exit_code')
                    if isinstance(native_exit_code, int) and not isinstance(native_exit_code, bool) and 0 <= native_exit_code <= 0xffffffff:
                        print("  [CLIENT-EXIT] code=0x%08x" % native_exit_code, flush=True)
                    else:
                        native_exit_code = None
            except Exception:
                print("  [CLIENT-EXIT] STATUS_UNAVAILABLE", flush=True)
        if options.server or emulator_launch is not None:
                                                                              
                                                                             
            try:
                dev.kill(pid)
            except frida.ProcessNotFoundError:
                owned_native_ended = True
            except frida.InvalidOperationError:
                pass
            except Exception:
                print("  [CLIENT-EXIT] STOP_FAILED", flush=True)
            if exit_metrics is not None and not owned_native_ended:
                try:
                    owned_native_ended = exit_metrics.wait_for_exit(2000) is True and exit_metrics.read().get('exited') is True
                except Exception:
                    pass
        if exit_metrics is not None:
            try:
                exit_metrics.close()
            except Exception:
                print("  [CLIENT-EXIT] OBSERVER_CLOSE_FAILED", flush=True)
        if launcher_stop is not None:
            launcher_stop.close()
        if emulator_patch is not None:
                                                                            
                                                                             
            emulator_patch.close()
        if capability_lease is not None:
            capability_lease.close()
        if emulator_launch is not None:
            ended = emulator_launch.end(native_ended=owned_native_ended)
            print("  [CLIENT-LAUNCH] " + ("ENDED" if ended else "END_UNCONFIRMED"), flush=True)
        if schema is not None:
            schema.stop(connected=not closed.is_set())
        if health is not None:
            final = health.finish(detached["reason"], detached["crash"],
                                  wait_for_exit=detached["reason"] == "process-terminated")
            print("  [HEALTH] " + json.dumps(final, ensure_ascii=False), flush=True)
        if sess is not None:
            if scr is not None and not closed.is_set():
                try:
                                                                             
                    scr.exports_sync.stopmarketfixes()
                except Exception as exc:
                    print("  [MARKET] cleanup: %s" % exc, flush=True)
            try:
                sess.detach()
            except frida.InvalidOperationError:
                pass
        if schema is not None:
            schema.close()
        if health is not None:
            health.close()

    if native_exit_code not in (None, 0):
        raise SystemExit(native_exit_code)

if __name__ == "__main__":
    main()
