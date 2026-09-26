'use strict';

                                                                                     
                                                                               
(function (global) {
                                                                           
                                                                             
  const JIT_SOURCE = Object.freeze([
    {name:'anet_cl_start',offset:16148,relative:35128010,length:23979,sha256:'b1498a3f7f8089b146e91bd4a1e7a3d412d7452b6634ba3def6c3a22756bfff4',emulatorSha256:'58a218fe2a7cbbe42d39b95c2bd18719639ff795a05d59b9ff8a3f58b4b69443'},
    {name:'cl_game_loop',offset:16488,relative:35127745,length:265,sha256:'26d98191376974d0ed587a5780f1111e6bbc5e49fd1ce2d5b28122a445413b78'},
    {name:'anet_main_reset',offset:16152,relative:26636749,length:286,sha256:'6d3b8dd391f2944be5996e628d8b6462d040725c6e72070ac9625cfd584904d8'},
    {name:'anet_main_run',offset:16156,relative:26637035,length:1795,sha256:'7c1615312b4e3d2d1b699e4ad18ab9425b801589e1cadbdfab76de64d9b421c3'},
    {name:'BE_RequestRestartClient',offset:380,relative:26638953,length:570,sha256:'ede0f0dd1f294b2e6c9ddc9509f0784630afd2b1a39ffd86ee1ffe59d375cc73'},
    {name:'anet_cl_exit',offset:16144,relative:35127483,length:262,sha256:'6e2cfbb199bca5be7fe922e107b14c634c74f8a13f26bd7607299b95a9a75b81'}
  ]);
  const JIT_CALLS = Object.freeze({
    BE_InitClient:{source:'anet_cl_start',returnOffset:19864,slot:0x14e28},
    BE_RunClient:{source:'anet_main_run',returnOffset:1732,slot:0x14e34},
    enet_init:{source:'anet_cl_start',returnOffset:20247,slot:0x18639e8},
    enet_init_client:{source:'anet_cl_start',returnOffset:23888,slot:0x18639ec}
  });
  function createJitObserver(runtime,emit) {
    let anchor=null,rejected=false;
    const hooks=[],targets=new Map(),importCounts=new Map();
    function snapshot() {
      if(!anchor)return {jit_verified:false};
      try {
        return {jit_verified:true,game_level_state:anchor.add(0x17f1acc).readS32(),
          game_anet_active:anchor.add(0x17f19e4).readS32(),be_active:anchor.add(0x14e40).readS32()};
      }catch(_){return {jit_verified:false};}
    }
    function mark(name,stage,extra={}) {emit({phase:'jit_state',name,stage,...snapshot(),...extra});}
    function discover(context,returnAddress,name,exportAddress) {
      try {
        if(runtime.Process.arch!=='ia32'||runtime.Process.pointerSize!==4)return false;
        const candidate=context.ebx,spec=JIT_CALLS[name];
        if(!candidate||!spec)return false;
        if(anchor&&candidate.compare(anchor)!==0)return false;
        const source=JIT_SOURCE.find(row=>row.name===spec.source),target=candidate.add(source.offset).readPointer();
        if(returnAddress.compare(target.add(spec.returnOffset))!==0||
          candidate.add(spec.slot).readPointer().compare(exportAddress)!==0)return false;
        const call=returnAddress.add(-8);
        if(call.readU8()!==0x8b||call.add(1).readU8()!==0x83||call.add(2).readU32()!==spec.slot||
          call.add(6).readU8()!==0xff||call.add(7).readU8()!==0xd0)return false;
        if(anchor)return true;
        for(const row of JIT_SOURCE) {
          const pointer=candidate.add(row.offset).readPointer(),region=runtime.Process.findRangeByAddress(pointer);
          if(pointer.compare(candidate.add(row.relative))!==0||!region||!region.protection.includes('x')||
            pointer.add(row.length).compare(region.base.add(region.size))>0)return false;
          const hash=runtime.Checksum.compute('sha256',pointer.readByteArray(row.length));
                                                                             
                                                                           
          if(hash!==row.sha256&&hash!==row.emulatorSha256)return false;
          targets.set(row.name,pointer);
        }
        anchor=candidate;
        for(const row of JIT_SOURCE.filter(value=>['BE_RequestRestartClient','anet_cl_exit'].includes(value.name))) {
          try {hooks.push(runtime.Interceptor.attach(targets.get(row.name),{
            onEnter(args) {
                                                                            
                                                                               
              mark(row.name,'before',
                row.name==='BE_RequestRestartClient'?{restart_reason:args[0].toInt32()}:{});
            }
          }));}catch(_){emit({phase:'hook_failed',name:row.name});}
        }
        emit({phase:'jit_verified',...snapshot()});return true;
      }catch(_){return false;}
    }
    function imported(context,returnAddress,name,exportAddress,stage) {
      if(stage==='before'&&!discover(context,returnAddress,name,exportAddress)) {
        if(!rejected){rejected=true;emit({phase:'jit_rejected',name});}
        return false;
      }
      if(stage==='before')importCounts.set(name,(importCounts.get(name)||0)+1);
      if(name==='BE_RunClient'&&importCounts.get(name)>1)return false;
      mark(name,stage);return true;
    }
    return {imported,snapshot,hooks};
  }
  function packetMetadata(buffers, count, pointerSize, actualLength) {
    if (!Number.isInteger(count) || count < 1 || count > 32 || ![4,8].includes(pointerSize)) return {header_valid:false};
    const rows=[];let total=0;
    for(let index=0;index<count;index++) {
      const row=buffers.add(index*(pointerSize===4?8:16));
      const length=row.readU32(),data=row.add(pointerSize===4?4:8).readPointer();
      if(length>262144 || total+length>262144)return {header_valid:false};
      rows.push({length,data});total+=length;
    }
    if(actualLength!==undefined) {
      if(!Number.isInteger(actualLength)||actualLength<0||actualLength>total)return {header_valid:false};
      total=actualLength;
    }
    const out={bytes:total,header_valid:false};
    function byte(offset) {
      if(offset>=total)throw Error('short');
      for(const row of rows){if(offset<row.length)return row.data.add(offset).readU8();offset-=row.length;}
      throw Error('short');
    }
    if(total<2)return out;
    const header=(byte(0)<<8)|byte(1),timed=(header&0x8000)!==0,offset=timed?4:2;
    out.header_valid=true;out.peer_id=header&0xfff;out.session=(header>>>12)&3;
    out.sent_time=timed;out.compressed=(header&0x4000)!==0;
                                                                             
    if(!out.compressed&&total>=offset+4) {
      const command=byte(offset);out.command=command&15;
      out.reliable=(command&0x80)!==0;out.channel=byte(offset+1);
    }
    return out;
  }

  function installAnetDiagnostics({runtime=global,report=value=>send(value),budget=96}={}) {
    if(!Number.isInteger(budget)||budget<1||budget>128)throw Error('Invalid diagnostic budget');
    const {Process,Interceptor}=runtime,hooks=[],modules=new Map(),installed=new Set(),timers=[],winsockReports={};
    let records=0,attempts=0,callbacks=0,preinitCallbacks=0,sends=0,receives=0,observer=null;
    function emit(event) {
      if(records>=budget)return;
      records++;
      try{report({tag:'HEALTH',event:{op:'anet_diagnostic',...event}});}catch(_){}
    }
    const jit=createJitObserver(runtime,emit);
    function moduleFor(address) {
      for(const value of modules.values()) {
        try{if(address.compare(value.base)>=0&&address.compare(value.base.add(value.size))<0)return value;}catch(_){}
      }
      return null;
    }
    function attach(module,name,callbacks) {
      const key=module.base.toString()+':'+name;
      if(installed.has(key))return;
      try {
        const address=module.findExportByName(name);if(!address){emit({phase:'hook_missing',name});return;}
        hooks.push(Interceptor.attach(address,callbacks));installed.add(key);return address;
      } catch(_){emit({phase:'hook_failed',name});}
    }
    function summary(delay) {emit({phase:'counters',delay_ms:delay,init_attempts:attempts,callbacks,
      preinit_callbacks:preinitCallbacks,sends,receives,...jit.snapshot()});}
    function importedBefore(context,name,address) {
      return jit.imported(context.context||{},context.returnAddress,name,address,'before');
    }
    function anetAdded(module) {
      if(modules.has(module.base.toString()))return;
      modules.set(module.base.toString(),module);emit({phase:'module_added',module:'ANet.dll'});
      const init=module.findExportByName('enet_init'),client=module.findExportByName('enet_init_client');
      attach(module,'enet_init',{
        onEnter(){this.jitObserved=importedBefore(this,'enet_init',init);},
        onLeave(result){if(this.jitObserved)jit.imported({},null,'enet_init',init,'after');
          emit({phase:'enet_init',result:result.toInt32(),...jit.snapshot()});}
      });
      attach(module,'enet_init_client',{
        onEnter(args){
          this.jitObserved=importedBefore(this,'enet_init_client',client);
          this.portRaw=args[1].toInt32();this.attempt=++attempts;
          for(const delay of [250,1000,3000,10000]) {
            if(attempts<=3&&typeof runtime.setTimeout==='function')timers.push(runtime.setTimeout(()=>summary(delay),delay));
          }
        },
        onLeave(result){if(this.jitObserved)jit.imported({},null,'enet_init_client',client,'after');
          emit({phase:'enet_init_client',attempt:this.attempt,result:result.toInt32(),
          port_fixed:this.portRaw,port:this.portRaw%1024===0?this.portRaw/1024:null,...jit.snapshot()});}
      });
      attach(module,'anet_callback',{onEnter(){
        if(!attempts){preinitCallbacks++;if(preinitCallbacks===1)emit({phase:'preinit_callback',...jit.snapshot()});return;}
        callbacks++;
        if(callbacks===1)emit({phase:'first_callback',init_attempts:attempts});
      }});
    }
    function battleEyeAdded(module) {
      for(const name of ['BE_InitClient','BE_RunClient']) {
        const address=module.findExportByName(name);
        attach(module,name,{
          onEnter(){this.jitObserved=importedBefore(this,name,address);},
                                                                             
          onLeave(){if(this.jitObserved)jit.imported({},null,name,address,'after');}
        });
      }
    }
    function winsockAdded(module) {
      for(const name of ['socket','WSAStartup'])attach(module,name,{
        onEnter(){this.ours=!!moduleFor(this.returnAddress);},
        onLeave(result){if(this.ours&&(winsockReports[name]=(winsockReports[name]||0)+1)<=3)
          emit({phase:name,result:result.toInt32(),thread_last_error:this.lastError||0});}
      });
      attach(module,'WSASendTo',{
        onEnter(args){
          this.ours=!!moduleFor(this.returnAddress);if(!this.ours)return;
          sends++;this.number=sends;
          if(sends>24)return;
          try{this.metadata=packetMetadata(args[1],args[2].toUInt32(),Process.pointerSize);}
          catch(_){this.metadata={header_valid:false};}
        },
        onLeave(result){if(this.ours&&this.number<=24)emit({phase:'send',number:this.number,
          result:result.toInt32(),thread_last_error:result.toInt32()===-1?(this.lastError||0):0,...this.metadata});}
      });
      attach(module,'WSARecvFrom',{
        onEnter(args){
          this.ours=!!moduleFor(this.returnAddress);if(!this.ours)return;
          this.buffers=args[1];this.count=args[2].toUInt32();this.received=args[3];
        },
        onLeave(result){
          if(!this.ours||result.toInt32()!==0)return;
          receives++;if(receives>24)return;
          let metadata;
          try{metadata=packetMetadata(this.buffers,this.count,Process.pointerSize,this.received.readU32());}
          catch(_){metadata={header_valid:false};}
          emit({phase:'receive',number:receives,result:0,...metadata});
        }
      });
    }
    function added(module) {
      const name=module.name.toLowerCase();
      if(name==='anet.dll')anetAdded(module);
      else if(name==='ws2_32.dll')winsockAdded(module);
      else if(name==='battleeye_client.dll')battleEyeAdded(module);
    }
    observer=Process.attachModuleObserver({onAdded:added,onRemoved(module){
      if(module.name.toLowerCase()==='anet.dll') {
        modules.delete(module.base.toString());emit({phase:'module_removed',module:'ANet.dll'});
                                                                           
      }
                                                                             
                                                                              
      if(['anet.dll','battleeye_client.dll','ws2_32.dll'].includes(module.name.toLowerCase()))
        for(const key of [...installed])if(key.startsWith(module.base.toString()+':'))installed.delete(key);
    }});
    const handle={observer,hooks,timers,jit,summary:()=>summary(0)};
    global.zulaAnetDiagnostics=handle;return handle;
  }
  if(typeof module==='object'&&module.exports)module.exports={packetMetadata,installAnetDiagnostics,createJitObserver,JIT_SOURCE,JIT_CALLS};
  else installAnetDiagnostics();
})(globalThis);
