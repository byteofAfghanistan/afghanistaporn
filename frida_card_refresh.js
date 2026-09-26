                                                                                
                                                                                 
                                                                                
   
(function () {
  'use strict';
  if (globalThis.zulaCardRefreshPatch) return;
  const fingerprints = {
    handler: { position: 1724, length: 2051, hash: 0x0ea47e00 },
    profile: { position: 1528, length: 384, hash: 0xc8194ccf },
    cardUpdate: { position: 1628, length: 139, hash: 0xb8db57ad }
  };
  const callOffset = 0x56b, dirtyOffset = 0x1831568;
  let installed = false, installing = false, stopped = false;
  let discovery = null, timer = null, patch = null, stopPromise = null;
  const rejected = new Set();
  function event(action, fields) { send(Object.assign({ kind: 'card_refresh', action: action }, fields || {})); }
  function hashCode(pointer, length) {
    let hash = 2166136261;
    const bytes = new Uint8Array(pointer.readByteArray(length));
    for (let i = 0; i < bytes.length; ++i) hash = Math.imul(hash ^ bytes[i], 16777619) >>> 0;
    return hash;
  }
  function verify(pointer, anchor, fingerprint) {
    const range = Process.findRangeByAddress(pointer);
    if (!range || range.protection.indexOf('x') < 0) return false;
    const prefix = new Uint8Array(pointer.readByteArray(14));
    const expected = [0x55, 0x53, 0x56, 0x57, 0xe8, 0, 0, 0, 0, 0x58, 0x8b, 0xd8, 0x81, 0xeb];
    if (!expected.every((value, index) => prefix[index] === value)) return false;
    return pointer.add(9).sub(pointer.add(14).readU32()).equals(anchor) &&
      hashCode(pointer, fingerprint.length) === fingerprint.hash;
  }
  function writeCode(address, bytes) {
    Memory.patchCode(address, bytes.byteLength, function (writable) { writable.writeByteArray(bytes); });
  }
  function restore() {
    if (!patch) return;
    writeCode(patch.address, patch.original);
    patch = null;
  }
  function status() {
    const resources = globalThis.zulaCardRefreshPatch.nativeResources;
    return { installed: installed, dirty: resources ? resources.anchor.add(dirtyOffset).readS32() : null };
  }
  function install(anchor) {
    if (stopped || installed || installing || Process.pointerSize !== 4) return;
    installing = true;
    try {
      const functions = {};
      for (const name of ['handler', 'profile', 'cardUpdate']) {
        const spec = fingerprints[name];
        functions[name] = anchor.add(spec.position).readPointer();
        if (!verify(functions[name], anchor, spec)) return;
      }
                                                                            
      if (anchor.add(0x18bc8bc).readS32() !== 0 || anchor.add(0x18bc8c0).readS32() !== 1) return;
      const address = functions.handler.add(callOffset);
      if (address.readU8() !== 0xe8 || !address.add(5).add(address.add(1).readS32()).equals(functions.profile)) return;
      const original = address.readByteArray(5);
                                                                                
                                                                
      const bridge = Memory.alloc(Process.pageSize);
      const bridgeBytes = new Uint8Array(15);
                                                                                
                                                                            
                                                                         
      bridgeBytes.set([0xc7, 0x83, 0x68, 0x15, 0x83, 0x01, 1, 0, 0, 0, 0xe9]);
      new DataView(bridgeBytes.buffer).setInt32(11, functions.profile.sub(bridge.add(15)).toInt32(), true);
      bridge.writeByteArray(bridgeBytes);
      if (!Memory.protect(bridge, Process.pageSize, 'r-x')) throw new Error('Cannot mark native card-refresh bridge executable');
                                                                         
      globalThis.zulaCardRefreshPatch.nativeResources = { bridge: bridge, anchor: anchor,
        address: address, original: original, profile: functions.profile, cardUpdate: functions.cardUpdate };
      const call = new Uint8Array(5); call[0] = 0xe8;
      new DataView(call.buffer).setInt32(1, bridge.sub(address.add(5)).toInt32(), true);
      patch = { address: address, original: original };
      writeCode(address, call);
      installed = true;
      if (timer) { clearInterval(timer); timer = null; }
      setImmediate(function () { if (discovery) { discovery.detach(); discovery = null; } });
      event('installed', { globals: anchor.toString(), successCall: address.toString(),
        dirtyFlag: anchor.add(dirtyOffset).toString(), refreshOn: 'native_customize_open' });
    } catch (error) {
      try { restore(); } catch (restoreError) { event('restore_failed', { error: String(restoreError) }); }
      const key = String(error);
      if (!rejected.has(key)) { rejected.add(key); event('not_installed', { error: key }); }
    } finally { installing = false; }
  }
  function findJsonLoads() {
    for (const module of Process.enumerateModules()) {
      if (!/jansson/i.test(module.name)) continue;
      let target = null;
      try { target = module.findExportByName('json_loads'); } catch (_) {}
      if (!target) { try { target = Module.findExportByName(module.name, 'json_loads'); } catch (_) {} }
      if (target) return target;
    }
    return null;
  }
  function discover() {
    if (stopped || installed || discovery) return;
    const target = findJsonLoads();
    if (!target) return;
    discovery = Interceptor.attach(target, { onEnter: function () {
      if (this.context.ebx) install(this.context.ebx);
    } });
    event('waiting_for_jit', { json_loads: target.toString() });
  }
  globalThis.zulaCardRefreshPatch = {
    nativeResources: null,
    status: status,
    stop: function () {
      if (stopPromise) return stopPromise;
      stopped = true;
      if (timer) { clearInterval(timer); timer = null; }
      if (discovery) { discovery.detach(); discovery = null; }
      restore(); installed = false;
                                                                                
                                                                                 
      stopPromise = new Promise(function (resolve) {
        setTimeout(function () { event('stopped', status()); resolve(status()); }, 20);
      });
      return stopPromise;
    }
  };
  if (Process.pointerSize !== 4) { event('not_installed', { error: 'Verified client is ia32 only' }); return; }
  discover();
  if (!installed) timer = setInterval(discover, 500);
})();
