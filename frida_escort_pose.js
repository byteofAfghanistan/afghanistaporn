                                                                            
                                                                              
(function (root) {
  'use strict';
  function bytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 || !/^[0-9a-f]+$/.test(hex)) throw Error('manifest_invalid');
    return Uint8Array.from(hex.match(/../g), x => parseInt(x, 16));
  }
  function same(a, b) { return a.length === b.length && a.every((v, i) => v === b[i]); }
  function add(a, b) { const n = a + b; if (!Number.isSafeInteger(n) || n < 0 || n > 0xffffffff) throw Error('address_invalid'); return n; }
  function u32(value) { return [value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255]; }
  function makeTrampoline(control, original, globals) {
    const code = [0x9c], branches = [];
    function condition(instruction, branch = 0x75) { code.push(...instruction, branch); branches.push(code.length); code.push(0); }
    condition([0x83, 0x3d, ...u32(control), 1]);
    for (const [key, value] of [['mode', 8], ['level', 1], ['first', 0]]) condition([0x83, 0xbb, ...u32(globals[key]), value]);
    condition([0x83, 0xbb, ...u32(globals.time), 0], 0x7e);
    code.push(0xb8, 0, 4, 0, 0, 0x9d, 0xc3);
    const fallback = code.length; code.push(...original, 0x9d, 0xc3);
    for (const offset of branches) code[offset] = fallback - offset - 1;
    return Uint8Array.from(code);
  }
  function createInstaller(manifest, env, launchId) {
    let finished = false, installing = false, current = null, control = 0;
    const written = [], source = manifest.source;
    function read32(address) { const b = env.read(address, 4); return new DataView(b.buffer, b.byteOffset, 4).getUint32(0, true); }
    function publish(active, reason, extra = {}) {
      current = Object.freeze({kind: 'escort_pose_patch', version: 1, feature: manifest.feature,
        proofHash: manifest.proofHash, launchId, active, reason, ...extra});
      finished = true;
                                                                          
                                                                      
      try { env.report(current); } catch (_) {}
      return current;
    }
    function quiescent(anchor) {
      return read32(add(anchor, source.globals.level)) === 0 && read32(add(anchor, source.globals.time)) === 0 &&
        source.lobbyNullPointers.every(offset => read32(add(anchor, offset)) === 0);
    }
    function verify(anchor) {
      const target = read32(add(anchor, source.rendererPointer));
      for (const spec of source.functions) {
        const pointer = read32(add(anchor, spec.pointerOffset));
        if (spec.relativeToRenderer !== null && pointer !== add(target, spec.relativeToRenderer)) throw Error('fingerprint');
        if (!env.executable(pointer, spec.length) || !same(env.read(pointer, spec.length), bytes(spec.hex))) throw Error('fingerprint');
      }
      if (((target + 9 - read32(target + 14)) >>> 0) !== anchor) throw Error('fingerprint');
      for (const [offset, value] of source.layout) if (read32(add(anchor, offset)) !== value) throw Error('fingerprint');
      return target;
    }
    function boundary(anchor, returnAddress) {
      const entry = read32(add(anchor, source.lobbyParserPointer));
      return returnAddress === add(entry, source.lobbyReturnOffset);
    }
    function stop(reason = 'timeout') { if (!finished) publish(false, reason); return current; }
    function attempt(anchor, returnAddress) {
      if (finished || installing) return false;
      try { if (!boundary(anchor, returnAddress)) return false; } catch (_) { return false; }
      installing = true;
      try {
        const target = verify(anchor);
        if (!quiescent(anchor)) throw Error('not_initial_lobby');
        const code = env.allocatePage(); control = env.allocatePage();
        if (!code || !control || code % 4096 || control % 4096 || code === control) throw Error('allocation_failed');
        env.write(control, Uint8Array.from([0, 0, 0, 0]));
        if (read32(control) !== 0) throw Error('write_failed');
        const patches = source.sites.map((spec, index) => {
          const entry = add(code, index * 256), original = bytes(spec.original), site = add(target, spec.offset);
          const trampoline = makeTrampoline(control, original, source.globals);
          env.write(entry, trampoline);
          if (!same(env.read(entry, trampoline.length), trampoline)) throw Error('write_failed');
          return {site, original, replacement: Uint8Array.from([0xe8, ...u32((entry - (site + 5)) >>> 0), 0x90])};
        });
        if (!env.makeExecutable(code, 4096) || !env.flush(code, 4096)) throw Error('protection_failed');
        verify(anchor);                                                               
        for (const patch of patches) {
          if (!quiescent(anchor)) throw Error('quiescence_lost');
          if (!same(env.read(patch.site, 6), patch.original)) throw Error('fingerprint');
          written.push(patch);                                                    
          env.patch(patch.site, patch.replacement);
          if (!same(env.read(patch.site, 6), patch.replacement) || !env.flush(patch.site, 6)) throw Error('write_failed');
        }
        if (!quiescent(anchor)) throw Error('quiescence_lost');
        env.write(control, Uint8Array.from([1, 0, 0, 0]));
        if (read32(control) !== 1) throw Error('write_failed');
        const sourceHashes = Object.fromEntries(source.functions.map(spec => [spec.name, spec.sha256]));
        publish(true, 'installed', {sourceHashes, anchor: '0x' + anchor.toString(16),
          sites: patches.map(patch => '0x' + patch.site.toString(16))});
        return true;
      } catch (error) {
        let rollbackFailed = false;
        try {
          if (control) {
            env.write(control, Uint8Array.from([0, 0, 0, 0]));
            if (read32(control) !== 0) throw Error('disable_failed');
          }
        } catch (_) { rollbackFailed = true; }
        for (const patch of [...written].reverse()) {
          try {
            if (!quiescent(anchor)) throw Error('quiescence_lost');
            const actual = env.read(patch.site, 6);
            if (same(actual, patch.original)) continue;
            if (!same(actual, patch.replacement)) throw Error('unknown_patch_bytes');
            env.patch(patch.site, patch.original);
            if (!same(env.read(patch.site, 6), patch.original) || !env.flush(patch.site, 6)) throw Error('restore_failed');
          } catch (_) { rollbackFailed = true; }
        }
        const allowed = ['fingerprint', 'not_initial_lobby', 'allocation_failed', 'protection_failed', 'quiescence_lost'];
        publish(false, rollbackFailed ? 'rollback_failed' : allowed.includes(error.message) ? error.message : 'write_failed');
        return false;
      } finally { installing = false; }
    }
    return Object.freeze({attempt, stop, status: () => current, finished: () => finished});
  }
  function startFrida(config) {
    if (root.zulaEscortPosePatch) throw Error('duplicate_escort_pose_instance');
    let discovery = null, discoverTimer = null, expiryTimer = null;
    function detachDiscovery() {
      if (discoverTimer !== null) { clearInterval(discoverTimer); discoverTimer = null; }
      if (expiryTimer !== null) { clearTimeout(expiryTimer); expiryTimer = null; }
      if (discovery !== null) { discovery.detach(); discovery = null; }
    }
    const report = value => { send(value); setImmediate(detachDiscovery); };
    if (!config || config.enabled !== true || config.pinned !== true || Process.platform !== 'windows' || Process.arch !== 'ia32') {
      send({kind: 'escort_pose_patch', version: 1, feature: config.manifest.feature, proofHash: config.manifest.proofHash,
        launchId: config.launchId, active: false, reason: 'platform_or_pin'}); return null;
    }
    const kernel = Process.getModuleByName('kernel32.dll');
    const find = name => kernel.getExportByName(name);
    const options = {abi: 'stdcall', scheduling: 'exclusive', traps: 'none'};
    const allocate = new NativeFunction(find('VirtualAlloc'), 'pointer', ['pointer', 'uint', 'uint', 'uint'], options);
    const flush = new NativeFunction(find('FlushInstructionCache'), 'bool', ['pointer', 'pointer', 'uint'], options);
    const currentProcess = new NativeFunction(find('GetCurrentProcess'), 'pointer', [], options)();
    const env = {
      read: (address, length) => new Uint8Array(ptr(address).readByteArray(length)),
      write: (address, value) => ptr(address).writeByteArray(value),
      executable: (address, length) => {
        const region = Process.findRangeByAddress(ptr(address));
        return !!region && region.protection.includes('x') && address + length <= region.base.toUInt32() + region.size;
      },
      allocatePage: () => allocate(ptr(0), 4096, 0x3000, 0x04).toUInt32(),
      makeExecutable: (address, length) => Memory.protect(ptr(address), length, 'r-x') && Memory.queryProtection(ptr(address)) === 'r-x',
      flush: (address, length) => flush(currentProcess, ptr(address), length),
      patch: (address, value) => {
        const protection = Memory.queryProtection(ptr(address));
        try { Memory.patchCode(ptr(address), value.length, writable => writable.writeByteArray(value)); }
        finally {
          if (Memory.queryProtection(ptr(address)) !== protection &&
              (!Memory.protect(ptr(address), value.length, protection) || Memory.queryProtection(ptr(address)) !== protection)) throw Error('protection_failed');
        }
      }, report
    };
    const installer = createInstaller(config.manifest, env, config.launchId);
    function discover() {
      if (installer.finished() || discovery) return;
      for (const module of Process.enumerateModules()) {
        if (!/jansson/i.test(module.name)) continue;
        const target = module.findExportByName('json_loads');
        if (!target) continue;
        discovery = Interceptor.attach(target, {onEnter() {
                                                                             
                                                                               
          installer.attempt(this.context.ebx.toUInt32(), this.returnAddress.toUInt32());
        }});
        break;
      }
    }
    root.zulaEscortPosePatch = Object.freeze({status: installer.status, stop() {
      detachDiscovery();
                                                                               
                                                                            
      return installer.stop('launcher_stopped');
    }});
    try { discover(); discoverTimer = setInterval(() => {
      try { discover(); } catch (_) { installer.stop('discovery_failed'); }
    }, 250); }
    catch (_) { installer.stop('discovery_failed'); }
    expiryTimer = setTimeout(() => installer.stop('timeout'), 90000);
    return root.zulaEscortPosePatch;
  }
  root.startZulaEscortPosePatch = startFrida;
  if (typeof module !== 'undefined' && module.exports) module.exports = {createInstaller, makeTrampoline, startFrida};
})(globalThis);
