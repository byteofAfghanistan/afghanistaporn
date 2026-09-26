'use strict';

                                                                            
                                                                                  
                                           
(function (global) {
  const installations = new Set();
  function installZulaRemoteTLS({pin, curlPath, rewrite, report = () => {}, runtime = global} = {}) {
    if (typeof pin !== 'string' || !/^sha256\/\/[A-Za-z0-9+/]{43}=$/.test(pin) || typeof rewrite !== 'function')
      throw new TypeError('A SHA256 public-key pin and remote URL mapper are required');
    if (typeof curlPath !== 'string' || curlPath.length > 32767 || /[\u0000-\u001f]/.test(curlPath) || !/^[a-z]:[\\/]/i.test(curlPath))
      throw new TypeError('The preflighted absolute Windows curl path is required');
    const expectedCurlPath = curlPath.replace(/\//g, '\\').toLowerCase();
    const {Process, Interceptor, NativeFunction, Memory, ptr} = runtime;
    if (Process.pointerSize !== 4 || typeof Process.attachModuleObserver !== 'function')
      throw new Error('Remote TLS requires IA32 and synchronous module observation');
    const handles = new Map(), multis = new Map(), hooks = [];
    const pinPointer = Memory.allocUtf8String(pin);
                                                                            
                                                                            
                                                                     
    const deniedSocketMulti = Memory.alloc(0x10c);
    deniedSocketMulti.add(0x108).writeU32(1);
    const state = {armed: false, installed: false, failed: false, failure: null};
    let observer, curlModule, setString, setLong, internal = 0;
    function emit(value) { try { report(value); } catch (_) {} }
    const kernel = Process.getModuleByName('kernel32.dll');
    const exit = new NativeFunction(kernel.getExportByName('ExitProcess'), 'void', ['uint'], {abi: 'stdcall', scheduling: 'exclusive'});
    const pinModule = new NativeFunction(kernel.getExportByName('GetModuleHandleExW'), 'int', ['uint', 'pointer', 'pointer'], {abi: 'stdcall', scheduling: 'exclusive', traps: 'none'});
    function fatal(code) {
      state.failed = true; state.failure = code; state.installed = false;
      emit({tag: 'TLS-PIN', msg: code});
                                                                                
                                                                                 
      exit(0x51);
    }
    const key = handle => handle && !handle.isNull() ? handle.toString() : null;
    const record = handle => handles.get(key(handle));
    function readURL(pointer) {
                                                                         
                                                                              
                                                                      
      if (pointer.isNull()) throw new Error('Missing URL');
      for (let size = 0; size <= 16384; size++) {
        if (pointer.add(size).readU8() === 0) return pointer.readUtf8String(size);
      }
      throw new Error('URL too long');
    }
    function fresh() { return {url: null, protected: false, configured: false}; }
    function apply(handle) {
      const row = record(handle);
      if (!row?.protected || state.failed) return !row?.protected && !state.failed;
      row.configured = false;
      try {
        internal++;
                                                                             
                                                                                
                                                                            
                                                                              
        for (const [option, value] of [[10230, pinPointer], [81, 2], [52, 0], [181, 2], [182, 2]]) {
          const result = option === 10230 ? setString(handle, option, value) : setLong(handle, option, value);
          if (result !== 0) { emit({tag: 'TLS-PIN', msg: 'SETOPT_REJECT ' + option + ':' + result}); return false; }
        }
        row.configured = true; return true;
      } catch (_) { emit({tag: 'TLS-PIN', msg: 'SETOPT_FAILED'}); return false; }
      finally { internal--; }
    }
    function permitted(handle, refresh) {
      const row = record(handle);
      if (!state.installed || state.failed || !row || row.url === null) return false;
      return !row.protected || (refresh ? apply(handle) : row.configured);
    }
    function attach(module, name, callbacks) {
      const address = module.getExportByName(name);
      if (!address || address.isNull()) throw new Error('Missing required curl export');
      hooks.push(Interceptor.attach(address, callbacks));
      return address;
    }
    function install(module) {
      if (typeof module.path !== 'string' || module.path.replace(/\//g, '\\').toLowerCase() !== expectedCurlPath) { fatal('CURL_PATH_MISMATCH'); return; }
      if (curlModule) { if (module.base.toString() !== curlModule.base.toString()) fatal('MULTIPLE_CURL_MODULES'); return; }
      curlModule = module;
      try {
                                                                            
                                                                                
                                                                             
                                                                         
        const moduleHandleSlot = Memory.alloc(Process.pointerSize);
        if (pinModule(5, module.base, moduleHandleSlot) === 0 || moduleHandleSlot.readPointer().toString() !== module.base.toString()) {
          fatal('CURL_PIN_FAILED'); return;
        }
                                                                                
        attach(module, 'curl_easy_perform', {
          onEnter(args) { this.blocked = !permitted(args[0], true); if (this.blocked) args[0] = ptr(0); },
          onLeave(result) { if (this.blocked) result.replace(90); }
        });
        attach(module, 'curl_multi_add_handle', {
          onEnter(args) { this.multi = key(args[0]); this.handle = key(args[1]); this.blocked = !multis.has(this.multi) || !permitted(args[1], true); if (this.blocked) args[1] = ptr(0); },
          onLeave(result) { if (this.blocked) result.replace(2); else if (result.toInt32() === 0) multis.get(this.multi).add(this.handle); }
        });
        for (const name of ['curl_multi_perform', 'curl_multi_socket_action']) attach(module, name, {
          onEnter(args) {
            const rows = multis.get(key(args[0]));
            this.blocked = !state.installed || state.failed || !rows || [...rows].some(id => !permitted(ptr(id), false));
            if (this.blocked) args[0] = name === 'curl_multi_socket_action' ? deniedSocketMulti : ptr(0);
          },
          onLeave(result) { if (this.blocked) result.replace(1); }
        });
        const setopt = module.getExportByName('curl_easy_setopt');
        setString = new NativeFunction(setopt, 'int', ['pointer', 'int', '...', 'pointer'], {abi: 'mscdecl', scheduling: 'exclusive', traps: 'none'});
        setLong = new NativeFunction(setopt, 'int', ['pointer', 'int', '...', 'long'], {abi: 'mscdecl', scheduling: 'exclusive', traps: 'none'});
        attach(module, 'curl_easy_init', {onLeave(result) { if (!result.isNull()) handles.set(key(result), fresh()); }});
        attach(module, 'curl_easy_setopt', {
          onEnter(args) {
            if (internal) return;
            this.handle = args[0]; this.option = args[1].toInt32();
            if (!key(this.handle)) return;
            if (this.option === 10002) {
              try {
                const input = readURL(args[2]);
                const mapped = rewrite(input);
                this.url = mapped === null ? input : mapped;
                this.protect = mapped !== null;
                this.urlPointer = Memory.allocUtf8String(this.url); args[2] = this.urlPointer;
              } catch (_) { this.invalidURL = true; }
            } else if (record(this.handle)?.protected) {
              if (this.option === 10230) args[2] = pinPointer;
              else if (this.option === 52) args[2] = ptr(0);
              else if (this.option === 81 || this.option === 181 || this.option === 182) args[2] = ptr(2);
            }
          },
          onLeave(result) {
            if (!this.handle || !key(this.handle)) return;
            if (this.invalidURL) { handles.set(key(this.handle), {url: null, protected: true, configured: false}); return; }
            if (result.toInt32() !== 0) {
              if (record(this.handle)?.protected) record(this.handle).configured = false;
              return;
            }
            if (this.option === 10002) {
              const old = record(this.handle), sticky = Boolean(old?.protected);
              handles.set(key(this.handle), {url: sticky && !this.protect ? null : this.url, protected: sticky || this.protect, configured: false});
              if (this.protect) { apply(this.handle); emit({tag: 'CURL', msg: this.url.split('?')[0]}); }
            }
          }
        });
        attach(module, 'curl_easy_reset', {
          onEnter(args) { this.handle = args[0]; this.protected = Boolean(record(args[0])?.protected); },
          onLeave() { if (key(this.handle)) { handles.set(key(this.handle), {url: null, protected: this.protected, configured: false}); if (this.protected) apply(this.handle); } }
        });
        attach(module, 'curl_easy_duphandle', {
          onEnter(args) { const row = record(args[0]); this.original = row ? {...row} : fresh(); },
          onLeave(result) { if (!result.isNull()) { handles.set(key(result), {...this.original, configured: false}); if (this.original.protected) apply(result); } }
        });
        attach(module, 'curl_easy_cleanup', {onEnter(args) { const id = key(args[0]); handles.delete(id); for (const members of multis.values()) members.delete(id); }});
        attach(module, 'curl_multi_init', {onLeave(result) { if (!result.isNull()) multis.set(key(result), new Set()); }});
        attach(module, 'curl_multi_remove_handle', {
          onEnter(args) { this.multi = key(args[0]); this.handle = key(args[1]); },
          onLeave(result) { if (result.toInt32() === 0) multis.get(this.multi)?.delete(this.handle); }
        });
        attach(module, 'curl_multi_cleanup', {onEnter(args) { multis.delete(key(args[0])); }});
        Interceptor.flush(); state.installed = true; emit({tag: 'TLS-PIN', msg: 'INSTALLED'});
      } catch (_) { fatal('INSTALL_FAILED'); }
    }
    observer = Process.attachModuleObserver({
      onAdded(module) { if (module.name.toLowerCase() === 'libcurl.dll') install(module); },
      onRemoved(module) { if (curlModule && module.base.toString() === curlModule.base.toString()) fatal('CURL_MODULE_REMOVED'); }
    });
    if (!observer) throw new Error('Remote TLS module observation was not armed');
    state.armed = true;
                                                                                
                                                      
    installations.add({observer, hooks, pinPointer, deniedSocketMulti, functions: () => [exit, pinModule, setString, setLong]});
    return Object.freeze({status: () => ({...state})});
  }
  global.installZulaRemoteTLS = installZulaRemoteTLS;
  if (typeof module !== 'undefined' && module.exports) module.exports = {installZulaRemoteTLS};
})(globalThis);
