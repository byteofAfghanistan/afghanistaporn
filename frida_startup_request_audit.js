'use strict';

                                                                             
                                                                             
(function (global) {
  const ENDPOINTS = new Map([
    ['/zula/lobi/getmyuserinfo', '/zula/lobi/GetMyUserInfo'],
    ['/lobi/getmyuserinfo', '/lobi/GetMyUserInfo'],
    ['/zula/lobi/serverlogon', '/zula/lobi/ServerLogOn'],
    ['/lobi/serverlogon', '/lobi/ServerLogOn'],
    ['/zula/server/getserverlist', '/zula/server/GetServerList'],
    ['/server/getserverlist', '/server/GetServerList'],
    ['/zula/server/getserverlist2', '/zula/server/GetServerList2'],
    ['/server/getserverlist2', '/server/GetServerList2']
  ]);
  const FIELDS = new Set(['Token', 'token', 'TOKEN', 'MemberId', 'UserId', 'Id', 'ID',
    'NickName', 'Version', 'GameVersion', 'ServerId', 'ChannelId', 'Language', 'Locale',
    'HardwareId', 'HardwareID', 'HWID', 'MacAddress', 'ComputerName', 'SessionId',
    'LaunchId', 'Data', 'data', 'Request', 'DeviceId', 'OS', 'CPU', 'GPU']);

  function tokenMeta(entries, checksum) {
    const values = entries.filter(row => /^(?:Token|token|TOKEN)$/.test(row[0]));
    const exact = values.find(row => row[0] === 'Token') || values[0];
    const out = {token_present: !!exact, token_count: values.length};
    if (!exact) return out;
    out.token_field = exact[0];
    const value = exact[1];
    out.token_type = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    if (typeof value === 'string') {
      out.token_length = value.length;
      out.token_lower_hex = /^[a-f0-9]+$/.test(value);
      if (value.length <= 1024) out.token_sha256 = checksum(value);
    }
    return out;
  }
  function fieldsMeta(entries, checksum) {
    return Object.assign({field_names: [...new Set(entries.map(row => row[0]).filter(name => FIELDS.has(name)))].sort(),
      field_count: entries.length, unknown_field_count: entries.filter(row => !FIELDS.has(row[0])).length}, tokenMeta(entries, checksum));
  }
  function formEntries(value) {
    if (!value) return [];
    return value.split('&').slice(0, 128).map(part => {
      const index = part.indexOf('=');
      const decode = text => decodeURIComponent(text.replace(/\+/g, ' '));
      return [decode(index < 0 ? part : part.slice(0, index)), decode(index < 0 ? '' : part.slice(index + 1))];
    });
  }
  function bodyMeta(value, checksum) {
    const text = value.trim();
    try {
      if (text.startsWith('{') || text.startsWith('[') || text.startsWith('"')) {
        const obj = JSON.parse(text);
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return {body_format: 'json_nonobject'};
        return Object.assign({body_format: 'json'}, fieldsMeta(Object.keys(obj).slice(0, 128).map(name => [name, obj[name]]), checksum));
      }
      return Object.assign({body_format: 'form'}, fieldsMeta(formEntries(text), checksum));
    } catch (_) { return {body_format: 'invalid'}; }
  }
  function urlMeta(value, checksum) {
    const match = /^https?:\/\/[^/?#]+([^?#]*)(?:\?([^#]*))?(?:#.*)?$/i.exec(value);
    if (!match) return null;
    const endpoint = ENDPOINTS.get(match[1].toLowerCase());
    if (!endpoint) return null;
    try { return {endpoint, query: fieldsMeta(formEntries(match[2] || ''), checksum)}; }
    catch (_) { return {endpoint, query: {format: 'invalid'}}; }
  }

  function installZulaStartupRequestAudit({runtime = global, report = value => send(value), budget = 16} = {}) {
    if (!Number.isInteger(budget) || budget < 1 || budget > 16) throw Error('Invalid audit budget');
    const {Process, Interceptor, Checksum} = runtime;
    const handles = new Map(), forms = new Map(), hooks = [], modules = new Set();
    let count = 0;
    const digest = value => Checksum.compute('sha256', value);
    const key = p => p && !p.isNull() ? p.toString() : null;
    function text(pointer, maximum) {
      if (!pointer || pointer.isNull()) return '';
      for (let length = 0; length <= maximum; length++) {
        if (pointer.add(length).readU8() === 0) return pointer.readUtf8String(length);
      }
      throw Error('Audit input bound');
    }
    function row(handle) {
      const id = key(handle);
      if (!id) return null;
      if (!handles.has(id)) {
        if (handles.size >= 64) return null;
        handles.set(id, {url: null, body: {body_format: 'absent'}});
      }
      return handles.get(id);
    }
    function emit(handle) {
      if (count >= budget) return;
      const value = handles.get(key(handle));
      if (!value || !value.url) return;
      const event = Object.assign({op: 'startup_request_audit', request_number: ++count,
        endpoint: value.url.endpoint, query: value.url.query}, value.body);
      try { report({tag: 'HEALTH', event}); } catch (_) {}
    }
    function attach(module, name, callbacks) { hooks.push(Interceptor.attach(module.getExportByName(name), callbacks)); }
    function added(module) {
      if (module.name.toLowerCase() !== 'libcurl.dll' || modules.has(module.base.toString())) return;
      modules.add(module.base.toString());
      attach(module, 'curl_formadd', {
        onEnter(args) {
          if (count >= budget) return;
          this.first = args[0];
          try {
            let name = null, contents = null, ended = false;
            for (let index = 2; index <= 24; index += 2) {
              const option = args[index].toInt32();
              if (option === 17) { ended = true; break; }
              if (option === 1 || option === 2) name = args[index + 1];
              else if (option === 4 || option === 5) contents = args[index + 1];
              else if (option !== 3 && option !== 6) break;                    
            }
            if (!ended || name === null) { this.formUnsupported = true; return; }
            const field = text(name, 64);
            const safeName = FIELDS.has(field) ? field : null;
            this.entry = {name: safeName, token: /^(?:Token|token|TOKEN)$/.test(field) && contents !== null ?
              tokenMeta([[field, text(contents, 1024)]], digest) : null};
          } catch (_) { this.formUnsupported = true; }
        },
        onLeave(result) {
          if (!this.first || result.toInt32() !== 0) return;
          try {
            const id = key(this.first.readPointer()); if (!id) return;
            if (!forms.has(id)) {
              if (forms.size >= 64) return;
              forms.set(id, {body_format: 'multipart', field_names: [], field_count: 0,
                unknown_field_count: 0, token_present: false, token_count: 0});
            }
            const value = forms.get(id);
            if (this.formUnsupported || !this.entry || value.field_count >= 128) { value.body_format = 'multipart_partial'; return; }
            value.field_count++;
            if (this.entry.name === null) value.unknown_field_count++;
            else if (!value.field_names.includes(this.entry.name)) { value.field_names.push(this.entry.name); value.field_names.sort(); }
            if (this.entry.token) {
              const total = value.token_count + 1;
              if (!value.token_present || this.entry.name === 'Token') Object.assign(value, this.entry.token);
              value.token_count = total;
            }
          } catch (_) {}
        }
      });
      attach(module, 'curl_formfree', {onEnter(args) { forms.delete(key(args[0])); }});
      attach(module, 'curl_easy_setopt', {
        onEnter(args) {
          if (count >= budget) return;
          this.handle = args[0]; this.option = args[1].toInt32();
          try {
            if (this.option === 10002) this.url = urlMeta(text(args[2], 16384), digest);
            else if (this.option === 10015 || this.option === 10165) this.body = bodyMeta(text(args[2], 8192), digest);
            else if (this.option === 10024) this.body = forms.get(key(args[2])) || {body_format: 'multipart_unobserved'};
          } catch (_) { if (this.option !== 10002) this.body = {body_format: 'unreadable'}; }
        },
        onLeave(result) {
          if (!this.handle || result.toInt32() !== 0) return;
          const value = row(this.handle); if (!value) return;
          if (this.option === 10002) value.url = this.url || null;
          else if (this.body) value.body = this.body;
        }
      });
      attach(module, 'curl_easy_perform', {onEnter(args) { emit(args[0]); }});
      attach(module, 'curl_multi_add_handle', {onEnter(args) { emit(args[1]); }});
      attach(module, 'curl_easy_reset', {onEnter(args) { handles.delete(key(args[0])); }});
      attach(module, 'curl_easy_cleanup', {onEnter(args) { handles.delete(key(args[0])); }});
    }
    const observer = Process.attachModuleObserver({onAdded: added});
                                                                            
                                                                            
    return Object.freeze({observer, hooks, status: () => ({records: count, limit: budget})});
  }
  global.installZulaStartupRequestAudit = installZulaStartupRequestAudit;
  if (typeof module !== 'undefined' && module.exports) module.exports = {installZulaStartupRequestAudit, bodyMeta, urlMeta};
  else global.zulaStartupRequestAudit = installZulaStartupRequestAudit();
})(globalThis);
