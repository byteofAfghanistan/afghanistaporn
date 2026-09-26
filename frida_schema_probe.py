# -*- coding: utf-8 -*-
                                                                                

                                                                                 
                                                  

                                                                              
                                                                           
                                                                                  
                                                                                
                                                                              
                                                                                
                                                                              
                                                                               
                                                                        
   
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import threading
import time
import uuid


JS_TEMPLATE = r"""
'use strict';
const cfg = __CONFIG__;
const typeNames = ['object', 'array', 'string', 'integer', 'real', 'true', 'false', 'null'];
const selected = /market|shopversion|memberversion|memberitem|bag|items|extraset|set1|cards|character|getmember.*ver|claim|notification|clanchannel|clanmessages|privatemessages|roomchat|remainingtime|remaningtime|total_time/i;
const endpoint = /\/(?:shop\/(?:getitems|getfeatureditems)|item\/(?:getmyitems|getmybagitems|getmyclaimitems|getmycards|setitemcard|setactivecharacter)|[^/?]*\/[^/?]*(?:member[^/?]*(?:ver|state)|claim|notification)[^/?]*)\b/i;
const nodes = new Map();
const roots = new Map();
const missing = new Map();
const listeners = [];
const queue = [];
const seen = new Set();
const renderTotals = {pan_create: 0, pan_setbutton: 0};
const renderDeltas = {pan_create: 0, pan_setbutton: 0};
let rootSequence = 0, emitted = 0, dropped = 0, stopped = false;

function enqueue(record, unique) {
  if (stopped) return;
  if (unique) {
    const signature = JSON.stringify(record);
    if (seen.has(signature)) return;
    if (seen.size < cfg.maxEvents) seen.add(signature);
  }
  if (emitted >= cfg.maxEvents) { dropped++; return; }
  record.time_ms = Date.now();
  queue.push(record); emitted++;
}
function flush() {
  if (queue.length) send({kind: 'batch', events: queue.splice(0)});
}
function stringAt(p, limit) {
                                                                              
                                                                            
  try { return p.isNull() ? null : p.readCString().split('\x00', 1)[0].slice(0, limit); }
  catch (_) { return '<unreadable>'; }
}
function returnAddress(invocation) {
  return invocation.returnAddress ? invocation.returnAddress.toString() : null;
}
function typeAt(p) {
  if (p.isNull()) return 'missing';
  try { const n = p.readU32(); return n < typeNames.length ? typeNames[n] : 'unknown_enum_' + n; }
  catch (_) { return 'unreadable'; }
}
function contexts(p) {
  if (p.isNull()) return [];
  const stored = nodes.get(p.toString()) || [];
  return stored.filter(c => roots.has(c.root));
}
function remember(p, context) {
                                                                              
  if (p.isNull() || nodes.size >= cfg.maxNodes) return;
  const key = p.toString();
  const previous = contexts(p).filter(c => c.root !== context.root || c.path !== context.path);
  previous.push(context);
  nodes.set(key, previous.slice(-4));
}
function active(context) {
  const root = roots.get(context.root);
  return root && root.selected;
}
function promote(context, hint) {
  const root = roots.get(context.root);
  if (root && !root.selected && selected.test(hint)) {
    root.selected = true;
    enqueue({op: 'root_selected', root: context.root, reason: 'accessed_key', key: hint});
  }
}
function nullContext(tid) {
  const last = missing.get(tid);
  return last && Date.now() - last.time < 25 ? last.contexts : [];
}
function findExport(name) {
  const candidates = ['Jansson.dll', 'jansson.dll'];
  for (const moduleName of candidates) {
    try {
      const mod = Process.findModuleByName(moduleName);
      if (mod) {
        if (typeof mod.findExportByName === 'function') { const p = mod.findExportByName(name); if (p) return p; }
        if (typeof mod.getExportByName === 'function') { const p = mod.getExportByName(name); if (p) return p; }
      }
    } catch (_) {}
  }
  try { if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name); } catch (_) {}
  try { if (typeof Module.findExportByName === 'function') return Module.findExportByName(null, name); } catch (_) {}
  return null;
}
function attach(name, callbacks, required) {
  const p = findExport(name);
  if (!p) {
    enqueue({op: 'hook_missing', name: name, required: !!required});
    return false;
  }
  listeners.push(Interceptor.attach(p, callbacks));
  enqueue({op: 'hook_ready', name: name, address: p.toString()});
  return true;
}

attach('json_loads', {
  onEnter(args) {
    this.prefix = stringAt(args[0], cfg.previewBytes) || '';
    this.caller = returnAddress(this);
                                                                               
                                                                               
    this.parents = contexts(args[0]);
  },
  onLeave(result) {
    const prefix = this.prefix;
    const inherited = this.parents.some(active);
    const byPayload = selected.test(prefix);
    const genericEnvelope = /["']httpcode["']\s*:/.test(prefix) && /["']data["']\s*:/.test(prefix);
    const id = ++rootSequence;
    const root = {ptr: result.toString(), born: Date.now(), selected: inherited || byPayload || genericEnvelope,
      memberVersions: /MemberVersionType/i.test(prefix)};
    roots.set(id, root);
    remember(result, {root: id, path: '$'});
    enqueue({op: 'json_loads', root: id, pointer: result.toString(), type: typeAt(result),
      selected: root.selected, reason: inherited ? 'nested_data_pointer' : byPayload ? 'payload_hint' : genericEnvelope ? 'generic_envelope_candidate' : 'unselected',
      parent_paths: this.parents, preview: prefix.slice(0, cfg.textLimit), preview_scan_bytes: cfg.previewBytes,
      return_address: this.caller});
  }
}, true);

attach('json_object_get', {
  onEnter(args) {
    this.parent = args[0]; this.parentType = typeAt(args[0]);
    this.key = stringAt(args[1], 160) || '<null_key>';
    this.parents = contexts(args[0]);
    this.tid = this.threadId;
    this.caller = returnAddress(this);
    this.parents.forEach(c => promote(c, this.key));
  },
  onLeave(result) {
    const children = this.parents.map(c => ({root: c.root, path: c.path + '[' + JSON.stringify(this.key) + ']'}));
    children.forEach(c => remember(result, c));
    const tracked = children.filter(active);
    if (result.isNull() && tracked.length) missing.set(this.tid, {time: Date.now(), contexts: tracked});
    tracked.forEach(c => enqueue({op: 'json_object_get', root: c.root, path: c.path,
      parent_type: this.parentType, expected_parent_type: 'object', type: typeAt(result),
      pointer: result.toString(), missing: result.isNull(), parent_type_mismatch: this.parentType !== 'object',
      return_address: this.caller}, true));
  }
}, true);

attach('json_array_get', {
  onEnter(args) {
    this.parentType = typeAt(args[0]); this.index = args[1].toUInt32();
    this.parents = contexts(args[0]); this.tid = this.threadId;
    this.caller = returnAddress(this);
  },
  onLeave(result) {
                                                                                 
    const versionArray = this.parents.some(c => { const root = roots.get(c.root); return root && root.memberVersions; });
    if (this.index >= cfg.arrayLimit && !versionArray) return;
    const children = this.parents.map(c => ({root: c.root, path: c.path + '[' + this.index + ']'}));
    children.forEach(c => remember(result, c));
    const tracked = children.filter(active);
    if (result.isNull() && tracked.length) missing.set(this.tid, {time: Date.now(), contexts: tracked});
    tracked.forEach(c => enqueue({op: 'json_array_get', root: c.root, path: c.path,
      parent_type: this.parentType, expected_parent_type: 'array', type: typeAt(result),
      pointer: result.toString(), missing: result.isNull(), parent_type_mismatch: this.parentType !== 'array',
      return_address: this.caller}, true));
  }
}, true);

function accessor(name, expected) {
  attach(name, {
    onEnter(args) {
      this.actual = typeAt(args[0]);
      this.caller = returnAddress(this);
      this.owners = contexts(args[0]).filter(active);
      this.inferredNull = args[0].isNull() && !this.owners.length;
      if (this.inferredNull) this.owners = nullContext(this.threadId);
    },
    onLeave(result) {
      if (!this.owners.length) return;
      this.owners.forEach(c => {
        const record = {op: name, root: c.root, path: c.path,
          expected_type: expected, actual_type: this.actual, return_address: this.caller,
          type_mismatch: expected === 'number' ? !['integer', 'real'].includes(this.actual) : this.actual !== expected};
        if (this.inferredNull) record.path_attribution = 'recent_null_same_thread_heuristic';
        if (name === 'json_string_value') {
          record.result = stringAt(result, cfg.textLimit);
          if (!result.isNull()) remember(result, c);
        } else if (name === 'json_array_size' || name === 'json_object_size') {
          record.result = result.toUInt32();
        } else if (name === 'json_integer_value') {
          record.return_register = result.toString();
          record.result_low32 = result.toInt32();
        }
        enqueue(record, true);
      });
    }
  }, false);
}
accessor('json_array_size', 'array');
accessor('json_object_size', 'object');
accessor('json_string_value', 'string');
accessor('json_integer_value', 'integer');
accessor('json_real_value', 'real');
accessor('json_number_value', 'number');

attach('json_delete', {
  onEnter(args) {
    const key = args[0].toString();
    nodes.delete(key);
    for (const [id, root] of roots) if (root.ptr === key) roots.delete(id);
  }
}, false);

                                                                          
attach('curl_easy_setopt', {
  onEnter(args) {
    if (args[1].toInt32() !== 10002) return;
    const url = stringAt(args[2], 1024) || '';
    if (endpoint.test(url)) enqueue({op: 'request_hint', path: url.replace(/^https?:\/\/[^/]+/i, '').split('?')[0], attribution: 'chronological_only'});
  }
}, false);

if (cfg.renderCounters) {
  ['pan_create', 'pan_setbutton'].forEach(function (name) {
    attach(name, {onEnter() {renderTotals[name]++; renderDeltas[name]++;}}, false);
  });
}
function reportRender() {
  if (renderDeltas.pan_create || renderDeltas.pan_setbutton) {
    enqueue({op: 'render_counts', delta: Object.assign({}, renderDeltas), total: Object.assign({}, renderTotals)});
    renderDeltas.pan_create = 0; renderDeltas.pan_setbutton = 0;
  }
}
const timer = setInterval(function () {
  const now = Date.now();
  for (const [id, root] of roots) if (now - root.born > cfg.rootLifetimeMs) roots.delete(id);
  for (const [key, values] of nodes) if (!values.some(c => roots.has(c.root))) nodes.delete(key);
  for (const [tid, last] of missing) if (now - last.time > 1000) missing.delete(tid);
  reportRender();
  flush();
}, 250);
enqueue({op: 'probe_ready', pointer_size: Process.pointerSize, config: cfg});
flush();
rpc.exports = {
  stop() {
    clearInterval(timer);
    for (const listener of listeners) listener.detach();
    reportRender();
                                                                                 
    queue.push({op: 'probe_summary', time_ms: Date.now(), emitted: emitted, dropped: dropped, tracked_nodes: nodes.size, tracked_roots: roots.size,
      render_totals: cfg.renderCounters ? Object.assign({}, renderTotals) : null});
    flush(); stopped = true;
    return {emitted: emitted, dropped: dropped};
  }
};
"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--pid', type=int, help='Attach this existing PID instead of requiring exactly one zula.exe.')
    parser.add_argument('--duration', type=float, default=60, help='Seconds to trace (default: 60).')
    parser.add_argument('--output', type=Path, default=Path(__file__).resolve().parents[1] / 'logs' / 'schema_probe.jsonl')
    parser.add_argument('--max-events', type=int, default=5000, help='Maximum queued events per run (default: 5000).')
    parser.add_argument('--array-limit', type=int, default=3, help='Trace the first N elements of each array (default: 3).')
    parser.add_argument('--render-counters', action='store_true', help='Also count pan_create/pan_setbutton calls in 250ms batches.')
    args = parser.parse_args()
    if args.duration <= 0 or args.max_events < 1 or args.array_limit < 1 or (args.pid is not None and args.pid < 1):
        parser.error('duration, max-events, array-limit and pid must be positive')
    return args


def main() -> int:
    args = parse_args()
    try:
        import frida
    except ImportError:
        print('Frida is missing. Install in this Python environment: pip install frida', file=sys.stderr)
        return 1
    run_id = uuid.uuid4().hex[:12]
    finished = threading.Event()
    write_lock = threading.Lock()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    session = script = None
    config = {'maxEvents': args.max_events, 'arrayLimit': args.array_limit,
              'maxNodes': 20000, 'previewBytes': 2048, 'textLimit': 180,
              'rootLifetimeMs': max(30000, int(args.duration * 1000) + 1000),
              'renderCounters': args.render_counters}
    with args.output.open('a', encoding='utf-8', buffering=1) as output:
        def write_event(event):
            event = {'run_id': run_id, **event}
            with write_lock:
                output.write(json.dumps(event, ensure_ascii=False) + '\n')

        def on_message(message, data):
            if message.get('type') == 'send':
                payload = message.get('payload', {})
                for event in payload.get('events', []):
                    write_event(event)
                    if event.get('op') in {'probe_ready', 'hook_missing', 'root_selected'}:
                        print(json.dumps(event, ensure_ascii=False), flush=True)
            elif message.get('type') == 'error':
                write_event({'op': 'frida_error', 'message': message})
                print(message.get('stack', message), file=sys.stderr, flush=True)

        def on_detached(reason, *details):
            write_event({'op': 'session_detached', 'reason': str(reason)})
            finished.set()

        try:
            device = frida.get_local_device()
            if args.pid is None:
                matches = [p for p in device.enumerate_processes() if p.name.lower() == 'zula.exe']
                if len(matches) != 1:
                    raise RuntimeError(f'Expected exactly one existing zula.exe; found {len(matches)}. No process was started. Use --pid to select explicitly.')
                pid = matches[0].pid
            else:
                pid = args.pid
            print(f'Attach-only schema probe: PID {pid}, {args.duration:g}s, output {args.output}', flush=True)
            write_event({'op': 'run_start', 'pid': pid, 'duration': args.duration, 'time_ms': int(time.time() * 1000)})
            session = device.attach(pid)
            session.on('detached', on_detached)
            script = session.create_script(JS_TEMPLATE.replace('__CONFIG__', json.dumps(config)))
            script.on('message', on_message)
            script.load()
            deadline = time.monotonic() + args.duration
            while not finished.is_set() and time.monotonic() < deadline:
                finished.wait(min(0.25, max(0, deadline - time.monotonic())))
        except KeyboardInterrupt:
            print('Stopping probe; game is left running.', flush=True)
        except Exception as exc:
            write_event({'op': 'probe_error', 'error': str(exc)})
            print(f'Probe error: {exc}', file=sys.stderr)
            return 1
        finally:
            if script is not None and not finished.is_set():
                try:
                    summary = script.exports_sync.stop()
                    print(f'Probe complete: {summary}', flush=True)
                except Exception as exc:
                    write_event({'op': 'stop_error', 'error': str(exc)})
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
