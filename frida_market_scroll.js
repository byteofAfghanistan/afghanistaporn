                                                                                
                                                                            
                                                                           
                                                                            
   
(function () {
  'use strict';
  if (globalThis.zulaMarketScrollPatch) return;

                                                                              
  const MARKET_SCROLL_CORE = String.raw`
/* Return the first visible item in the client's fixed-point representation.
 * Keep the original rows-2 stepping and rows-3 lower-edge clamp, without the
 * lossy 1/(rows-2) intermediate. Calculate in double before the final integer.
 */
int ms_scroll_first(int count, int start, int span, int position) {
  int rows, last, row;
  double progress, target;
  if (count <= 9 || span <= 0) return 0;
  rows = count / 3 + (count % 3 != 0);
  last = rows - 3;
  progress = ((double)position - (double)start) / (double)span;
  if (progress <= 0.0) return 0;
  target = ((double)position - (double)start) * (double)(rows - 2) / (double)span;
  row = target >= (double)last ? last : (int)target;
  /* The destination is a signed 32-bit value with ten fractional bits. */
  if (row > 699050) row = 699050;
  return row * 3072;
}
`;
                           

  const MARKET_SCROLL_RUNTIME = String.raw`
typedef unsigned char ms_byte;
typedef struct { volatile unsigned int busy, calls; int count, first; } MSScrollState;
extern MSScrollState scroll_state;

void market_scroll_update(void *anchor) {
  ms_byte *g = (ms_byte *)anchor;
  ms_byte *panel;
  int count, start, span, first;
  ++scroll_state.busy;
  ++scroll_state.calls;
  panel = *(ms_byte **)(g + 0x1817d38);
  count = *(int *)(g + 0x1817330);
  start = *(int *)(g + 0x1817d3c);
  span = *(int *)(g + 0x1817d34);
  first = panel ? ms_scroll_first(count, start, span, *(int *)(panel + 24)) : 0;
  if (panel && (count <= 9 || span <= 0)) *(int *)(panel + 24) = start;
  *(int *)(g + 0x1817e28) = first;
  scroll_state.count = count;
  scroll_state.first = first;
  --scroll_state.busy;
}
`;

  const specifications = [
    { name: 'wheel', position: 0x20f4, length: 1174, hash: 0x9e9d92ac,
      offset: 0x22d, patchLength: 595 },
    { name: 'drag', position: 0x21b4, length: 1273, hash: 0x11c30c05,
      offset: 0x267, patchLength: 595 }
  ];
  let installed = false, installing = false, stopped = false;
  let discovery = null, discoverTimer = null, moduleKeepAlive = null, state = null;
  let activePatches = [], stopPromise = null;
  const rejected = new Set();

  function event(action, fields) {
    send(Object.assign({ kind: 'market_scroll', action: action }, fields || {}));
  }
  function codeHash(pointer, length) {
    const bytes = new Uint8Array(pointer.readByteArray(length));
    let hash = 2166136261;
    for (let i = 0; i < bytes.length; ++i) hash = Math.imul(hash ^ bytes[i], 16777619) >>> 0;
    return hash;
  }
  function verifiedFunction(pointer, anchor, spec) {
    const range = Process.findRangeByAddress(pointer);
    if (!range || range.protection.indexOf('x') < 0) return false;
    const bytes = new Uint8Array(pointer.readByteArray(14));
    const expected = [0x55, 0x53, 0x56, 0x57, 0xe8, 0, 0, 0, 0, 0x58, 0x8b, 0xd8, 0x81, 0xeb];
    if (!expected.every((value, index) => bytes[index] === value)) return false;
    if (!pointer.add(9).sub(pointer.add(14).readU32()).equals(anchor)) return false;
    return codeHash(pointer, spec.length) === spec.hash;
  }
  function snapshot() {
    return state ? { installed: installed, busy: state.readU32(), calls: state.add(4).readU32(),
      count: state.add(8).readS32(), first: state.add(12).readS32() / 1024 } : { installed: installed };
  }
  function writeBlock(address, bytes) {
    Memory.patchCode(address, bytes.byteLength, function (writable) { writable.writeByteArray(bytes); });
  }
  function restoreBlocks() {
    while (activePatches.length) {
      const patch = activePatches[activePatches.length - 1];
      writeBlock(patch.address, patch.original);
      activePatches.pop();
    }
  }
  function install(anchor) {
    if (installed || stopped || installing || Process.pointerSize !== 4) return;
    installing = true;
    try {
      if (anchor.isNull() || anchor.add(0x18fb214).readU32() !== 28 ||
          anchor.add(0x18fb224).readU32() !== 24 || anchor.add(0x18fb228).readU32() !== 4) return;
      const patches = specifications.map(function (spec) {
        const target = anchor.add(spec.position).readPointer();
        if (!verifiedFunction(target, anchor, spec)) return null;
        const address = target.add(spec.offset);
        return { name: spec.name, address: address, original: address.readByteArray(spec.patchLength),
          length: spec.patchLength };
      });
      if (patches.some(function (patch) { return patch === null; })) return;
      state = Memory.alloc(16); state.writeByteArray(new Uint8Array(16));
      moduleKeepAlive = new CModule(MARKET_SCROLL_CORE + MARKET_SCROLL_RUNTIME, { scroll_state: state });
                                                                              
                                                                             
                                                                                
      globalThis.zulaMarketScrollPatch.nativeResources = {
        module: moduleKeepAlive, state: state, patches: patches, anchor: anchor
      };
      const helper = moduleKeepAlive.market_scroll_update.toUInt32();
      patches.forEach(function (patch) {
        const bytes = new Uint8Array(patch.length); bytes.fill(0x90);
                                                                               
                                                                                 
        bytes.set([0x53, 0xb8, helper & 255, (helper >>> 8) & 255, (helper >>> 16) & 255,
          (helper >>> 24) & 255, 0xff, 0xd0, 0x83, 0xc4, 0x04, 0xe9]);
        new DataView(bytes.buffer).setInt32(12, patch.length - 16, true);
                                                                              
        activePatches.push(patch);
        writeBlock(patch.address, bytes);
      });
      installed = true;
      if (discoverTimer) { clearInterval(discoverTimer); discoverTimer = null; }
      setImmediate(function () { if (discovery) { discovery.detach(); discovery = null; } });
      event('installed', { globals: anchor.toString(), wheel: patches[0].address.toString(),
        drag: patches[1].address.toString(), preservedCatalog: true });
    } catch (error) {
      try { restoreBlocks(); } catch (restoreError) { event('restore_failed', { error: String(restoreError) }); }
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

  globalThis.zulaMarketScrollPatch = {
    nativeResources: null,
    status: snapshot,
    stop: function () {
      if (stopPromise) return stopPromise;
      stopped = true;
      if (discoverTimer) { clearInterval(discoverTimer); discoverTimer = null; }
      if (discovery) { discovery.detach(); discovery = null; }
      restoreBlocks();
      installed = false;
                                                                               
                                                                               
                                                                                
                                                                                
      stopPromise = new Promise(function (resolve) {
        function drained() {
          if (state && state.readU32()) { setTimeout(drained, 10); return; }
          setTimeout(function () {
            if (state && state.readU32()) { drained(); return; }
            event('stopped', snapshot()); resolve(snapshot());
          }, 20);
        }
        drained();
      });
      return stopPromise;
    }
  };
  if (Process.pointerSize !== 4) { event('not_installed', { error: 'Verified client is ia32 only' }); return; }
  discover();
  if (!installed) discoverTimer = setInterval(discover, 500);
})();
