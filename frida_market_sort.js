                                                                                   
                                                                                
                                                                               
                                                                               
                                                                       
   
(function () {
  'use strict';
  if (globalThis.zulaMarketSortPatch) return;

                                                                                   
  const MARKET_SORT_CORE = String.raw`
typedef int (*ms_compare_fn)(void *, void *, int);

/* The original scan replaces its candidate iff compare(later, best, mode)>=1024.
 * Ordered tree reduction retains that direction and the original positional tie
 * rule. Each chosen swap and the resulting array are identical to selection sort
 * for the client's key comparators (including their +/-1024 equality behavior).
 * Empty/inactive leaves never reach the comparator.
 */
static int ms_winner(int left, int right, void **items, int mode,
                     ms_compare_fn compare, unsigned int *comparisons) {
  if (left < 0) return right;
  if (right < 0) return left;
  ++*comparisons;
  return compare(items[right], items[left], mode) >= 1024 ? right : left;
}

static void ms_update(int leaf, int value, int *tree, unsigned int leaves,
                      void **items, int mode, ms_compare_fn compare,
                      unsigned int *comparisons) {
  unsigned int at = leaves + (unsigned int)leaf;
  tree[at] = value;
  while ((at >>= 1) != 0)
    tree[at] = ms_winner(tree[at * 2], tree[at * 2 + 1], items, mode,
                         compare, comparisons);
}

int ms_sort_core(void **items, int count, int mode, ms_compare_fn compare,
                 int *tree, unsigned int leaves, unsigned int *comparisons) {
  unsigned int i, node;
  int best;
  void *temporary;
  if (count < 0 || leaves == 0 || (leaves & (leaves - 1)) != 0 ||
      (unsigned int)count > leaves || !comparisons || !compare || !tree ||
      (count != 0 && !items)) return -1;
  *comparisons = 0;
  for (i = 0; i < leaves; ++i) tree[leaves + i] = i < (unsigned int)count ? (int)i : -1;
  for (node = leaves - 1; node != 0; --node)
    tree[node] = ms_winner(tree[node * 2], tree[node * 2 + 1], items, mode,
                           compare, comparisons);
  for (i = 0; i < (unsigned int)count; ++i) {
    best = tree[1];
    if (best < (int)i || best >= count) return -2;
    if (best != (int)i) {
      temporary = items[i]; items[i] = items[best]; items[best] = temporary;
    }
    // Update the displaced winner first, then remove the sorted prefix leaf.
    // Intermediate tree states are never queried as a result.
    if (best != (int)i)
      ms_update(best, best, tree, leaves, items, mode, compare, comparisons);
    ms_update((int)i, -1, tree, leaves, items, mode, compare, comparisons);
  }
  return 0;
}
`;
                         

  const MARKET_SORT_RUNTIME = String.raw`
#include <stddef.h>
typedef struct { void **array; int used; int size; } MSView;
typedef struct {
  unsigned int busy, calls, count, comparisons, status, fallbacks;
} MSState;
typedef void (*ms_sort_fn)(int);
extern MSView market_view;
extern MSState market_state;
extern ms_sort_fn market_original;
extern int market_compare(void *, void *, int);
extern void market_refresh(void);
extern void *market_malloc(size_t);
extern void market_free(void *);

void market_sort(int mode) {
  unsigned int leaves = 1, comparisons = 0;
  int count = market_view.used, result;
  int *tree;
  ++market_state.calls;
  market_state.count = count < 0 ? 0 : (unsigned int)count;
  market_state.comparisons = 0;
  market_state.status = 0;
  // Validation/allocation failures preserve the unmodified original routine.
  if (market_state.busy || count < 0 || count > market_view.size ||
      count > 1048576 || (count && !market_view.array)) {
    ++market_state.fallbacks; market_state.status = 1;
    market_original(mode); return;
  }
  if (count < 2) { market_refresh(); return; }
  while (leaves < (unsigned int)count) leaves <<= 1;
  tree = (int *)market_malloc((size_t)leaves * 2 * sizeof(int));
  if (!tree) {
    ++market_state.fallbacks; market_state.status = 2;
    market_original(mode); return;
  }
  market_state.busy = 1;
  result = ms_sort_core(market_view.array, count, mode, market_compare,
                         tree, leaves, &comparisons);
  market_free(tree);
  market_state.comparisons = comparisons;
  market_state.status = result == 0 ? 0 : 3;
  market_state.busy = 0;
  if (result != 0) { ++market_state.fallbacks; market_original(mode); return; }
  market_refresh();
}
`;

  const positions = {
    sort: 0x212c, compare: 0x20f8, refresh: 0x2134, view: 0x181732c,
    usedOffset: 0x18fb7c0, arrayOffset: 0x18fb7c8, itemSize: 0x18b00b0
  };
  const verifiedCode = {
    sort: { length: 1520, hash: 0x036c03e2 },
    compare: { length: 3076, hash: 0xcf5d9924 },
    refresh: { length: 231, hash: 0xa01852b6 }
  };
  let installed = false, installing = false, stopped = false;
  let discovery = null, discoverTimer = null, statsTimer = null;
  let moduleKeepAlive = null, state = null, originalSlot = null, target = null;
                                                                            
                                                                               
  const nativeResources = {};
  let lastCalls = 0;
  const rejected = new Set();
  function event(action, fields) {
    send(Object.assign({ kind: 'market_sort', action: action }, fields || {}));
  }
  function exported(module, name) {
    try { return module.findExportByName(name); } catch (_) {}
    try { return Module.findExportByName(module.name, name); } catch (_) {}
    return null;
  }
  function findJsonLoads() {
    for (const module of Process.enumerateModules()) {
      if (!/jansson/i.test(module.name)) continue;
      const p = exported(module, 'json_loads');
      if (p) return p;
    }
    return null;
  }
  function allocator() {
    for (const module of Process.enumerateModules()) {
      if (!/^(?:msvcr\w*|ucrtbase)\.dll$/i.test(module.name)) continue;
      const allocate = exported(module, 'malloc'), release = exported(module, 'free');
      if (allocate && release) return { allocate: allocate, release: release, module: module.name };
    }
    throw new Error('No matching loaded CRT malloc/free pair');
  }
  function codeHash(pointer, length) {
    const bytes = new Uint8Array(pointer.readByteArray(length));
    let hash = 2166136261;
    for (let i = 0; i < bytes.length; ++i) hash = Math.imul(hash ^ bytes[i], 16777619) >>> 0;
    return hash;
  }
  function verifiedFunction(pointer, base, fingerprint) {
    const range = Process.findRangeByAddress(pointer);
    if (!range || range.protection.indexOf('x') < 0) return false;
    const prologue = Array.from(new Uint8Array(pointer.readByteArray(14)));
    const expected = [0x55, 0x53, 0x56, 0x57, 0xe8, 0, 0, 0, 0, 0x58, 0x8b, 0xd8, 0x81, 0xeb];
    if (!expected.every((value, index) => prologue[index] === value)) return false;
    if (!pointer.add(9).sub(pointer.add(14).readU32()).equals(base)) return false;
    return codeHash(pointer, fingerprint.length) === fingerprint.hash;
  }
  function snapshot() {
    if (!state) return { installed: installed };
    return { installed: installed, busy: state.readU32(), calls: state.add(4).readU32(),
      count: state.add(8).readU32(), comparisons: state.add(12).readU32(),
      status: state.add(16).readU32(), fallbacks: state.add(20).readU32() };
  }
  function install(base) {
    if (installed || stopped || installing || Process.pointerSize !== 4) return;
    installing = true;
    try {
      if (base.isNull() || base.add(positions.usedOffset).readU32() !== 4 ||
          base.add(positions.arrayOffset).readU32() !== 0 ||
          base.add(positions.itemSize).readU32() !== 584) return;
      const functions = {};
      for (const name of ['sort', 'compare', 'refresh']) {
        functions[name] = base.add(positions[name]).readPointer();
        if (!verifiedFunction(functions[name], base, verifiedCode[name])) return;
      }
      if (typeof Interceptor.replaceFast !== 'function') throw new Error('Frida replaceFast required for safe original fallback');
      const crt = allocator();
      state = Memory.alloc(24); state.writeByteArray(new Uint8Array(24));
      originalSlot = Memory.alloc(Process.pointerSize); originalSlot.writePointer(ptr(0));
      moduleKeepAlive = new CModule(MARKET_SORT_CORE + MARKET_SORT_RUNTIME, {
        market_view: base.add(positions.view), market_state: state,
        market_original: originalSlot, market_compare: functions.compare,
        market_refresh: functions.refresh, market_malloc: crt.allocate, market_free: crt.release
      });
      nativeResources.module = moduleKeepAlive;
      nativeResources.state = state;
      nativeResources.originalSlot = originalSlot;
      target = functions.sort;
      originalSlot.writePointer(Interceptor.replaceFast(target, moduleKeepAlive.market_sort));
      Interceptor.flush(); installed = true;
      if (discoverTimer) { clearInterval(discoverTimer); discoverTimer = null; }
                                                                  
      setImmediate(function () { if (discovery) { discovery.detach(); discovery = null; } });
      event('installed', { globals: base.toString(), target: target.toString(),
        comparator: functions.compare.toString(), refresh: functions.refresh.toString(), crt: crt.module });
      statsTimer = setInterval(function () {
        const report = snapshot();
        if (!report.busy && report.calls !== lastCalls) { lastCalls = report.calls; event('sorted', report); }
      }, 1000);
    } catch (error) {
      const key = String(error);
      if (!rejected.has(key)) { rejected.add(key); event('not_installed', { error: key }); }
    } finally { installing = false; }
  }
  function discover() {
    if (stopped || installed || discovery) return;
    const p = findJsonLoads();
    if (!p) return;
    discovery = Interceptor.attach(p, { onEnter: function () {
      if (this.context.ebx) install(this.context.ebx);
    } });
    event('waiting_for_jit', { json_loads: p.toString() });
  }
  globalThis.zulaMarketSortPatch = {
    nativeResources: nativeResources,
    status: snapshot,
    stop: function () {
      if (state && state.readU32()) throw new Error('Native sort active; retry after completion');
      stopped = true;
      if (discoverTimer) clearInterval(discoverTimer);
      if (statsTimer) clearInterval(statsTimer);
      if (discovery) discovery.detach();
      if (installed && target) { Interceptor.revert(target); Interceptor.flush(); }
      installed = false; event('stopped');
    }
  };
  if (Process.pointerSize !== 4) { event('not_installed', { error: 'Verified client is ia32 only' }); return; }
  discover();
  if (!installed) discoverTimer = setInterval(discover, 500);
})();
