                                                                         

                                                                       
                                                                     
   
import argparse
import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import threading
import time
import uuid


class ProcessMemoryCountersEx(ctypes.Structure):
    _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
        (name, ctypes.c_size_t) for name in ('PeakWorkingSetSize', 'WorkingSetSize',
            'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage', 'QuotaPeakNonPagedPoolUsage',
            'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage', 'PrivateUsage')]


class WinProcessMetrics:
                                                                                     

    def __init__(self, pid):
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.psapi = ctypes.WinDLL('psapi', use_last_error=True)
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(ProcessMemoryCountersEx), wintypes.DWORD]
        self.psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
                                                                               
        self.handle = self.kernel.OpenProcess(0x0400 | 0x0010 | 0x00100000, False, pid)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def read(self):
        wait = self.kernel.WaitForSingleObject(self.handle, 0)
        if wait == 0xffffffff:
            raise ctypes.WinError(ctypes.get_last_error())
        exit_code = wintypes.DWORD()
        if not self.kernel.GetExitCodeProcess(self.handle, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        exited = wait == 0
        result = {'exited': exited, 'exit_code': exit_code.value if exited else None}
        if not exited:
            memory = ProcessMemoryCountersEx()
            memory.cb = ctypes.sizeof(memory)
            if self.psapi.GetProcessMemoryInfo(self.handle, ctypes.byref(memory), memory.cb):
                result.update(private_bytes=int(memory.PrivateUsage), working_set_bytes=int(memory.WorkingSetSize),
                              peak_working_set_bytes=int(memory.PeakWorkingSetSize), peak_commit_bytes=int(memory.PeakPagefileUsage))
            else:
                result['memory_query_error'] = ctypes.get_last_error()
        return result

    def wait_for_exit(self, milliseconds):
        return self.kernel.WaitForSingleObject(self.handle, milliseconds) == 0

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def safe_crash_metadata(crash):
                                                                              
    if crash is None:
        return None
    def field(name):
        try:
            return crash.get(name) if isinstance(crash, dict) else getattr(crash, name, None)
        except Exception:
            return None
    result = {}
    for name in ('pid', 'process_name', 'summary'):
        value = field(name)
        if isinstance(value, (int, float, bool)):
            result[name] = value
        elif isinstance(value, str):
            result[name] = value[:600]
    parameters = field('parameters')
    if isinstance(parameters, dict):
        allowed = ('type', 'exception', 'address', 'thread_id', 'threadId', 'signal', 'code')
        result['parameters'] = {key: (value[:256] if isinstance(value, str) else value)
                                for key, value in parameters.items() if key in allowed and isinstance(value, (str, int, float, bool))}
    return result or {'present': True}


class ClientHealth:
    def __init__(self, pid, output_path=None, *, metrics=None, output=None):
        self.pid = pid
        self.metrics = metrics or WinProcessMetrics(pid)
        self.output = None
        self.owns_output = output is None
        try:
            if output is None:
                output_path = Path(output_path or Path(__file__).resolve().parents[1] / 'logs' / 'client_health.jsonl')
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output = output_path.open('a', encoding='utf-8', buffering=1)
            self.output = output
        except Exception:
            self.metrics.close()
            raise
        self.run_id = uuid.uuid4().hex[:12]
        self.peak_private = 0
        self.peak_working = 0
        self.peak_commit = 0
        self.latest = None
        self.finished = False
        self.write_failed = False
        self.lock = threading.Lock()
        self.record({'op': 'health_start', 'sampling_seconds': 1, 'peak_private_measurement': 'sampled'})

    def record(self, event):
        event = {'utc': datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z'),
                 'pid': self.pid, 'run_id': self.run_id, **event}
        try:
            with self.lock:
                self.output.write(json.dumps(event, ensure_ascii=False) + '\n')
                self.output.flush()
        except (OSError, ValueError) as exc:
            if not self.write_failed:
                print('[HEALTH] log write failed: %s' % exc, file=sys.stderr, flush=True)
            self.write_failed = True

    def poll(self):
        try:
            sample = self.metrics.read()
        except OSError as exc:
            self.record({'op': 'health_error', 'error': str(exc)})
            return self.latest or {'exited': False, 'exit_code': None}
        self.peak_private = max(self.peak_private, sample.get('private_bytes', 0))
        self.peak_working = max(self.peak_working, sample.get('peak_working_set_bytes', sample.get('working_set_bytes', 0)))
        self.peak_commit = max(self.peak_commit, sample.get('peak_commit_bytes', 0))
        sample.update(peak_private_mb=round(self.peak_private / 1048576, 3),
                      peak_working_mb=round(self.peak_working / 1048576, 3),
                      peak_commit_mb=round(self.peak_commit / 1048576, 3))
        for source, destination in [('private_bytes', 'private_mb'), ('working_set_bytes', 'working_mb')]:
            if source in sample:
                sample[destination] = round(sample[source] / 1048576, 3)
        self.latest = sample
        self.record({'op': 'health_sample', **sample})
        return sample

    def finish(self, reason='monitor-ended', crash=None, wait_for_exit=False):
        if self.finished:
            return self.latest
        self.finished = True
        if wait_for_exit:
            self.metrics.wait_for_exit(2000)
        sample = self.poll()
        crash_data = safe_crash_metadata(crash)
        exit_code = sample.get('exit_code')
        event = {'op': 'health_end', **sample, 'reason': str(reason), 'frida_crash': crash_data,
                 'exit_code_hex': '0x%08x' % exit_code if exit_code is not None else None,
                 'abnormal_exit': bool(crash_data is not None or (sample.get('exited') and exit_code != 0))}
        self.record(event)
        return event

    def close(self):
        self.metrics.close()
        with self.lock:
            if self.owns_output and self.output is not None:
                self.output.close()


                                                                              
                                                                              
DIAGNOSTICS_JS = r"""
(function () {
  var exceptionCount = 0, exitCount = 0, exceptionKinds = {};
  var criticalKinds = ['arithmetic', 'access-violation', 'illegal-instruction', 'stack-overflow', 'abort', 'bounds-check'];
  function addressInfo(address) {
    if (!address) return null;
    var result = {address: address.toString()};
    try {
      var module = Process.findModuleByAddress(address);
      if (module) { result.module = module.name; result.offset = address.sub(module.base).toString(); }
    } catch (e) {}
    return result;
  }
  function trace(context) {
    var frames = [], mode = 'accurate';
    try { frames = Thread.backtrace(context, Backtracer.ACCURATE); } catch (e) {}
    if (frames.length < 2) {
      mode = 'fuzzy';
      try { frames = Thread.backtrace(context, Backtracer.FUZZY); } catch (e) {}
    }
    return {mode: mode, frames: frames.slice(0, 20).map(addressInfo)};
  }
  function emit(event) { send({tag: 'HEALTH', event: event}); }
  try {
    Process.setExceptionHandler(function (details) {
      try {
        exceptionCount++;
        var kind = String(details.type || 'unknown');
        var seen = exceptionKinds[kind] = (exceptionKinds[kind] || 0) + 1;
                                                                           
                                                                         
        var critical = criticalKinds.indexOf(kind) !== -1;
        var limit = critical ? 32 : 4;
        if (seen <= limit) {
          var context = details.context, registers = {};
          ['pc','sp','eax','ebx','ecx','edx','esi','edi','ebp','esp','eip',
           'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','rip','r8','r9'].forEach(function (key) {
            if (context[key] !== undefined) registers[key] = context[key].toString();
          });
          var event = {op: 'native_exception', number: exceptionCount, kind_number: seen, critical: critical,
            exception_type: details.type, thread_id: Process.getCurrentThreadId(),
            fault: addressInfo(details.address), registers: registers, backtrace: trace(context)};
          if (details.memory) event.memory = {operation: details.memory.operation, address: details.memory.address.toString()};
          try { event.instruction = Instruction.parse(details.address).toString(); } catch (e) {}
          emit(event);
        } else if (seen === limit + 1) {
          emit({op: 'exception_kind_budget_exhausted', exception_type: kind, max_events: limit});
        }
      } catch (e) { emit({op: 'diagnostic_error', error: String(e).slice(0, 300)}); }
      return false;
    });
    emit({op: 'exception_observer_ready', critical_kinds: criticalKinds,
      critical_max_events_per_kind: 32, other_max_events_per_kind: 4});
  } catch (e) { emit({op: 'diagnostic_error', error: 'exception observer: ' + String(e).slice(0, 300)}); }
  ['ExitProcess', 'RtlExitUserProcess', 'TerminateProcess'].forEach(function (name) {
    try {
      var address = findExp(['kernel32.dll', 'KernelBase.dll', 'ntdll.dll'], name);
      if (!address) { emit({op: 'diagnostic_hook_missing', name: name}); return; }
      Interceptor.attach(address, {onEnter: function (args) {
        if (++exitCount > 24) return;
        var event = {op: 'native_exit_call', name: name,
          exit_code: args[name === 'TerminateProcess' ? 1 : 0].toUInt32(),
          caller: addressInfo(this.returnAddress), thread_id: Process.getCurrentThreadId(),
          backtrace: trace(this.context)};
        if (name === 'TerminateProcess') event.target_handle = args[0].toString();
        emit(event);
      }});
      emit({op: 'exit_observer_ready', name: name, address: addressInfo(address)});
    } catch (e) { emit({op: 'diagnostic_error', name: name, error: String(e).slice(0, 300)}); }
  });
})();
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--duration', type=float, default=600)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.pid < 1 or args.duration <= 0:
        parser.error('pid and duration must be positive')
    monitor = ClientHealth(args.pid, args.output)
    print('[HEALTH] read-only monitor ready for PID %d' % args.pid, flush=True)
    reason = 'monitor-timeout'
    try:
        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            if monitor.poll().get('exited'):
                reason = 'process-exited'
                break
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        reason = 'monitor-interrupted'
    finally:
        final = monitor.finish(reason)
        print('[HEALTH] ' + json.dumps(final, ensure_ascii=False), flush=True)
        monitor.close()


if __name__ == '__main__':
    main()
