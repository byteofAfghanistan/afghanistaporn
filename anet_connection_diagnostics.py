                                                                                  
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import uuid


def diagnostics_enabled(emulator, environ=None):
    value = (os.environ if environ is None else environ).get("ZULA_ANET_DIAGNOSTICS", "")
    return value == "1" or (value != "0" and bool(emulator))


_PHASES = {
    "module_added", "module_removed", "hook_missing", "hook_failed", "counters",
    "enet_init", "enet_init_client", "first_callback", "socket", "WSAStartup", "send", "receive",
    "preinit_callback", "jit_state", "jit_verified", "jit_rejected",
}
_HOOKS = {"enet_init", "enet_init_client", "anet_callback", "socket", "WSAStartup", "WSASendTo", "WSARecvFrom",
          "BE_InitClient", "BE_RunClient", "BE_RequestRestartClient", "anet_cl_exit"}
_BOOLS = {"header_valid", "sent_time", "compressed", "reliable", "jit_verified"}
_RANGES = {
    "result": (-2147483648, 2147483647), "port_fixed": (-2147483648, 2147483647),
    "port": (0, 65535), "thread_last_error": (0, 65535), "bytes": (0, 262144),
    "peer_id": (0, 4095), "session": (0, 3), "command": (0, 15), "channel": (0, 255),
    "number": (1, 24), "attempt": (1, 100000000), "init_attempts": (0, 100000000),
    "callbacks": (0, 100000000), "sends": (0, 100000000), "receives": (0, 100000000),
    "delay_ms": (0, 10000),
    "preinit_callbacks": (0, 100000000),
    "game_level_state": (-2147483648, 2147483647), "game_anet_active": (-2147483648, 2147483647),
    "be_active": (-2147483648, 2147483647), "restart_reason": (-2147483648, 2147483647),
}


def safe_event(event):
    if not isinstance(event, dict) or event.get("op") != "anet_diagnostic":
        return None
    phase = event.get("phase")
    if not isinstance(phase, str) or phase not in _PHASES:
        return None
    clean = {"op": "anet_diagnostic", "phase": phase}
    if event.get("module") == "ANet.dll":
        clean["module"] = "ANet.dll"
    name = event.get("name")
    if isinstance(name, str) and name in _HOOKS:
        clean["name"] = name
    if event.get("stage") in ("before", "after"):
        clean["stage"] = event["stage"]
    for name in _BOOLS:
        if type(event.get(name)) is bool:
            clean[name] = event[name]
    for name, (minimum, maximum) in _RANGES.items():
        value = event.get(name)
        if type(value) is int and minimum <= value <= maximum:
            clean[name] = value
    return clean


class AnetConnectionLog:
    def __init__(self, path, pid, budget=96):
        if type(pid) is not int or pid <= 0 or type(budget) is not int or not 1 <= budget <= 128:
            raise ValueError("Invalid diagnostic bounds")
        self.path = Path(path)
        self.pid = pid
        self.run_id = uuid.uuid4().hex
        self.remaining = budget
        self.lock = threading.Lock()

    def record(self, event):
        clean = safe_event(event)
        if clean is None:
            return False
        with self.lock:
            if not self.remaining:
                return False
            self.remaining -= 1
            clean.update(time=datetime.now(timezone.utc).isoformat(), pid=self.pid, run_id=self.run_id)
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as output:
                    output.write(json.dumps(clean, separators=(",", ":")) + "\n")
                return True
            except OSError:
                                                                            
                return False
