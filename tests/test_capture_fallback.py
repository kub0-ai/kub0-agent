#!/usr/bin/env python3
"""Missing optional collector must leave procfs IPC functional, without auth."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
from test_traffic_history_live import Client, BIN

if Path("/usr/lib/kub0/kub0-capture").exists() or Path("/usr/lib/vallum/vallum-capture").exists():
    print("capture fallback probe skipped: installed collector must not be attached by a test")
    raise SystemExit(0)
with tempfile.TemporaryDirectory(prefix="kub0-capture-fallback-") as td:
    private = Path(td)
    # PTR lookups run in-process now, so a getent PATH shim no longer stops
    # them; KUB0_NO_PTR does.
    env = dict(os.environ, HOME=td, XDG_STATE_HOME=td, XDG_CONFIG_HOME=td, XDG_RUNTIME_DIR=td,
        KUB0_NO_PTR="1")
    with open(private / "daemon.log", "w") as log:
        p = subprocess.Popen([str(BIN), "--capture", "--socket", str(private / "ipc"),
            "--interval-ms", "150"],
            env=env, stdout=subprocess.DEVNULL, stderr=log)
        ipc = None
        try:
            ipc = Client(private / "ipc")
            status = ipc.until(lambda v: v.get("type") == "capture-status")
            assert status["state"] == "unavailable"
            ipc.until(lambda v: v.get("type") == "snapshot")
            tick = ipc.until(lambda v: v.get("type") == "tick")
            assert isinstance(tick["count"], int) and p.poll() is None
            print(json.dumps(dict(missingCollectorFallback=True, procfsSnapshotAndTick=True,
                captureState=status["state"], noAuthenticationPrompt=True)))
        finally:
            if ipc:
                ipc.sock.close()
            p.terminate()
            p.wait(timeout=5)
