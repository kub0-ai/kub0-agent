#!/usr/bin/env python3
"""Exercise kub0d's real IPC, local TCP traffic, restart and read-only export.

All state lives in a disposable directory. PTR queries are disabled with
KUB0_NO_PTR (lookups are in-process, so a getent PATH shim would not stop
them), and no kub0 account exists in the isolated state directory.
"""
import csv
import io
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug/kub0d"


class Client:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        deadline = time.monotonic() + 10
        while True:
            try:
                self.sock.connect(str(path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        self.buffer = b""

    def send(self, value):
        self.sock.sendall(json.dumps(value).encode() + b"\n")

    def until(self, predicate, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                value = json.loads(line)
                if predicate(value):
                    return value
            if select.select([self.sock], [], [], max(0, deadline - time.monotonic()))[0]:
                data = self.sock.recv(256 * 1024)
                assert data, "daemon disconnected"
                self.buffer += data
        raise AssertionError("timed out waiting for a matching daemon event")


def run():
    with tempfile.TemporaryDirectory(prefix="vallum-traffic-history-live-") as td:
        private = Path(td)
        state_home = private / "state"
        state_home.mkdir(mode=0o700)
        state = state_home / "kub0"
        state.mkdir(mode=0o700)
        home = private / "home"
        home.mkdir(mode=0o700)
        env = dict(os.environ, HOME=str(home), XDG_STATE_HOME=str(state_home), XDG_RUNTIME_DIR=str(private),
            XDG_CONFIG_HOME=str(private / "config"),
            KUB0_NO_PTR="1")
        ipc_path = private / "monitor.sock"
        log = open(private / "daemon.log", "w")

        def start():
            return subprocess.Popen([str(BIN), "--socket", str(ipc_path),
                "--interval-ms", "150", "--data-dir", str(ROOT / "data")], env=env,
                stdout=subprocess.DEVNULL, stderr=log)

        daemon = start()
        ipc = None
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = peer = None
        try:
            ipc = Client(ipc_path)
            ipc.until(lambda v: v.get("type") == "snapshot")
            assert not (state / "account.json").exists(), "probe must not adopt an operator account"
            client = socket.create_connection(listener.getsockname())
            peer, _ = listener.accept()
            client.settimeout(5)
            peer.settimeout(5)
            port = listener.getsockname()[1]
            connected = ipc.until(lambda v: v.get("type") == "connect" and v["remote"]["port"] == port)
            app_id = connected["app"]["id"]
            executable = str(Path("/proc/self/exe").resolve())
            assert connected["exe"] == executable
            ipc.until(lambda v: v.get("type") == "bandwidth" and any(a["id"] == app_id and a["measured"] > 0 for a in v["apps"]))
            time.sleep(0.3)
            client.sendall(b"x" * 8192)
            received = b""
            while len(received) < 8192:
                received += peer.recv(8192 - len(received))
            peer.sendall(b"y" * 4096)
            received = b""
            while len(received) < 4096:
                received += client.recv(4096 - len(received))
            measured = ipc.until(lambda v: v.get("type") == "bandwidth" and any(a["id"] == app_id and a["txBytes"] >= 8192 and a["rxBytes"] >= 4096 and (a["txRate"] or 0) > 0 for a in v["apps"]))
            app = next(a for a in measured["apps"] if a["id"] == app_id)
            client.close()
            peer.close()
            listener.close()
            ipc.until(lambda v: v.get("type") == "disconnect" and v["id"] == connected["id"])
            query = {"cmd": "history", "request": "live-probe", "query": str(port), "since": int(time.time() * 1000) - 60000}
            ipc.send(query)
            history = ipc.until(lambda v: v.get("type") == "history" and v.get("request") == "live-probe")
            assert history["error"] == "", history["error"]
            rows = [e for e in history["entries"] if e["connection"]["id"] == connected["id"]]
            assert len(rows) == 1 and not rows[0]["active"]
            assert rows[0]["connection"]["exe"] == executable
            assert rows[0]["bytes"]["tx"] >= 8192 and rows[0]["bytes"]["rx"] >= 4096
            original = rows[0]
            ipc.sock.close()
            daemon.terminate()
            daemon.wait(timeout=5)
            daemon = start()
            ipc = Client(ipc_path)
            ipc.until(lambda v: v.get("type") == "snapshot")
            ipc.send(query)
            reopened = ipc.until(lambda v: v.get("type") == "history" and v.get("request") == "live-probe")
            retained = next(e for e in reopened["entries"] if e["key"] == original["key"])
            assert retained["firstObserved"] == original["firstObserved"]
            assert retained["lastObserved"] == original["lastObserved"]
            assert not retained["active"]
            # Export through the client: the daemon's own history verb is retired.
            exported = subprocess.check_output([str(ROOT / "target/debug/kub0"), "--socket", str(ipc_path),
                "history", "--query", str(port), "--csv"], env=env, text=True)
            csv_rows = list(csv.DictReader(io.StringIO(exported)))
            assert any(r["destination"] == "127.0.0.1" and r["port"] == str(port) and r["executable"] == executable and int(r["sampled_tx_bytes"]) >= 8192 for r in csv_rows)
            print(json.dumps({"local_tcp_measured": True, "tx_delta": app["txBytes"], "rx_delta": app["rxBytes"],
                "closed_history_retained": True, "restart_preserved_timestamps": True, "csv_export_valid": True}))
        finally:
            if ipc:
                ipc.sock.close()
            for s in (client, peer, listener):
                if s:
                    s.close()
            daemon.terminate()
            daemon.wait(timeout=5)
            log.close()


if __name__ == "__main__":
    run()
