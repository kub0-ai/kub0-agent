#!/usr/bin/env python3
"""Actual daemon/API/IPC inventory transitions on a local fixture API only.

No operator account, external requests, desktop, helper mutations or real
tenant data. Fresh temporary credentials are never printed.
"""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time

from test_traffic_history_live import Client, BIN, ROOT


def run():
    keys = [secrets.token_urlsafe(24), secrets.token_urlsafe(24)]
    entered = threading.Event()
    release = threading.Event()
    mode = {"value": "full"}
    trace = []
    started = time.monotonic()

    class API(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, body, status=200):
            trace.append({"elapsed": round(time.monotonic() - started, 2), "path": self.path,
                "mode": mode["value"], "tenantB": self.headers.get("Authorization") == "Bearer " + keys[1], "status": status})
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            # HTTP/1.0 closes each response. Make that explicit so the client
            # cannot pool a socket while this handler is still shutting down.
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.reply({"status": "ok"})

        def do_GET(self):
            # A valid answer to each read, so a fleet frame is the success path: the
            # deny-list body is not a policy set, and the daemon would say so.
            if self.path.startswith("/detonate/api/enforce/netpolicy"):
                self.reply({"policies": []})
                return
            if self.path != "/api/nodes":
                self.reply({"version": 1, "entries": []})
                return
            is_b = self.headers.get("Authorization") == "Bearer " + keys[1]
            current = mode["value"]
            if is_b:
                self.reply({"nodes": [], "count": 0, "node_limit": 10}, 200 if current == "empty" else 500)
                return
            if current == "malformed":
                self.reply({"nodes": None})
                return
            if current == "gate":
                entered.set()
                assert release.wait(8), "fixture response gate timed out"
            seen = datetime.now(timezone.utc).isoformat()
            self.reply({"count": 4, "node_limit": 10, "nodes": [
                {"node_name": "fixture-self", "agent": "vallum", "state": "enforcing", "last_seen": seen, "blocks_active": 3, "agent_ver": "0.2.0"},
                {"node_name": "tenant-a-private-host", "agent": "vallum", "state": "monitoring", "last_seen": seen, "blocks_active": 0},
                {"node_name": "fixture-offline", "agent": "vallum", "state": "down", "last_seen": "2026-01-01T00:00:00Z"},
                {"node_name": "cluster", "agent": "vigiles", "state": "enforced"}
            ]})

    server = ThreadingHTTPServer(("127.0.0.1", 0), API)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    server_url = "http://127.0.0.1:" + str(server.server_port)
    with tempfile.TemporaryDirectory(prefix="vallum-endpoints-live-") as td:
        private = Path(td)
        state_home = private / "state"
        state_home.mkdir(mode=0o700)
        state = state_home / "kub0"
        state.mkdir(mode=0o700)
        home = private / "home"
        home.mkdir(mode=0o700)
        account = state / "account.json"

        def set_account(index):
            # Same display name across tenants: username alone cannot key a cache.
            data = {"schema": 1, "token": keys[index], "github_username": "fixture-user",
                "connected_at": index + 1, "server_url": server_url}
            temporary = state / "new-account.json"
            fd = os.open(temporary, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle)
            temporary.replace(account)

        set_account(0)
        env = {key: value for key, value in os.environ.items() if not key.startswith("KUB0_") and not key.lower().endswith("_proxy")}
        env.update(HOME=str(home), XDG_STATE_HOME=str(state_home), XDG_RUNTIME_DIR=str(private),
            XDG_CONFIG_HOME=str(private / "config"), KUB0_SERVER_URL=server_url,
            KUB0_NODE_NAME="fixture-self", KUB0_HEARTBEAT_INTERVAL="15",
            KUB0_NO_PTR="1")
        socket_path = private / "monitor.sock"
        with open(private / "daemon.log", "w") as log:
            daemon = subprocess.Popen([str(BIN), "--socket", str(socket_path),
                "--interval-ms", "300", "--data-dir", str(ROOT / "data")], env=env,
                stdout=subprocess.DEVNULL, stderr=log)
            ipc = None
            try:
                ipc = Client(socket_path)
                full = ipc.until(lambda v: v.get("type") == "fleet" and v.get("endpointsRefreshOk") is True, 15)
                assert len(full["endpoints"]) == 3
                assert full["selfState"] == "enforcing"
                assert full["netpolicyRefreshOk"] is True, full.get("netpolicyRefreshOk")
                assert {r["nodeName"] for r in full["endpoints"]} == {"fixture-self", "tenant-a-private-host", "fixture-offline"}
                assert next(r for r in full["endpoints"] if r["nodeName"] == "fixture-offline")["blocksActive"] is None
                assert not any(key in json.dumps(full) for key in keys)
                mode["value"] = "malformed"
                failed = ipc.until(lambda v: v.get("type") == "fleet" and v.get("endpointsRefreshOk") is False, 22)
                assert failed["endpoints"] == full["endpoints"]
                assert failed["endpointsUpdatedAt"] == full["endpointsUpdatedAt"]
                assert failed["orgEndpoints"] == full["orgEndpoints"]
                assert failed["nodeLimit"] == full["nodeLimit"]
                assert failed["selfState"] == full["selfState"]
                mode["value"] = "gate"
                assert entered.wait(22), "fixture never received in-flight tenant A fetch"
                set_account(1)
                release.set()
                cleared = ipc.until(lambda v: v.get("type") == "fleet" and v.get("connected") is False, 5)
                assert cleared["endpoints"] == [] and cleared["endpointsUpdatedAt"] == 0
                switched = ipc.until(lambda v: v.get("type") == "fleet" and v.get("connected") is True and v.get("endpointsRefreshOk") is False, 22)
                assert switched["endpoints"] == [] and switched["endpointsUpdatedAt"] == 0
                mode["value"] = "empty"
                empty = ipc.until(lambda v: v.get("type") == "fleet" and v.get("endpointsRefreshOk") is True, 22)
                assert empty["endpoints"] == [] and empty["endpointsUpdatedAt"] > 0
                # Through the daemon: its own disconnect verb is retired.
                subprocess.run([str(ROOT / "target/debug/kub0"), "--socket", str(socket_path), "logout"], env=env,
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                disconnected = ipc.until(lambda v: v.get("type") == "fleet" and v.get("connected") is False, 22)
                assert disconnected["endpoints"] == [] and disconnected["endpointsUpdatedAt"] == 0
                assert not any(key in (private / "daemon.log").read_text() for key in keys)
                print(json.dumps({"mixedTenantInventory": True, "offlineKept": True, "malformedRetainsLastSuccess": True,
                    "inFlightAccountChangeClears": True, "sameUsernameNewTenantClears": True,
                    "validEmptyInventory": True, "disconnectClears": True, "credentialsOmitted": True}))
            except BaseException:
                log.flush()
                diagnostic = (private / "daemon.log").read_text()
                for key in keys: diagnostic = diagnostic.replace(key, "[redacted]")
                print(json.dumps({"fixtureTrace": trace, "daemonLog": diagnostic[-4000:]}))
                raise
            finally:
                release.set()
                if ipc: ipc.sock.close()
                daemon.terminate()
                daemon.wait(timeout=5)
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    run()
