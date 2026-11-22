#!/usr/bin/env python3
"""Fleet network policy, end to end, on a real kub0d against a local fixture API.

Runs inside a fresh unprivileged network namespace (`unshare -Urn`), so the
"public" destinations are TEST-NET addresses bound to the namespace's own
loopback and nothing leaves the machine. No operator account or tenant data.

Proves, on the live daemon:
  positive   a connection to 198.51.100.7 matches the `ip` rule: its connect
             event carries the rule, and the next heartbeat reports hits and the
             destination
  near miss  a connection to 198.51.100.8 matches nothing
  floor      a rule covering 127.0.0.0/8 never shows on a connection and never
             reports a destination; it is counted as suppressed instead
  etag       the second policy fetch sends If-None-Match and a 304 keeps the set
  panel      the fleet frame carries the policies and this run's counts
  block      a block rule's match is would_block, never blocked: a user-mode
             kub0d cannot enforce, and its enforcement state says why
  snooze     a monitor rule snoozes over the socket; a block rule's snooze is
             refused by the policy's default user_can_snooze
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time

if os.environ.get("VALLUM_NETNS") != "1":
    # Loud, not silent: a skipped live test must never read like a passing one.
    if subprocess.call(["unshare", "-Urn", "true"], stderr=subprocess.DEVNULL) != 0:
        print("test_netpolicy_live.py SKIPPED: unprivileged user namespaces are unavailable")
        sys.exit(0)
    env = dict(os.environ, VALLUM_NETNS="1")
    sys.exit(subprocess.call(["unshare", "-Urn", sys.executable, __file__], env=env))

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_traffic_history_live import Client, BIN, ROOT  # noqa: E402

for cmd in (["ip", "link", "set", "lo", "up"],
            ["ip", "addr", "add", "198.51.100.7/32", "dev", "lo"],
            ["ip", "addr", "add", "198.51.100.8/32", "dev", "lo"],
            ["ip", "addr", "add", "198.51.100.10/32", "dev", "lo"]):
    subprocess.run(cmd, check=True)

POLICY = {"policies": [{"id": "p1", "name": "Fixture", "mode": "monitor", "user_can_snooze": "monitor_only",
    "version": 7, "rules": [
        {"id": "r-hit", "kind": "ip", "action": "monitor", "match": {"cidr": "198.51.100.7/32"}},
        {"id": "r-floor", "kind": "ip", "action": "monitor", "match": {"cidr": "127.0.0.0/8"}}]},
    {"id": "p2", "name": "Blocker", "mode": "block", "version": 3, "rules": [
        {"id": "r-block", "kind": "ip", "action": "block", "match": {"cidr": "198.51.100.10/32"}}]}]}
ETAG = '"fixture-1"'


def run():
    key = secrets.token_urlsafe(24)
    heartbeats, policy_gets = [], []

    class API(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, body, status=200, headers=()):
            data = b"" if body is None else json.dumps(body).encode()
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path == "/ingest/heartbeat":
                heartbeats.append(json.loads(body))
            self.reply({"status": "ok"})

        def do_GET(self):
            if self.path.startswith("/detonate/api/enforce/netpolicy"):
                inm = self.headers.get("If-None-Match", "")
                policy_gets.append({"path": self.path, "ifNoneMatch": inm,
                    "auth": self.headers.get("Authorization") == "Bearer " + key})
                if inm == ETAG:
                    self.reply(None, 304, [("ETag", ETAG)])
                else:
                    self.reply(POLICY, 200, [("ETag", ETAG)])
            elif self.path == "/api/nodes":
                self.reply({"nodes": [], "count": 0, "node_limit": 10})
            else:
                self.reply({"version": 1, "entries": []})

    server = ThreadingHTTPServer(("127.0.0.1", 0), API)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    server_url = "http://127.0.0.1:" + str(server.server_port)

    with tempfile.TemporaryDirectory(prefix="vallum-netpolicy-live-") as td:
        private = Path(td)
        state = private / "state" / "kub0"
        state.mkdir(parents=True, mode=0o700)
        home = private / "home"
        home.mkdir(mode=0o700)
        account = state / "account.json"
        fd = os.open(account, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump({"schema": 1, "token": key, "github_username": "fixture-user",
                "connected_at": 1, "server_url": server_url}, handle)
        env = {k: v for k, v in os.environ.items() if not k.startswith("KUB0_") and not k.lower().endswith("_proxy")}
        env.update(HOME=str(home), XDG_STATE_HOME=str(private / "state"), XDG_RUNTIME_DIR=str(private), XDG_CONFIG_HOME=str(private / "config"),
            KUB0_SERVER_URL=server_url, KUB0_NODE_NAME="fixture node", KUB0_HEARTBEAT_INTERVAL="15")
        socket_path = private / "monitor.sock"
        listeners, clients = [], []
        with open(private / "daemon.log", "w") as log:
            daemon = subprocess.Popen([str(BIN), "--socket", str(socket_path), "--interval-ms", "300",
                "--data-dir", str(ROOT / "data")], env=env, stdout=subprocess.DEVNULL, stderr=log)
            ipc = None
            try:
                ipc = Client(socket_path)
                ipc.until(lambda v: v.get("type") == "fleet" and v.get("netpolicies"), 15)

                # 127.0.0.1 is the floor canary: held open so the sampler is sure to see it.
                for addr in ("198.51.100.7", "198.51.100.8", "198.51.100.10", "127.0.0.1"):
                    srv = socket.socket()
                    srv.bind((addr, 0))
                    srv.listen()
                    listeners.append(srv)
                    clients.append(socket.create_connection(srv.getsockname()))

                # One wait for all three: until() discards what it does not match, so
                # waiting per address would drop a frame that arrived out of order.
                # A connection can show up twice (client and accepted side); keep all.
                seen = {}

                def collect(v):
                    if v.get("type") == "connect":
                        seen.setdefault(v.get("remote", {}).get("ip"), []).append(v)
                    return all(ip in seen for ip in ("198.51.100.7", "198.51.100.8", "198.51.100.10", "127.0.0.1"))
                ipc.until(collect, 10)

                hits = [c for c in seen["198.51.100.7"] if c.get("policy")]
                assert hits, seen["198.51.100.7"]
                assert [p["ruleId"] for p in hits[0]["policy"]] == ["r-hit"], hits[0]["policy"]
                assert hits[0]["policy"][0]["label"] == "Fixture: traffic to 198.51.100.7/32"
                for c in seen["198.51.100.8"] + seen["127.0.0.1"]:
                    assert "policy" not in c, (c["remote"], c.get("policy"))

                deadline = time.monotonic() + 40
                report = None
                while time.monotonic() < deadline and report is None:
                    for hb in heartbeats:
                        rows = {m["rule_id"]: m for m in hb.get("policy_matches", [])}
                        if "r-hit" in rows and "r-floor" in rows and "r-block" in rows:
                            report = rows
                    time.sleep(0.5)
                assert report, "no heartbeat carried policy_matches"
                assert report["r-hit"]["hits"] >= 1 and report["r-hit"]["dests"] == ["198.51.100.7"], report["r-hit"]
                assert report["r-hit"]["policy_id"] == "p1" and report["r-hit"]["policy_version"] == 7
                assert report["r-hit"]["would_block"] == 0, "monitor only"
                blk = report["r-block"]
                assert blk["hits"] >= 1 and blk["would_block"] >= 1 and blk["blocked"] == 0, blk
                floor = report["r-floor"]
                assert floor["hits"] == 0 and floor["dests"] == [], floor
                assert floor["suppressed"] >= 1, floor
                for hb in heartbeats:
                    for m in hb.get("policy_matches", []):
                        assert all(not d.startswith("127.") for d in m["dests"]), m

                assert all(g["auth"] for g in policy_gets)
                assert policy_gets[0]["path"] == "/detonate/api/enforce/netpolicy?node=fixture%20node", policy_gets[0]
                assert any(g["ifNoneMatch"] == ETAG for g in policy_gets[1:]), policy_gets

                frame = ipc.until(lambda v: v.get("type") == "fleet" and any(
                    r["id"] == "r-hit" and r["hits"] >= 1 for p in v.get("netpolicies", []) for r in p["rules"]), 25)
                rules = {r["id"]: r for p in frame["netpolicies"] for r in p["rules"]}
                assert rules["r-hit"]["label"] == "Fixture: traffic to 198.51.100.7/32"
                enf = frame["netpolicyEnforcement"]
                assert enf["state"] == "monitor" and not enf["enforcing"] and "system service" in enf["reason"], enf
                assert rules["r-block"]["effectiveAction"] == "block" and not rules["r-block"]["enforced"]
                assert rules["r-hit"]["canSnooze"] and not rules["r-block"]["canSnooze"]

                ipc.send({"cmd": "netpolicy-snooze", "ruleId": "r-hit", "seconds": 600})
                snoozed = ipc.until(lambda v: v.get("type") == "fleet" and any(
                    r["id"] == "r-hit" and r.get("snoozedUntil", 0) > 0 for p in v.get("netpolicies", []) for r in p["rules"]), 10)
                assert snoozed
                ipc.send({"cmd": "netpolicy-snooze", "ruleId": "r-block", "seconds": 600})
                refused = ipc.until(lambda v: v.get("type") == "status" and "does not allow" in v.get("message", ""), 10)
                assert refused
                ipc.send({"cmd": "netpolicy-resume", "ruleId": "r-hit"})
                ipc.until(lambda v: v.get("type") == "fleet" and any(
                    r["id"] == "r-hit" and r.get("snoozedUntil", 0) == 0 for p in v.get("netpolicies", []) for r in p["rules"]), 10)
                assert json.loads((private / "state" / "kub0" / "netpolicy-snoozes.json").read_text()) == {}
                assert key not in json.dumps(frame) and key not in (private / "daemon.log").read_text()
                print(json.dumps({"positiveMatchReported": True, "nearMissSilent": True,
                    "floorNeverAHit": True, "floorSuppressedCounted": True, "etagRevalidated": True,
                    "panelFrameCarriesCounts": True, "blockIsWouldBlockInUserMode": True,
                    "snoozeHonoursPolicy": True, "credentialsOmitted": True}))
            except BaseException:
                log.flush()
                diagnostic = (private / "daemon.log").read_text().replace(key, "[redacted]")
                print(json.dumps({"heartbeats": heartbeats, "policyGets": policy_gets, "daemonLog": diagnostic[-3000:]}))
                raise
            finally:
                for s in clients + listeners:
                    s.close()
                if ipc:
                    ipc.sock.close()
                daemon.terminate()
                daemon.wait(timeout=5)
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    run()
