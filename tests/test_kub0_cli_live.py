#!/usr/bin/env python3
"""The `kub0` CLI against a real user-mode daemon on a private socket.

Reads, the refusal of privileged verbs on a user daemon, request/reply
correlation on the raw socket, and a full device-code login against a local
fixture auth server (partial replies, the account file, logout). No operator
account, no external request, no helper, no root. A fixture token is never
printed by the CLI, and the test checks that.
"""
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

KUB0 = ROOT / "target/debug/kub0"


def kub0(env, *args, timeout=30):
    p = subprocess.run([str(KUB0), *args], env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def run():
    assert KUB0.is_file(), f"{KUB0} is not built (cargo build -p kub0)"
    token = "fixture-" + secrets.token_urlsafe(24)
    polls = {"n": 0}

    class Auth(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, body, status=200):
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path == "/api/auth/device/start":
                self.reply({"device_state": "st-1", "user_code": "ABCD-EFGH",
                            "connect_url": "http://127.0.0.1/connect", "expires_in": 20, "interval": 1})
                return
            self.reply({"status": "ok"})

        def do_GET(self):
            if self.path.startswith("/api/auth/device/poll"):
                polls["n"] += 1
                if polls["n"] < 2:
                    self.reply({"status": "pending"})
                else:
                    self.reply({"status": "complete", "token": token, "github_username": "octo"})
                return
            if self.path.startswith("/detonate/api/enforce/netpolicy"):
                self.reply({"policies": []})
                return
            if self.path == "/api/nodes":
                self.reply({"nodes": [], "count": 0, "node_limit": 10})
                return
            self.reply({"version": 1, "entries": []})

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Auth)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    with tempfile.TemporaryDirectory(prefix="vallum-kub0-cli-live-") as td:
        private = Path(td)
        state_home = private / "state"
        state_home.mkdir(mode=0o700)
        state = state_home / "kub0"
        state.mkdir(mode=0o700)
        home = private / "home"
        home.mkdir(mode=0o700)
        env = dict(os.environ, HOME=str(home), XDG_STATE_HOME=str(state_home), XDG_RUNTIME_DIR=str(private),
                   XDG_CONFIG_HOME=str(private / "config"), KUB0_NO_PTR="1",
                   KUB0_HEARTBEAT_INTERVAL="15")
        sock = private / "monitor.sock"
        log = open(private / "daemon.log", "w")
        daemon = subprocess.Popen([str(BIN), "--socket", str(sock), "--interval-ms", "200"],
                                  env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            raw = Client(sock)
            raw.until(lambda v: v.get("type") == "snapshot")

            # -- reads -------------------------------------------------------
            rc, out, err = kub0(env, "--socket", str(sock), "status")
            assert rc == 0, (rc, err)
            assert "kub0d" in out and "not logged in" in out, out
            rc, out, err = kub0(env, "--socket", str(sock), "--json", "status")
            assert rc == 0, err
            st = json.loads(out)
            assert st["daemon"]["mode"] == "user", st["daemon"]
            assert st["account"]["connected"] is False
            assert st["peer"]["uid"] == os.getuid(), st["peer"]
            assert st["daemon"]["socket"] == str(sock)
            for verb, needle in [("whoami", "not logged in"), ("rules", "not logged in"),
                                 ("endpoints", "not logged in"), ("trusts", "no digests trusted")]:
                rc, out, err = kub0(env, "--socket", str(sock), verb)
                assert rc == 0 and needle in out, (verb, rc, out, err)
            rc, out, err = kub0(env, "--socket", str(sock), "version")
            assert rc == 0 and out.startswith("kub0 ") and "kub0d" in out, (out, err)

            # -- system-daemon verbs refuse on a user daemon, with the fix named:
            # root for a verb that lowers protection, the group for the rest --
            sha = "a" * 64
            for argv in (["trust", sha], ["allow-once", sha], ["unblock", "firefox"],
                         ["unblock", "firefox", "--to", "192.0.2.1"], ["pause"], ["teardown", "--yes"],
                         ["block", "firefox", "--ip", "192.0.2.1"]):
                rc, out, err = kub0(env, "--socket", str(sock), *argv)
                assert rc == 1, (argv, rc, out, err)
                assert "system daemon" in err and "needs root" in err and "sudo kub0" in err, (argv, err)
            for argv in (["untrust", sha], ["block", "firefox"], ["resume"], ["sync"], ["blocks"],
                         ["block", "firefox", "--to", "192.0.2.1", "--for", "5m", "--pid", str(os.getpid())]):
                rc, out, err = kub0(env, "--socket", str(sock), *argv)
                assert rc == 1, (argv, rc, out, err)
                assert "system daemon" in err and "the kub0 group" in err and "needs root" not in err, (argv, err)

            # -- watch, tag and note through requests, on the owner's daemon --
            rc, out, err = kub0(env, "--socket", str(sock), "--json", "watch", "add", "port", "4444", "lab")
            assert rc == 0, (rc, out, err)
            rule = json.loads(out)["rule"]
            assert rule["value"] == "4444" and rule["note"] == "lab" and "owner" not in rule, rule
            rc, out, err = kub0(env, "--socket", str(sock), "watch", "rm", rule["id"])
            assert rc == 0 and rule["id"] in out, (rc, out, err)
            rc, out, err = kub0(env, "--socket", str(sock), "watch", "rm", rule["id"])
            assert rc == 1 and "no watch rule" in err, (rc, out, err)
            rc, out, err = kub0(env, "--socket", str(sock), "tag", "198.51.100.0/24", "Lab", "net")
            assert rc == 0 and "Lab net" in out, (rc, out, err)
            rc, out, err = kub0(env, "--socket", str(sock), "note", "block", "firefox")
            assert rc == 2 and "unknown command note" in err, (rc, out, err)
            rc, out, err = kub0(env, "--socket", str(sock), "policy", "snooze", "no-such-rule")
            assert rc == 1 and "no such rule" in err, (rc, out, err)

            # -- the reads (#61 step 2), each from the daemon's own state --
            for argv, needle in ((["apps"], "app"), (["apps", "--sort", "name", "--live"], "app"),
                                 (["conns"], ""), (["activity", "--since", "1h"], ""),
                                 (["history", "--hours", "1"], ""), (["intel"], "watch rules"),
                                 (["why", "203.0.113.9"], ""), (["policies"], "enforcement"),
                                 (["watches"], "watch"), (["brief", "--hours", "1"], "#")):
                rc, out, err = kub0(env, "--socket", str(sock), *argv)
                assert rc == 0 and needle in out, (argv, rc, out, err)
                rc, out, err = kub0(env, "--socket", str(sock), "--json", *argv)
                assert rc == 0, (argv, rc, err)
                json.loads(out)
            rc, out, err = kub0(env, "--socket", str(sock), "history", "--hours", "1", "--csv")
            assert rc == 0 and out.splitlines()[0].count(",") >= 3, (rc, out, err)
            rc, out, err = kub0(env, "--socket", str(sock), "apps", "--blocked")
            assert rc == 1 and "system daemon" in err, "what is blocked is the helper's, on the system daemon"
            rc, out, err = kub0(env, "--socket", str(sock), "watch", "--help")
            assert rc == 0 and "changes the ones they set" in out and "user daemon is retired" not in out, out
            rc, out, err = kub0(env, "--socket", str(sock), "teardown")
            assert rc == 2 and "--yes" in err, (rc, err)
            rc, out, err = kub0(env, "--socket", str(sock), "nope")
            assert rc == 2 and "unknown command" in err, (rc, err)
            rc, out, err = kub0(env, "--socket", str(private / "absent.sock"), "status")
            assert rc == 3 and "cannot reach" in err, (rc, err)

            # -- raw protocol: one reply, to the asker, with its id ------------
            raw.send({"req": "r1", "cmd": "status"})
            r = raw.until(lambda v: v.get("type") == "reply")
            assert r["req"] == "r1" and r["ok"] is True and not r.get("partial"), r
            assert r["result"]["daemon"]["pid"] == daemon.pid, r["result"]["daemon"]
            raw.send({"req": "r2", "cmd": "bogus"})
            r = raw.until(lambda v: v.get("type") == "reply" and v.get("req") == "r2")
            assert r["ok"] is False and "unknown command" in r["error"], r
            raw.send({"req": "", "cmd": "status"})
            raw.send({"cmd": "status"})
            raw.send({"req": "r3", "cmd": "whoami"})
            r = raw.until(lambda v: v.get("type") == "reply" and v.get("req") == "r3")
            assert r["ok"] is True, r
            # A second client must not see the first client's reply.
            other = Client(sock)
            other.until(lambda v: v.get("type") == "snapshot")
            raw.send({"req": "r4", "cmd": "rules"})
            raw.until(lambda v: v.get("type") == "reply" and v.get("req") == "r4")
            other.send({"req": "o1", "cmd": "whoami"})
            seen = other.until(lambda v: v.get("type") == "reply")
            assert seen["req"] == "o1", seen

            # -- login through the daemon, against the fixture auth server ----
            rc, out, err = kub0(env, "--socket", str(sock), "login", "--auth-url", base, "--server-url", base, timeout=60)
            assert rc == 0, (rc, out, err)
            assert "Open http://127.0.0.1/connect and enter code ABCD-EFGH" in out, out
            assert "connected as octo" in out, out
            assert token not in out and token not in err, "the token must never reach the CLI"
            account = state / "account.json"
            assert account.is_file(), "the daemon writes the account file"
            assert (account.stat().st_mode & 0o777) == 0o600, oct(account.stat().st_mode)
            assert json.loads(account.read_text())["token"] == token
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                rc, out, err = kub0(env, "--socket", str(sock), "--json", "whoami")
                assert rc == 0, err
                who = json.loads(out)
                if who["connected"] and who["githubUsername"] == "octo":
                    break
                time.sleep(0.2)
            else:
                raise AssertionError(f"the daemon never picked the account up: {who}")
            assert token not in out
            rc, out, err = kub0(env, "--socket", str(sock), "whoami")
            assert rc == 0 and "octo" in out and base in out, (out, err)
            rc, out, err = kub0(env, "--socket", str(sock), "logout")
            assert rc == 0 and "disconnected" in out, (rc, out, err)
            assert not account.exists()
            assert (state / "disconnected").exists(), "logout leaves the marker the daemon honours"
            rc, out, err = kub0(env, "--socket", str(sock), "logout")
            assert rc == 0 and "not connected" in out, (out, err)

            # -- the daemon's old client verbs are retired: each names its kub0 command --
            for verb, want in (("status", "kub0 whoami"), ("connect", "kub0 login"), ("history", "kub0 history")):
                p = subprocess.run([str(BIN), verb, "--state-dir", str(state)], env=env, capture_output=True, text=True)
                assert p.returncode == 2 and want in p.stderr and not p.stdout, (verb, p.returncode, p.stdout, p.stderr)
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
            log.close()
            httpd.shutdown()
            text = (private / "daemon.log").read_text()
            assert token not in text, "the daemon must never log the token"
    print("kub0 cli live: ok")


if __name__ == "__main__":
    run()
