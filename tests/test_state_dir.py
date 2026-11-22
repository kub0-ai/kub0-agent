#!/usr/bin/env python3
"""Probe the real state-dir guard and the recovery path with private state only.

The daemon's old `connect|status|history|disconnect` verbs are retired shims,
so recovery from a state directory under temporary storage goes through a
daemon started on it by environment default (never refused) and the `kub0`
client. That daemon also proves the rename's move of the per-user directory:
a 0.4.x `$XDG_STATE_HOME/vallum` becomes `$XDG_STATE_HOME/kub0` on its first
start, account included, and a second start finds nothing to move.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from test_traffic_history_live import Client

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "target/debug/kub0d"
KUB0 = ROOT / "target/debug/kub0"


def run():
    # A second directory outside /tmp lets us exercise aliases into temporary
    # storage. Nothing uses the operator's account or starts the live daemon.
    with tempfile.TemporaryDirectory(prefix="vallum-state-dir-") as td, \
            tempfile.TemporaryDirectory(prefix=".vallum-state-dir-", dir=ROOT) as wd:
        private, durable = Path(td), Path(wd)
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("KUB0_") and not k.lower().endswith("_proxy")}
        env.update(HOME=str(private / "home"), XDG_STATE_HOME=str(private / "state"), XDG_RUNTIME_DIR=str(private),
                   XDG_CONFIG_HOME=str(private / "config"), TMPDIR=str(private))
        alias = durable / "temporary-alias"
        alias.symlink_to(private, target_is_directory=True)
        nested = private / "nested"
        nested.mkdir()
        (durable / "nested-alias").symlink_to(nested, target_is_directory=True)

        def cli(args, extra=None):
            return subprocess.run([str(BIN), *map(str, args)], cwd=ROOT,
                                  env=dict(env, **(extra or {})), text=True,
                                  capture_output=True, timeout=10)

        refused = [Path(root) / "vallum-state-dir-fixture" for root in
                   ("/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp", "/dev/shm")]
        refused += [private, alias, alias / "missing" / "state",
                    durable / "nested-alias" / ".." / "missing",
                    Path("/srv/../tmp/vallum-state-dir-fixture"),
                    Path(os.path.relpath(alias / "missing", ROOT))]
        for path in refused:
            daemon = cli(["--state-dir", path, "--self-test"])
            assert daemon.returncode == 2 and "refusing --state-dir" in daemon.stderr, daemon.stderr
            # The retired client verb answers before it reads any argument.
            connect = cli(["connect", "--state-dir", path,
                           "--server-url", "http://127.0.0.1:9",
                           "--auth-url", "http://127.0.0.1:9"])
            assert connect.returncode == 2 and "kub0 login" in connect.stderr, connect.stderr
            assert not connect.stdout, connect.stdout
        system = cli(["--system", "--state-dir", alias, "--self-test"])
        assert system.returncode == 2 and "refusing --state-dir" in system.stderr

        accepted = ["/srv/vallum", "/tmpfoo/vallum", "/var/tmpx/vallum",
                    "/tmp/../srv/vallum", durable / "missing-state"]
        for path in accepted:
            result = cli(["--state-dir", path, "--self-test"])
            assert result.returncode == 0, result.stderr
        for tmpdir in ("", "/", "/srv/.."):
            result = cli(["--state-dir", "/srv/vallum", "--self-test"], {"TMPDIR": tmpdir})
            assert result.returncode == 0, result.stderr
        custom = durable / "custom-temp"
        custom.mkdir()
        result = cli(["--state-dir", custom / "missing", "--self-test"], {"TMPDIR": str(custom)})
        assert result.returncode == 2 and "refusing --state-dir" in result.stderr
        result = cli(["--state-dir", durable / "custom-temporary", "--self-test"], {"TMPDIR": str(custom)})
        assert result.returncode == 0, result.stderr
        result = cli(["--self-test"])
        assert result.returncode == 0, result.stderr
        for args in (["--state-dir"], ["--state-dir", ""],
                     ["--state-dir", "--system", "--self-test"],
                     ["--state-dir", "-h", "--self-test"]):
            result = cli(args)
            assert result.returncode != 0 and "--state-dir" in result.stderr

        # Recovery: the account and history sit under temporary storage, where
        # an explicit --state-dir is refused, so the daemon is started on them by
        # environment default and read back through kub0. Every URL is a dead
        # loopback port; no operator account, no external request.
        assert KUB0.is_file(), f"{KUB0} is not built (cargo build -p kub0)"
        # The 0.4.x per-user directory, as a pre-rename daemon left it.
        old_state = private / "vallum"
        recovery_state = private / "kub0"
        old_state.mkdir(mode=0o700)
        (old_state / "watchlist.json").write_text("{\"rules\": []}\n")
        account = old_state / "account.json"
        fixture_token = "state-dir-private-fixture-token"
        account.write_text(json.dumps({"schema": 1, "token": fixture_token,
            "github_username": "state-dir-fixture", "connected_at": 1,
            "server_url": "http://127.0.0.1:9"}))
        account.chmod(0o600)
        before = hashlib.sha256(account.read_bytes()).hexdigest()
        account = recovery_state / "account.json"
        ipc_path = private / "recovery.sock"
        denv = dict(env, XDG_STATE_HOME=str(private), KUB0_NO_PTR="1",
                    KUB0_HEARTBEAT_INTERVAL="3600")

        def client(*args):
            return subprocess.run([str(KUB0), "--socket", str(ipc_path), *args], cwd=ROOT,
                                  env=denv, text=True, capture_output=True, timeout=30)

        def bare_start(tag):
            """A start without --migrate-state: it uses the old directory, moves nothing."""
            with open(private / f"{tag}.log", "w") as log:
                d = subprocess.Popen([str(BIN), "--socket", str(ipc_path), "--interval-ms", "200"],
                                     env=denv, stdout=subprocess.DEVNULL, stderr=log)
                c = None
                try:
                    c = Client(ipc_path)
                    c.until(lambda event: event.get("type") == "snapshot")
                    status = client("status")
                    assert status.returncode == 0 and "state-dir-fixture" in status.stdout, status.stderr
                finally:
                    if c:
                        c.sock.close()
                    d.terminate()
                    d.wait(timeout=5)

        bare_start("bare")
        assert old_state.is_dir() and not recovery_state.exists(), "a bare start moved the 0.4.x directory"
        assert "moved " not in (private / "bare.log").read_text()

        # The panel's start asks for the move.
        with open(private / "recovery.log", "w") as log:
            daemon = subprocess.Popen([str(BIN), "--socket", str(ipc_path), "--interval-ms", "200",
                                       "--migrate-state"],
                                      env=denv, stdout=subprocess.DEVNULL, stderr=log)
            ipc = None
            try:
                ipc = Client(ipc_path)
                ipc.until(lambda event: event.get("type") == "snapshot")
                assert not old_state.exists(), "the 0.4.x directory was moved, not copied"
                assert (recovery_state / "watchlist.json").is_file()
                assert (recovery_state / "history.sqlite").is_file()
                status = client("status")
                assert status.returncode == 0 and "state-dir-fixture" in status.stdout, status.stderr
                assert fixture_token not in status.stdout + status.stderr
                history = client("history", "--csv")
                assert history.returncode == 0 and "destination" in history.stdout, history.stderr
                assert hashlib.sha256(account.read_bytes()).hexdigest() == before
                logout = client("logout")
                assert logout.returncode == 0 and not account.exists(), logout.stderr
                assert fixture_token not in logout.stdout + logout.stderr
            finally:
                if ipc:
                    ipc.sock.close()
                daemon.terminate()
                daemon.wait(timeout=5)
        # Never moved by a self-test, which opens no state, nor out from under
        # a 0.4.x user daemon still running on that directory: found by its
        # process (argv[0] `vallumd`, its own XDG_STATE_HOME), not a socket.
        guard_home = private / "guard"
        guard_old = guard_home / "vallum"
        guard_old.mkdir(parents=True)
        (guard_old / "watchlist.json").write_text("{\"rules\": []}\n")
        genv = dict(denv, XDG_STATE_HOME=str(guard_home), XDG_RUNTIME_DIR=str(guard_home))
        st = subprocess.run([str(BIN), "--self-test"], env=genv, text=True, capture_output=True, timeout=30)
        assert st.returncode == 0 and guard_old.is_dir() and not (guard_home / "kub0").exists(), st.stderr
        old_daemon = subprocess.Popen(["bash", "-c", f"exec -a {guard_home}/vallumd sleep 60"], env=genv)
        try:
            # Until bash has exec'd, /proc shows `bash -c …`: a kub0d started
            # in that window sees no 0.4.x daemon (seen on the CI runner).
            deadline = time.monotonic() + 5
            while not Path(f"/proc/{old_daemon.pid}/cmdline").read_bytes().split(b"\0")[0].endswith(b"/vallumd"):
                assert time.monotonic() < deadline, "the stand-in 0.4.x daemon never exec'd"
                time.sleep(0.01)
            with open(private / "guard.log", "w") as log:
                daemon = subprocess.Popen([str(BIN), "--interval-ms", "200", "--migrate-state"], env=genv,
                                          stdout=subprocess.DEVNULL, stderr=log)
                ipc = None
                try:
                    ipc = Client(guard_home / "kub0.sock")
                    ipc.until(lambda event: event.get("type") == "snapshot")
                finally:
                    if ipc:
                        ipc.sock.close()
                    daemon.terminate()
                    daemon.wait(timeout=5)
        finally:
            old_daemon.kill()
            old_daemon.wait(timeout=5)
        assert guard_old.is_dir() and (guard_old / "watchlist.json").is_file(), "left where the running daemon has it"
        assert not (guard_home / "kub0").exists(), "and no second directory beside it"
        assert "is still running on" in (private / "guard.log").read_text()

        # A second start: nothing to move, nothing recreated at the old path.
        with open(private / "second.log", "w") as log:
            daemon = subprocess.Popen([str(BIN), "--socket", str(ipc_path), "--interval-ms", "200",
                                       "--migrate-state"],
                                      env=denv, stdout=subprocess.DEVNULL, stderr=log)
            ipc = None
            try:
                ipc = Client(ipc_path)
                ipc.until(lambda event: event.get("type") == "snapshot")
            finally:
                if ipc:
                    ipc.sock.close()
                daemon.terminate()
                daemon.wait(timeout=5)
        assert not old_state.exists() and recovery_state.is_dir()
        moved_log = (private / "recovery.log").read_text()
        assert "moved " + str(old_state) + " to " + str(recovery_state) in moved_log, moved_log
        assert "moved " not in (private / "second.log").read_text()
        assert not (alias / "missing").exists()
        print(json.dumps({"bareStartMovesNothing": True, "userStateMovedOnPanelStart": True, "neverMovedBySelfTestOrUnderAnOldDaemon": True,"temporaryPathsRefused": len(refused), "symlinkAndParentPathsChecked": True,
                          "durableAndNearMissPathsAccepted": len(accepted), "customTmpdirChecked": True,
                          "emptyAndRootTmpdirChecked": True, "privateDefaultsPreserved": True,
                          "temporaryStateRecoveredThroughDaemon": True, "credentialsOmitted": True}))


if __name__ == "__main__":
    run()
