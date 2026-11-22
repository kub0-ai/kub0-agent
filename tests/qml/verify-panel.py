#!/usr/bin/env python3
"""Render the actual panel on a private headless Sway display, using fixtures.

Requires sway and grim; VALLUM_SWAY_PREFIX can name a privately extracted
Sway package prefix. Never connects to or restarts the user's desktop.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
prefix = os.environ.get("VALLUM_SWAY_PREFIX", "")
sway = str(Path(prefix) / "usr/bin/sway") if prefix else shutil.which("sway")
assert sway and shutil.which("grim"), "sway and grim are required"
evidence = Path(os.environ.get("VALLUM_PANEL_EVIDENCE", "/tmp/vallum-traffic-history-panel"))
evidence.mkdir(parents=True, exist_ok=True)

with tempfile.TemporaryDirectory(prefix="vallum-panel-wayland-") as td:
    private = Path(td)
    for name in ("runtime", "state", "config", "cache"):
        (private / name).mkdir(mode=0o700)
    (private / "Ui").symlink_to("/usr/share/omarchy/shell/Ui")
    (private / "Commons").symlink_to("/usr/share/omarchy/shell/Commons")
    for name in ("panel-harness.qml", "Fixture.js"):
        shutil.copy(ROOT / "tests/qml" / name, private / name)
    config = private / "sway.conf"
    config.write_text("swaybg_command -\nxwayland disable\noutput HEADLESS-1 mode 1000x800\nseat seat0 fallback true\n")
    env = os.environ.copy()
    for key in ("DISPLAY", "WAYLAND_DISPLAY", "WAYLAND_SOCKET", "HYPRLAND_INSTANCE_SIGNATURE", "SWAYSOCK"):
        env.pop(key, None)
    env.update(WLR_BACKENDS="headless", WLR_RENDERER="pixman", WLR_LIBINPUT_NO_DEVICES="1",
        WLR_HEADLESS_OUTPUTS="1", XDG_RUNTIME_DIR=str(private / "runtime"),
        XDG_STATE_HOME=str(private / "state"), XDG_CONFIG_HOME=str(private / "config"),
        XDG_CACHE_HOME=str(private / "cache"))
    if prefix:
        env["LD_LIBRARY_PATH"] = str(Path(prefix) / "usr/lib")
    with open(evidence / "compositor.log", "w") as log:
        compositor = subprocess.Popen([sway, "--config", str(config)], env=env, stdout=log, stderr=log)
        results = []
        try:
            deadline = time.monotonic() + 10
            sockets = []
            while time.monotonic() < deadline:
                sockets = [p for p in (private / "runtime").glob("wayland-*") if p.is_socket()]
                if sockets:
                    break
                assert compositor.poll() is None, "compositor failed; see compositor.log"
                time.sleep(0.05)
            assert sockets, "headless display did not start"
            env.update(WAYLAND_DISPLAY=sockets[0].name, QT_QPA_PLATFORM="wayland", QT_QUICK_BACKEND="software",
                QT_QPA_PLATFORMTHEME="generic", QML2_IMPORT_PATH="/usr/share/omarchy/shell",
                VALLUM_CANDIDATE_DIR=str(ROOT), VALLUM_SCENARIO="populated", VALLUM_HOLD_MS="2200",
                VALLUM_CHECK="", VALLUM_BLOCK_READY="0")
            ipc_sockets = list((private / "runtime").glob("sway-ipc.*.sock"))
            assert len(ipc_sockets) == 1, "private compositor IPC not found"
            env["SWAYSOCK"] = str(ipc_sockets[0])
            swaymsg = str(Path(prefix) / "usr/bin/swaymsg") if prefix else shutil.which("swaymsg")
            pointer = os.environ.get("VALLUM_POINTER", shutil.which("wlrctl"))
            assert pointer, "wlrctl is required for native endpoint pointer checks"
            for view in ("apps", "history", "evidence", "settings", "scoped", "endpoints", "endpoints-failed", "endpoints-disconnected"):
                env["VALLUM_VIEW"] = "endpoints" if view.startswith("endpoints") else view
                env["VALLUM_KUB0"] = "1" if view.startswith("endpoints") and view != "endpoints-disconnected" else "0"
                env["VALLUM_ENDPOINT_CASE"] = "failed" if view == "endpoints-failed" else ""
                env["VALLUM_CHECK"] = "endpoints-native" if view.startswith("endpoints") else ""
                env["VALLUM_HOLD_MS"] = "8000" if view.startswith("endpoints") else "2200"
                env["VALLUM_BLOCK_READY"] = "1" if view.startswith("endpoints") else "0"
                env["VALLUM_HEALTH"] = "stale" if view == "scoped" else "current"
                with open(evidence / (view + ".log"), "w") as panel_log:
                    panel = subprocess.Popen(["quickshell", "-p", str(private / "panel-harness.qml"), "--no-color"], env=env, stdout=panel_log, stderr=panel_log)
                    keyboard = None
                    try:
                        time.sleep(1.4)
                        subprocess.run(["grim", str(evidence / (view + ".png"))], env=env, check=True, timeout=5)
                        if view.startswith("endpoints"):
                            def current():
                                lines = (evidence / (view + ".log")).read_text().splitlines()
                                frames = [json.loads(line.split("ENDPOINT_NATIVE_STATE ", 1)[1]) for line in lines if "ENDPOINT_NATIVE_STATE " in line]
                                assert frames, "endpoint probe did not run"
                                return frames[-1]
                            def click(name):
                                point = current()["points"][name]
                                assert point, name + " is missing"
                                for command in (f"seat seat0 cursor set {point['x']} {point['y']}",):
                                    response = subprocess.run([swaymsg, "-r", command], env=env, text=True, capture_output=True, check=True)
                                    assert all(row["success"] for row in json.loads(response.stdout)), response.stdout
                                subprocess.run([pointer, "pointer", "click", "left"], env=env, check=True)
                                time.sleep(0.2)
                            assert current()["pendingBlock"] == "", "inventory enabled hidden app blocking"
                            if view == "endpoints":
                                assert len(current()["rows"]) == 3 and current()["thisDevice"], current()
                                click("monitoring")
                                assert current()["filter"] == "monitoring" and current()["rows"] == ["fixture-remote"], current()
                                click("monitoring")
                                assert current()["filter"] == "" and len(current()["rows"]) == 3, current()
                                click("self")
                                assert current()["selected"] == "fixture-host", current()
                                click("self")
                                assert current()["selected"] == "", current()
                                click("offline")
                                assert current()["rows"] == ["fixture-offline"], current()
                                click("offline")
                                assert len(current()["rows"]) == 3, current()
                                click("search")
                                keyboard = subprocess.Popen(["wtype", "aarch64", "-s", "600", "-k", "Escape", "-s", "9000"], env=env)
                                time.sleep(0.2)
                                assert current()["rows"] == ["fixture-remote"], current()
                                time.sleep(0.7)
                                assert keyboard.poll() is None, "private keyboard disconnected early"
                                assert len(current()["rows"]) == 3 and current()["opened"], current()
                            elif view == "endpoints-failed":
                                assert len(current()["rows"]) == 3 and "refresh failed" in current()["status"], current()
                            else:
                                assert current()["rows"] == [] and "Connect" in current()["status"], current()
                        subprocess.run(["grim", str(evidence / (view + ".png"))], env=env, check=True, timeout=5)
                        rc = panel.wait(timeout=8)
                    finally:
                        if panel.poll() is None:
                            panel.terminate()
                            panel.wait(timeout=5)
                        if keyboard is not None and keyboard.poll() is None:
                            keyboard.terminate()
                            keyboard.wait(timeout=5)
                text = (evidence / (view + ".log")).read_text()
                errors = [line for line in text.splitlines() if ("WARN" in line or "ERROR" in line) and "not placed in the graphics scene" not in line]
                assert rc == 0 and "HARNESS_PANEL_OPEN true" in text and not errors, {"exitCode":rc, "warnings":errors, "log":str(evidence / (view + ".log"))}
                if view == "evidence":
                    assert "EVIDENCE_DRAWER_OPEN true" in text, "evidence button did not open its drawer"
                if view == "scoped":
                    assert "SCOPED_CANCEL_CONTROL true" in text and "SCOPED_CANCEL com.discordapp.discord 127.0.0.1" in text, "dormant mixed-case rule has no working cancellation control"
                results.append({"view": view, "rendered": True, "warnings": errors})
            (evidence / "results.json").write_text(json.dumps(results, indent=2) + "\n")
            print(json.dumps(results))
        finally:
            compositor.terminate()
            compositor.wait(timeout=5)
