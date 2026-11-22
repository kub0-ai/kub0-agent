#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== cargo test =="
cargo test --workspace

echo "== node model tests =="
node tests/test_connection_model.js
node tests/test_geo.js
node tests/test_health.js
node tests/test_traffic_history.js
node tests/test_scoped_rules.js
node tests/test_evidence.js
node tests/test_capture.js
node tests/test_service_dispatch.js
node tests/test_control.js
node tests/test_panel_changes.js
node tests/test_search_selection.js
node tests/test_activity.js
node tests/test_kub0.js
node tests/test_endpoints.js
node tests/test_peers.js
# Generated from the daemon's serde structs by daemon/tests/wire_contract.rs,
# which cargo test above already checked is current.
node tests/test_wire_contract.js
node tests/test_execgate_contract.js
node tests/test_prefs.js
node tests/test_scroll.js
node tests/test_ux.js
node tests/test_formats.js
node tests/test_policy_timestamps.js
node tests/test_system_status.js
node tests/test_system_status_provenance.js
node tests/test_intel.js
node tests/test_workflows.js
node tests/test_binds.js
node tests/test_setup.js
node tests/test_first_run.js
node tests/test_showcase_fixture.js
python3 tests/test_install_binds.py
python3 tests/test_install_release.py
python3 tests/test_release_tools.py

echo "== no automatic QML replay entrypoint =="
# pipefail-safe: grep -c exits 1 when the count is 0
n="$(grep -c 'startFallback()' Service.qml || true)"
if [[ "$n" != "0" ]]; then
  echo "Service.qml still contains startFallback() ($n)"
  exit 1
fi

echo "== qml row-sync test =="
# Whether a ListView delegate survives a model update is not observable from
# ConnectionModel.js — it is a property of the QML view layer, and it is the
# whole point of syncRows(). Needs the Qt6 runtime specifically: /usr/bin/qml is
# Qt5 on Arch and cannot parse a versionless `import QtQuick`.
QML6=""
for candidate in /usr/lib/qt6/bin/qml /usr/lib/qt6/libexec/qml qml6; do
  if command -v "$candidate" >/dev/null 2>&1; then QML6="$candidate"; break; fi
done
if [[ -n $QML6 ]]; then
  for qml_test in tests/test_row_sync.qml tests/test_prefs_qml.qml tests/test_hero_posture.qml tests/test_naming_focus.qml tests/test_stable_repeaters.qml; do
    qml_log="$(mktemp)"
    # Deliberately NOT a pipeline. Under `set -e -o pipefail` a grep that matches
    # nothing returns 1 and takes the whole script down before the verdict below
    # is ever read — so the runtime's exit code is captured first, on its own, and
    # the output is filtered afterwards where a no-match cannot be fatal.
    set +e
    QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=minimal DISPLAY= WAYLAND_DISPLAY= \
      QT_ASSUME_STDERR_HAS_CONSOLE=1 QT_LOGGING_RULES="*=true" \
      "$QML6" "$qml_test" >"$qml_log" 2>&1
    qml_rc=$?
    set -e
    echo "== qml $(basename "$qml_test") =="
    sed -n 's/^qml: //p' "$qml_log"
    rm -f "$qml_log"
    [[ $qml_rc -eq 0 ]] || { echo "qml $(basename "$qml_test") FAILED (exit $qml_rc)"; exit 1; }
  done
  # The panel's sub-views, instantiated against the stub kit in tests/qml/kitstub
  # (no Omarchy, no quickshell). Proves every binding in IntelView, HistoryView,
  # ConnectionEvidence and DestinationRules resolves and that fixture rows render.
  qml_log="$(mktemp)"
  set +e
  QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=minimal DISPLAY= WAYLAND_DISPLAY= \
    QT_QUICK_BACKEND=software QT_ASSUME_STDERR_HAS_CONSOLE=1 \
    "$QML6" -I tests/qml/kitstub tests/qml/kit-harness.qml >"$qml_log" 2>&1
  qml_rc=$?
  set -e
  echo "== qml kit-harness (sub-views against the stub kit) =="
  grep -v '^qml: ok' "$qml_log" | grep -v XDG_RUNTIME_DIR || true
  grep -c '^qml: ok' "$qml_log" | sed 's/$/ checks ok/'
  rm -f "$qml_log"
  [[ $qml_rc -eq 0 ]] || { echo "qml kit-harness FAILED (exit $qml_rc)"; exit 1; }
  # WheelStep.qml on a real Flickable and ListView: a notch, the speed choice,
  # the coast after a swipe. It imports the kit's Style, hence the stub path.
  qml_log="$(mktemp)"
  set +e
  QT_QPA_PLATFORM=offscreen QT_QPA_PLATFORMTHEME=minimal DISPLAY= WAYLAND_DISPLAY= \
    QT_QUICK_BACKEND=software QT_ASSUME_STDERR_HAS_CONSOLE=1 \
    "$QML6" -I tests/qml/kitstub tests/test_scroll_feel.qml >"$qml_log" 2>&1
  qml_rc=$?
  set -e
  echo "== qml test_scroll_feel.qml =="
  sed -n 's/^qml: //p' "$qml_log"
  rm -f "$qml_log"
  [[ $qml_rc -eq 0 ]] || { echo "qml test_scroll_feel.qml FAILED (exit $qml_rc)"; exit 1; }
else
  echo "  skipped — no Qt6 qml runtime found"
fi

echo "== kub0d --self-test =="
cargo build -p vallumd
target/debug/kub0d --self-test

# The live tests below read back through the CLI (the daemon's `history`,
# `disconnect` and `status` are retired shims), so it is built first.
cargo build -p kub0

echo "== explicit state directory guard and recovery =="
python3 tests/test_state_dir.py

echo "== local TCP, history restart and export =="
python3 tests/test_traffic_history_live.py
python3 tests/test_capture_fallback.py
# A database is read from the data dir the daemon was given, and nowhere else.
python3 tests/test_data_dir.py
python3 tests/test_endpoints_live.py
python3 tests/test_netpolicy_live.py
# The CLI against the daemon it was just built with.
python3 tests/test_kub0_cli_live.py
# The fleet test renders through the real helper binary; build it here rather
# than trusting one left over from an earlier local build.
cargo build -p vallum-block
python3 tests/test_fleet_nft.py

echo "== replay fixture parses =="
node -e '
const fs = require("fs");
const CM = require("./ConnectionModel.js");
const lines = fs.readFileSync("tests/fixtures/replay.ndjson","utf8").trim().split("\n");
let s = CM.emptyState();
for (const line of lines) s = CM.applyLine(s, line, 1);
if (s.count < 1) { console.error("replay produced empty model"); process.exit(1); }
console.log("replay connections", s.count, "apps", Object.keys(s.apps).length);
'

echo "all off-device tests passed"
