#!/usr/bin/env bash
# Install the optional observer without enabling it or attaching any hooks.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
bash "$ROOT/capture/build.sh"
run_root() { if [[ $(id -u) -eq 0 ]]; then "$@"; else /usr/bin/sudo "$@"; fi; }
run_root /usr/bin/install -d -m 0755 /usr/lib/kub0
run_root /usr/bin/install -m 0755 "$ROOT/target/capture/kub0-capture" /usr/lib/kub0/kub0-capture
run_root /usr/bin/install -m 0644 "$ROOT/polkit/ai.kub0.agent.capture.policy" /usr/share/polkit-1/actions/ai.kub0.agent.capture.policy
# A host that had the 0.4.x collector: its file and its policy go (kub0d runs
# only the one above), and its directory with them when that leaves it empty.
run_root /usr/bin/rm -f /usr/lib/vallum/vallum-capture /usr/share/polkit-1/actions/ai.kub0.vallum.capture.policy
run_root /usr/bin/rmdir /usr/lib/vallum 2>/dev/null || true
echo 'Installed. Capture remains off until enabled in the kub0 panel settings.'
