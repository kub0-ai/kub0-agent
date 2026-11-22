#!/usr/bin/env bash
# Privileged tests use private mount/network namespaces and disposable cgroups.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ $(id -u) -ne 0 ]]; then
  # Some PAM fingerprint prompts use stdout. Keep authentication outside the
  # redirected JSON report, then reuse the resulting sudo credential cache.
  /usr/bin/sudo -v >&2
  exec /usr/bin/sudo -n "$ROOT/tests/verify-root-enhancements.sh" "$@"
fi
[[ ${SUDO_UID:-0} -ne 0 ]] || { echo 'Run this script through sudo from your non-root account.' >&2; exit 1; }
export VALLUM_TEST_PARENT_NETNS="$(readlink /proc/self/ns/net)"
export VALLUM_TEST_PARENT_MNTNS="$(readlink /proc/self/ns/mnt)"
exec /usr/bin/unshare --mount --net --propagation private /usr/bin/python3 "$ROOT/tests/verify_root_enhancements.py" "$@"
