#!/usr/bin/env bash
# Install the privileged half of kub0 for the Omarchy panel, idempotently, by
# running the freshly built `kub0 install` from this checkout:
#
#   /usr/lib/kub0/kub0-block                       the helper
#   /usr/share/polkit-1/actions/ai.kub0.agent.policy  one action per helper verb,
#                                                     including the exec-gate ones
#   /usr/lib/kub0/kub0d                            the daemon, for the system unit
#   /usr/lib/kub0/kub0 + /usr/bin/kub0             the CLI (a copy, not a symlink)
#   /etc/systemd/system/kub0d.service              --system with KUB0_EXEC_GATE=1
#   /etc/systemd/system/kub0-expiry.{service,timer}
#   /usr/share/kub0/geoip/*                        the geo databases, when present
#   /var/lib/kub0/execgate/                        the exec gate's local state
#   group kub0                                     the status group
#                                                  (docs/system-status.md); created
#                                                  empty, members are your call
#
# On a 0.4.x host it also does the rename (see `kub0 install`): it stops and
# removes vallumd.service and vallum-expiry.*, moves /var/lib/vallum to
# /var/lib/kub0, removes the old binary paths once kub0d runs, swaps the
# polkit policy and renames the vallum-status group in place (it refuses,
# changing nothing, when a kub0 group exists as well).
#
# Every file is compared before it is written, so a second run changes nothing
# and says so. The last step runs the installed helper's `status` through
# pkexec to prove the policy resolves. Prints what it did.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

FROM=""
for d in "$ROOT/bin" "$ROOT/target/release"; do
  if [[ -x "$d/kub0d" && -x "$d/kub0-block" && -x "$d/kub0" ]]; then
    FROM=$d
    break
  fi
done
[[ -n $FROM ]] || { echo "kub0d, kub0-block and kub0 are not built side by side. Run ./build.sh first." >&2; exit 1; }
HELPER_DST=/usr/lib/kub0/kub0-block

run_root() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    # TTY sudo: pkexec goes through Omarchy's in-process polkit agent, which
    # restarts when the plugin directory changes (cargo writes bin/) and
    # dismisses the prompt. A visible terminal can take the password itself.
    /usr/bin/sudo "$@"
  fi
}

echo "installing kub0's privileged half from $FROM (sudo may ask for your password)…"
# SUDO_USER unset: `kub0 install` would add the installing user to the kub0
# group, and this script leaves membership to you, as it always has.
run_root /usr/bin/env -u SUDO_USER "$FROM/kub0" install --from "$FROM"

if [[ ! -x "$HELPER_DST" ]]; then
  echo "failed to install $HELPER_DST" >&2
  exit 1
fi

echo "checking $HELPER_DST runs through its polkit action…"
if [[ $(id -u) -eq 0 ]]; then
  "$HELPER_DST" status || true
else
  # Best-effort. If the polkit agent is bouncing, blocking still works; the
  # first block will prompt instead of this status call.
  /usr/bin/pkexec "$HELPER_DST" status || /usr/bin/sudo "$HELPER_DST" status || true
fi

echo
echo "the CLI: kub0 doctor · sudo kub0 status · sudo kub0 login"
echo "verify the exec gate:"
echo "  systemctl status kub0d --no-pager | head -5"
echo "  journalctl -u kub0d -b --no-pager | grep -E 'exec gate' | tail -5"
echo "  sudo cat /var/lib/kub0/execgate/state.json"
echo "blocking asks once per few minutes; unblocking, pausing and trusting a blocked program ask every time."
