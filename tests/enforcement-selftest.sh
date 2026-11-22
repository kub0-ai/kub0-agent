#!/usr/bin/env bash
#
# Does a block actually block?
#
# Everything else in tests/ checks that the UI and the model agree about what
# is blocked. Nothing checks the only claim that matters to a user: that a
# blocked app genuinely loses the network. This does, end to end, against the
# real privileged helper, the real cgroup and the real nftables ruleset.
#
# It is a FUNCTIONAL validation, not an exploit test. It does not try to evade
# the block — escape and bypass work belongs in the kub0 gVisor sandbox, in a
# session scoped for it.
#
# Safety:
#   - The "app" is a throwaway shell this script spawns. No app you are using
#     is ever blocked, so a failure cannot take your browser off the network.
#   - The egress probe targets one host, once, with a short timeout.
#   - Cleanup runs on EXIT for every path including Ctrl-C, and the script
#     fails loudly if it cannot prove it left no residue behind.
#
# Usage:  sudo bash tests/enforcement-selftest.sh
#
# Root is required because kub0-block is a privileged helper and is not
# setuid — in normal use the shell reaches it through polkit.

set -uo pipefail

HELPER="${KUB0_HELPER:-${VALLUM_HELPER:-/usr/lib/kub0/kub0-block}}"
APP_ID="selftest-$$"
PROBE_HOST="${VALLUM_PROBE_HOST:-1.1.1.1}"
PROBE_PORT="${VALLUM_PROBE_PORT:-443}"
SLICE="/sys/fs/cgroup/vallum.slice"
# The helper PREFIXES the cgroup directory — cgroup_app() builds
# vallum.slice/vallum-<app> (helper/src/main.rs:96). Asserting on $SLICE/$APP_ID
# checks a path that can never exist, which reads as a broken block.
CG_APP="$SLICE/vallum-$APP_ID"

# nft output goes through a variable, never a pipe into grep. Under `pipefail`,
# `nft list ... | grep -q PAT` returns 141 when PAT MATCHES: grep exits on the
# first hit, closes the pipe, and nft dies of SIGPIPE. The gate then fails on
# exactly the condition it is meant to detect.
nft_vallum() { nft list table inet vallum 2>/dev/null; }

pass=0; fail=0
ok()   { echo "  ok    $1${2:+  [$2]}"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1${2:+  [$2]}"; fail=$((fail+1)); }
step() { echo; echo "── $1"; }

[[ $EUID -eq 0 ]] || { echo "must run as root: sudo bash $0" >&2; exit 2; }
[[ -x $HELPER ]]  || { echo "helper not installed at $HELPER" >&2; exit 2; }

# ------------------------------------------------------ who the subject must be
#
# The helper resolves the *invoking* user from PKEXEC_UID/SUDO_UID and never
# from its own euid (helper/src/caller.rs), then refuses any seed pid that user
# does not own. That is a privilege boundary, not an inconvenience: without it,
# anyone who can reach the helper through polkit could freeze root daemons.
#
# So a root-owned subject is not a valid test target — it is the case the helper
# is built to reject. The subject runs as the unprivileged user instead, which
# is also what a real blocked app is.
SUBJECT_UID="${VALLUM_TEST_UID:-${SUDO_UID:-}}"
if [[ -z $SUBJECT_UID || $SUBJECT_UID -eq 0 ]]; then
  echo "need an unprivileged uid for the test subject." >&2
  echo "run under sudo (SUDO_UID is set for you), or: VALLUM_TEST_UID=\$(id -u you) $0" >&2
  exit 2
fi
SUBJECT_GID="${VALLUM_TEST_GID:-${SUDO_GID:-$(id -g "$SUBJECT_UID" 2>/dev/null)}}"
[[ -n $SUBJECT_GID ]] || { echo "cannot resolve gid for uid $SUBJECT_UID" >&2; exit 2; }
command -v setpriv >/dev/null || { echo "setpriv (util-linux) required" >&2; exit 2; }
# Tell the helper who authorized this, so it agrees with who the subject is.
# Under sudo this is already true; setting it covers a bare-root shell.
export SUDO_UID="$SUBJECT_UID" SUDO_GID="$SUBJECT_GID"

# ---------------------------------------------------------------- the subject
#
# A shell that just sleeps. Blocking moves a process tree into vallum.slice, so
# the probe has to run INSIDE this process to inherit that cgroup — curling
# from the script's own shell would prove nothing, because the script is not
# the thing being blocked. That distinction is the entire test.
#
# It runs as SUBJECT_UID, not root: see the ownership note above. The redirects
# are opened by this (root) shell before the exec, so the subject inherits both
# fifo fds already open and never needs access to the paths itself.

fifo_in="$(mktemp -u)"; fifo_out="$(mktemp -u)"
mkfifo "$fifo_in" "$fifo_out"
setsid setpriv --reuid="$SUBJECT_UID" --regid="$SUBJECT_GID" --init-groups \
  bash --noprofile --norc <"$fifo_in" >"$fifo_out" 2>&1 &
SUBJECT=$!
exec {ctl}>"$fifo_in"
exec {res}<"$fifo_out"

cleanup() {
  local rc=$?
  step "cleanup"
  exec {ctl}>&- 2>/dev/null
  exec {res}<&- 2>/dev/null
  kill -9 "$SUBJECT" 2>/dev/null
  [[ -n ${straggler:-} ]] && kill -9 "$straggler" 2>/dev/null
  rm -f "$fifo_in" "$fifo_out"
  # Unblock unconditionally: if the test died between block and unblock, the
  # rule is still live and the only thing standing between the user and a
  # stuck cgroup is this line.
  "$HELPER" unblock-app "$APP_ID" >/dev/null 2>&1
  local leaked=0
  if [[ -d "$CG_APP" ]]; then bad "cgroup left behind" "$CG_APP"; leaked=1; fi
  local residue; residue="$(nft_vallum)"
  if grep -q -- "vallum-$APP_ID" <<<"$residue"; then
    bad "nft rule left behind" "vallum-$APP_ID"; leaked=1
  fi
  (( leaked == 0 )) && echo "  ok    no residue: cgroup and nft ruleset are clean"
  echo
  if (( fail == 0 && leaked == 0 )); then
    echo "ENFORCEMENT VALIDATED — $pass checks passed"
  else
    echo "ENFORCEMENT NOT VALIDATED — $fail failed"
    rc=1
  fi
  exit $rc
}
trap cleanup EXIT INT TERM

# Run a command inside the subject shell and return its exit status. A unique
# sentinel is used rather than a timeout on read, so a slow probe is reported
# as its own real exit code instead of being misread as a block.
in_subject() {
  local cmd="$1" tag="rc-$RANDOM-$RANDOM" line
  printf '%s; echo "%s:$?"\n' "$cmd" "$tag" >&$ctl
  while IFS= read -r -t 25 line <&$res; do
    [[ $line == "$tag":* ]] && { echo "${line#*:}"; return 0; }
  done
  echo "timeout"
}

probe_cmd="timeout 6 bash -c '</dev/tcp/$PROBE_HOST/$PROBE_PORT' 2>/dev/null"

step "0. preconditions"
status="$($HELPER status 2>&1)"
echo "$status" | grep -q '"blockingReady":true' \
  && ok "helper reports blocking ready" \
  || { bad "helper not ready" "$status"; exit 1; }
sleep 0.3
[[ -d /proc/$SUBJECT ]] && ok "test subject alive" "pid $SUBJECT" || { bad "subject died"; exit 1; }
# Assert the drop actually happened. A subject still running as root would be
# rejected by the helper's ownership check, and the failure would read as a
# broken block rather than a broken test.
subj_uid="$(awk '/^Uid:/{print $2}' "/proc/$SUBJECT/status" 2>/dev/null)"
[[ $subj_uid == "$SUBJECT_UID" ]] \
  && ok "subject runs as the invoking user" "uid $subj_uid" \
  || { bad "subject uid is $subj_uid, expected $SUBJECT_UID" "setpriv did not drop"; exit 1; }

step "1. baseline — the subject can reach the network BEFORE any block"
base="$(in_subject "$probe_cmd")"
if [[ $base == "0" ]]; then
  ok "egress succeeds unblocked" "$PROBE_HOST:$PROBE_PORT"
else
  bad "no baseline egress — cannot prove a block did anything" "rc=$base"
  echo "  (offline, or $PROBE_HOST:$PROBE_PORT is unreachable from here)"
  exit 1
fi

# A connection opened BEFORE the block and held open across it. nft's
# `socket cgroupv2` matches the cgroup a socket was created in, so migrating
# the process alone never catches this one; the helper has to close it. A
# probe that only opens fresh connections (step 3) cannot see that gap.
held="$(in_subject "exec 7<>/dev/tcp/$PROBE_HOST/$PROBE_PORT")"
if [[ $held == "0" ]]; then
  ok "held a connection open across the block" "fd 7"
else
  bad "could not open the held connection" "rc=$held"
fi

step "2. block"
out="$("$HELPER" block-app "$APP_ID" "$SUBJECT" 2>&1)"
echo "$out" | grep -q '"ok":true' \
  && ok "helper accepted the block" \
  || { bad "block rejected" "$out"; exit 1; }

# Assert the MECHANISM, not just the helper's own say-so. A helper that
# returned ok:true while moving nothing is exactly the failure this catches.
if grep -qx "$SUBJECT" "$CG_APP/cgroup.procs" 2>/dev/null; then
  ok "subject pid moved into the blocked cgroup" "$CG_APP"
else
  bad "pid is NOT in the blocked cgroup — helper claimed success" "pid $SUBJECT"
fi
ruleset="$(nft_vallum)"
[[ -n $ruleset ]] \
  && ok "nft table 'vallum' exists" \
  || bad "no nft table after a successful block"
if grep -q -- "vallum-$APP_ID" <<<"$ruleset"; then
  ok "a drop rule names this app's cgroup" "vallum-$APP_ID"
else
  bad "nft table has no rule for this app — nothing is enforcing" "vallum-$APP_ID"
fi

step "3a. a connection the app already had is closed, not grandfathered"
if grep -q '"closed":[1-9]' <<<"$out"; then
  ok "helper reports closing existing connections" "$(grep -o '"closed":[0-9]*' <<<"$out")"
else
  bad "helper closed no existing connections" "$out"
fi
# If the socket survived, this write is simply buffered and succeeds. A
# destroyed socket fails it at once (ECONNABORTED).
wrote="$(in_subject "printf x >&7 2>/dev/null")"
if [[ $wrote == "0" ]]; then
  bad "HELD CONNECTION STILL OPEN WHILE BLOCKED — existing sessions bypass the block" "fd 7 writable"
else
  ok "held connection is dead while blocked" "write rc=$wrote"
fi
in_subject "exec 7>&-" >/dev/null

step "3. THE CLAIM — a blocked app cannot reach the network"
blocked="$(in_subject "$probe_cmd")"
if [[ $blocked == "0" ]]; then
  bad "EGRESS STILL WORKS WHILE BLOCKED — the block is cosmetic" "rc=0"
elif [[ $blocked == "timeout" ]]; then
  # The subject shell never answered at all — that is a wedged test harness,
  # not evidence about the network.
  bad "subject shell unresponsive; inconclusive, not a proven block" "no reply in 25s"
elif [[ $blocked == "124" ]]; then
  # `timeout` killed the probe: the SYN went nowhere and nothing answered,
  # which is what an nftables `drop` looks like from inside. A `reject` would
  # have come back immediately with a non-124 status instead.
  ok "egress dropped while blocked — connect hung until timeout" "rc=124"
else
  ok "egress refused while blocked" "rc=$blocked"
fi

step "4. unblock restores the network"
# A process born while blocked has no restore record, and used to keep the
# cgroup busy so unblock failed after the rule was already gone.
# Braced: in_subject appends "; echo", and "&;" is a syntax error.
in_subject "{ sleep 600 >/dev/null 2>&1 & }" >/dev/null
straggler="$(grep -vx "$SUBJECT" "$CG_APP/cgroup.procs" 2>/dev/null | head -1)"
[[ -n $straggler ]] && ok "a process forked while blocked sits in the cgroup" "pid $straggler" \
  || bad "no straggler in the blocked cgroup to test with"
out="$("$HELPER" unblock-app "$APP_ID" 2>&1)"
echo "$out" | grep -q '"ok":true' \
  && ok "helper accepted the unblock" \
  || bad "unblock rejected" "$out"
if [[ -d "$CG_APP" ]]; then
  bad "blocked cgroup still exists after unblock" "$out"
else
  ok "blocked cgroup removed, stragglers rehomed" "$(grep -o '"adopted":\[[^]]*\]' <<<"$out")"
fi

restored="$(in_subject "$probe_cmd")"
if [[ $restored == "0" ]]; then
  ok "egress works again after unblock"
else
  # A block you cannot undo is worse than one that never applied.
  bad "STILL BLOCKED AFTER UNBLOCK — one-way door" "rc=$restored"
fi

step "5. the helper's own view agrees"
after="$($HELPER status 2>&1)"
echo "$after" | python3 -c "
import json,sys
d=json.load(sys.stdin)
owners=d.get('owners') or {}
print('  ok    status reports no owners' if '$APP_ID' not in owners
      else '  FAIL  status still owns $APP_ID')
" 2>/dev/null || echo "  (status not parseable)"
