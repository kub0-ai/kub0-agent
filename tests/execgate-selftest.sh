#!/usr/bin/env bash
#
# Root self-test for the system exec gate. CI does not run this: it needs
# EUID 0, and a sandbox without root cannot give it one.
#
#   sudo bash tests/execgate-selftest.sh
#
# Proves the gate end to end with no kub0 server. Keys come only from
# KUB0_EXEC_GATE_DENY_FILE. A listed sha256 is refused, the same bytes
# under another name are refused, one extra byte runs, and the sample runs
# again after the daemon is signaled. A final leg sends SIGTERM and requires
# the process to exit within 5s and the log to contain `exec gate: stopped`.
# The EXIT trap kills the daemon and removes the temp dir and the private
# state dir.
#
# --socket and --state-dir are private. --system defaults to
# /run/kub0/kub0.sock, which bind unlinks, and /var/lib/kub0/daemon.
# kub0d rejects a --state-dir under /tmp. No account file is created:
# without /var/lib/kub0/account.json the process never heartbeats.

set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "refusing: EUID is ${EUID}, need 0. Run: sudo bash tests/execgate-selftest.sh" >&2
  exit 2
fi
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "refusing: uname -s is $(uname -s), need Linux." >&2
  exit 2
fi
if [[ ! -e /proc/sys/fs/fanotify ]]; then
  echo "refusing: /proc/sys/fs/fanotify is absent; this kernel has no fanotify." >&2
  exit 2
fi
if [[ -e /run/kub0 ]]; then
  echo "refusing: /run/kub0 exists. --system rebinds /run/kub0/kub0-status.sock (daemon/src/system_status.rs). Stop the system unit so systemd removes that directory, then rerun." >&2
  exit 2
fi
command -v cargo >/dev/null 2>&1 || {
  echo "refusing: cargo is not on PATH; cannot build kub0d." >&2
  exit 2
}
command -v sha256sum >/dev/null 2>&1 || {
  echo "refusing: sha256sum is not on PATH; cannot key the deny file." >&2
  exit 2
}
command -v od >/dev/null 2>&1 || {
  echo "refusing: od is not on PATH; cannot mint a nonce." >&2
  exit 2
}
command -v timeout >/dev/null 2>&1 || {
  echo "refusing: timeout is not on PATH; a stuck exec must not hang this script." >&2
  exit 2
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

echo "building kub0d (--locked -p vallumd)"
cargo build --locked -p vallumd
bin="${ROOT}/target/debug/kub0d"
if [[ ! -x $bin ]]; then
  echo "FAIL target/debug/kub0d is not executable after cargo build" >&2
  echo "SELFTEST FAIL"
  exit 1
fi

tmp="$(mktemp -d /tmp/vallum-execgate-selftest.XXXXXX)"
state_dir=""
daemon_pid=""
log="${tmp}/kub0d.log"

cleanup() {
  local rc=$?
  trap - EXIT
  set +e
  if [[ -n ${daemon_pid} ]] && kill -0 "$daemon_pid" 2>/dev/null; then
    kill -TERM "$daemon_pid" 2>/dev/null
    local i=0
    while [[ $i -lt 50 ]]; do
      if ! kill -0 "$daemon_pid" 2>/dev/null; then
        break
      fi
      i=$((i + 1))
      sleep 0.1
    done
    if kill -0 "$daemon_pid" 2>/dev/null; then
      kill -KILL "$daemon_pid" 2>/dev/null
    fi
    wait "$daemon_pid" 2>/dev/null
  fi
  if [[ $tmp == /tmp/vallum-execgate-selftest.* && -d $tmp ]]; then
    rm -rf -- "$tmp"
  fi
  if [[ -n $state_dir && $state_dir == /var/lib/kub0-execgate-selftest.* && -d $state_dir ]]; then
    rm -rf -- "$state_dir"
  fi
  exit "$rc"
}
trap cleanup EXIT

state_dir="$(mktemp -d /var/lib/kub0-execgate-selftest.XXXXXX)"

mount_opts=""
if command -v findmnt >/dev/null 2>&1; then
  mount_opts="$(findmnt -n -o OPTIONS -T "$tmp" 2>/dev/null || true)"
fi
case ",${mount_opts}," in
  *,noexec,*)
    echo "refusing: ${tmp} is on a noexec mount, so an exec failure would not be the gate." >&2
    exit 2
    ;;
esac

if [[ -f /var/lib/kub0/account.json ]]; then
  echo "note: /var/lib/kub0/account.json is present, so this --system process may heartbeat. Sample keys still come only from KUB0_EXEC_GATE_DENY_FILE. A reachable kub0 server can also sync org network policy." >&2
fi

nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
if [[ ${#nonce} -lt 8 ]]; then
  echo "FAIL could not read a nonce from /dev/urandom" >&2
  echo "SELFTEST FAIL"
  exit 1
fi

S="${tmp}/S"
S2="${tmp}/S2"
deny="${tmp}/deny"
printf '#!/bin/sh\necho EXECGATE_SENTINEL_RAN %s\n' "$nonce" >"$S"
chmod +x "$S"
cp "$S" "$S2"
# One trailing byte. A newline keeps the shell parsing; the digest changes.
printf '\n' >>"$S2"
chmod +x "$S2"

hash="$(sha256sum "$S" | awk '{print $1}')"
if [[ ! $hash =~ ^[0-9a-f]{64}$ ]]; then
  echo "FAIL sha256 of S is not 64 hex: ${hash}" >&2
  echo "SELFTEST FAIL"
  exit 1
fi
printf '# comment exercised by the deny-file parser\n%s\n' "$hash" >"$deny"

export KUB0_EXEC_GATE=1
export KUB0_EXEC_GATE_DENY_FILE="$deny"
# Private trust store and state file: the self-test must not read the real
# machine's trusted digests or overwrite the state the panel mirrors.
export KUB0_EXEC_GATE_DIR="${state_dir}/execgate"

# TMPDIR=/tmp keeps kub0d's temporary-state check from treating the private
# state dir as disposable if the operator's TMPDIR is unusual.
TMPDIR=/tmp "$bin" --system --socket "${tmp}/vallum.sock" --state-dir "$state_dir" >"$log" 2>&1 &
daemon_pid=$!

fail_startup() {
  echo "FAIL $1"
  echo "---- last 40 daemon log lines ----"
  if [[ -f $log ]]; then
    tail -n 40 "$log" || true
  else
    echo "(no daemon log)"
  fi
  echo "SELFTEST FAIL"
  exit 1
}

ready=0
for _ in {1..30}; do
  if [[ -f $log ]] && grep -F -q 'exec gate NOT loaded' "$log"; then
    fail_startup "exec gate NOT loaded"
  fi
  if [[ -f $log ]] && grep -F -q 'exec gate ON:' "$log"; then
    ready=1
    break
  fi
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    fail_startup "kub0d exited before the first exec gate ON line"
  fi
  sleep 1
done
if [[ $ready -ne 1 ]]; then
  fail_startup "timed out after 30s waiting for the first exec gate ON line"
fi

# The ON line is logged before the command socket bind. Give bind a moment
# so a startup failure is a log tail, not a fail-open exec of S.
for _ in {1..25}; do
  if ! kill -0 "$daemon_pid" 2>/dev/null; then
    fail_startup "kub0d exited after exec gate ON (startup failed)"
  fi
  if grep -F -q 'kub0d: source=' "$log"; then
    break
  fi
  sleep 0.2
done
if ! kill -0 "$daemon_pid" 2>/dev/null; then
  fail_startup "kub0d exited after exec gate ON (startup failed)"
fi

RUN_RC=0
RUN_OUT=""

# bash itself execs the sample, so a refusal is that shell's EACCES/EPERM
# text. timeout is only the backstop: the module allows an unanswered event
# after 3s, and a gate that never answers must not hang the operator.
run_sample() {
  local target="$1"
  local quoted
  quoted="$(printf '%q' "$target")"
  RUN_RC=0
  RUN_OUT="$(timeout --signal=KILL 15 bash -c "exec ${quoted}" 2>&1)" || RUN_RC=$?
}

refused() {
  [[ $RUN_RC -ne 0 && $RUN_RC -ne 124 ]] || return 1
  [[ $RUN_OUT == *"Permission denied"* || $RUN_OUT == *"Operation not permitted"* ]]
}

ran_sentinel() {
  [[ $RUN_RC -eq 0 && $RUN_OUT == "EXECGATE_SENTINEL_RAN ${nonce}" ]]
}

expect_refused() {
  local label=$1 target=$2
  run_sample "$target"
  if refused; then
    echo "PASS ${label} refused rc=${RUN_RC} stderr=${RUN_OUT}"
    return 0
  fi
  echo "FAIL ${label} expected EACCES/EPERM, rc=${RUN_RC} observed=${RUN_OUT}"
  return 1
}

expect_sentinel() {
  local label=$1 target=$2
  run_sample "$target"
  if ran_sentinel; then
    echo "PASS ${label} sentinel rc=${RUN_RC} stdout=${RUN_OUT}"
    return 0
  fi
  echo "FAIL ${label} expected EXECGATE_SENTINEL_RAN ${nonce}, rc=${RUN_RC} observed=${RUN_OUT}"
  return 1
}

failed=0
expect_refused "a" "$S" || failed=1
expect_sentinel "b" "$S2" || failed=1
cp "$S" "${tmp}/copy"
chmod +x "${tmp}/copy"
expect_refused "c" "${tmp}/copy" || failed=1

if [[ -z ${daemon_pid} ]] || ! kill -0 "$daemon_pid" 2>/dev/null; then
  echo "FAIL d daemon not running before SIGTERM"
  failed=1
else
  kill -TERM "$daemon_pid" 2>/dev/null || true
  i=0
  exited=0
  while [[ $i -lt 50 ]]; do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      wait "$daemon_pid" 2>/dev/null || true
      daemon_pid=""
      exited=1
      break
    fi
    i=$((i + 1))
    sleep 0.1
  done
  if [[ $exited -ne 1 ]]; then
    echo "FAIL d daemon still alive 5s after SIGTERM"
    failed=1
  else
    expect_sentinel "d" "$S" || failed=1
  fi
fi

counters="$(grep -F 'exec gate: on=' "$log" | tail -n 1 || true)"
if [[ -n $counters ]]; then
  printf '%s\n' "$counters"
else
  echo "FAIL no exec gate: counters line in the daemon log"
  failed=1
fi

# Final leg. Legs a-d are unchanged, and d has already signaled a daemon that
# reached it. This leg signals a daemon that is still up, requires that exit
# within 5s, and requires the stop line shutdown logs once.
if [[ -n ${daemon_pid} ]] && kill -0 "$daemon_pid" 2>/dev/null; then
  kill -TERM "$daemon_pid" 2>/dev/null || true
  i=0
  exited=0
  while [[ $i -lt 50 ]]; do
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
      wait "$daemon_pid" 2>/dev/null || true
      daemon_pid=""
      exited=1
      break
    fi
    i=$((i + 1))
    sleep 0.1
  done
  if [[ $exited -ne 1 ]]; then
    echo "FAIL e daemon still alive 5s after SIGTERM"
    failed=1
  fi
fi
if [[ -f $log ]] && grep -F -q 'exec gate: stopped' "$log"; then
  echo "PASS e exec gate stopped"
else
  echo "FAIL e log missing exec gate: stopped"
  failed=1
fi

if [[ $failed -eq 0 ]]; then
  echo "SELFTEST PASS"
  exit 0
fi
echo "SELFTEST FAIL"
exit 1
