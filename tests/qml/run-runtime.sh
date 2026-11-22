#!/usr/bin/env bash
# Private runtime checks. Never touches the live desktop.
# Where UNIX bind and wl_display creation are refused (a Landlock sandbox, a
# container without user namespaces), the namespace setup fails the runner
# before QML: that is a run that did not happen, not a pass. The Service is
# never launched outside the private namespace.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
QML="$ROOT/tests/qml"
if [[ "${1:-}" != --isolated ]]; then
  WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/vr-XXXXXX")"
  WORKDIR="$(realpath "$WORKDIR")"
  # The host and the tree under test are read-only; only this private directory is writable.
  # Private /tmp and /run hide standard desktop sockets; network is isolated.
  printf '%s\n' "$WORKDIR" >"$WORKDIR/fence"
  rc=0
  # Every helper path the panel probes that exists on this host is masked by
  # the refusing fake: the renamed one, and (one release) the 0.4.x one the
  # panel falls back to. Neither real helper can run in here.
  masks=()
  for h in /usr/lib/kub0/kub0-block /usr/lib/vallum/vallum-block; do
    # After an upgrade the 0.4.x path is a symlink to the renamed helper. bwrap
    # cannot bind onto a symlink, and masking the target covers both names; the
    # helper proof below still executes each path and refuses on a miss.
    [[ -e "$h" && ! -L "$h" ]] && masks+=(--ro-bind "$QML/fake-plugin/bin/pkexec" "$h")
  done
  [[ ${#masks[@]} -gt 0 ]] || { echo "no installed helper path to mask (/usr/lib/kub0/kub0-block or the 0.4.x one)"; exit 1; }
  bwrap --die-with-parent --new-session --unshare-all --ro-bind / / \
    --tmpfs /tmp --tmpfs /run --bind "$WORKDIR" "$WORKDIR" --ro-bind "$WORKDIR/fence" /tmp/vallum-fence --proc /proc --dev /dev \
    "${masks[@]}" \
    --ro-bind "$QML/fake-plugin/bin/pkexec" /usr/bin/pkexec \
    --clearenv --setenv PATH /usr/bin:/bin --setenv VALLUM_SHOTS "${VALLUM_SHOTS:-}" \
    --setenv VALLUM_RUNTIME_WORKDIR "$WORKDIR" /bin/bash "$0" --isolated >"$WORKDIR/runner.log" 2>&1 || rc=$?
  cat "$WORKDIR/runner.log"
  python3 - "$WORKDIR" "$rc" <<'FENCE_RESULT'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
log = (root / 'runner.log').read_text()
result = {'exitCode': int(sys.argv[2]), 'namespaceStarted': 'NAMESPACE_READY' in log, 'log': str(root / 'runner.log')}
if not result['namespaceStarted']:
    result['fenceFailure'] = log.strip()
(root / 'runtime-result.json').write_text(json.dumps(result, indent=2) + '\n')
print('RUNTIME_RESULT', json.dumps(result))
FENCE_RESULT
  exit "$rc"
fi
WORKDIR="${VALLUM_RUNTIME_WORKDIR:?private runtime directory required}"
mountpoint -q /tmp/vallum-fence && [[ "$(cat /tmp/vallum-fence)" == "$WORKDIR" ]] || { echo "private namespace fence missing"; exit 1; }
echo NAMESPACE_READY
python3 - "$WORKDIR" "$QML/fake-plugin/bin/pkexec" <<'HELPER_PROOF'
import hashlib,json,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1])
fixture=pathlib.Path(sys.argv[2]).read_bytes()
present=[p for p in ('/usr/lib/kub0/kub0-block','/usr/lib/vallum/vallum-block') if pathlib.Path(p).exists()]
proofs=[]
for path in present:
    canonical=pathlib.Path(path).read_bytes()
    if canonical != fixture:
        (root/'helper-mask.json').write_text(json.dumps({'ok':False,'sameFixtureBytes':False,'path':path})+'\n')
        raise SystemExit('canonical helper mask missing at '+path+'; refusing to execute')
    rc=subprocess.run([path,'status'],env={'PATH':'/usr/bin:/bin'},capture_output=True,text=True)
    proofs.append({'path':path,'sameFixtureBytes':True,'canonicalHash':hashlib.sha256(canonical).hexdigest(),'exitCode':rc.returncode,'stderr':rc.stderr})
proof={'helpers':proofs,'ok':bool(proofs) and all(p['exitCode']==99 for p in proofs)}
(root/'helper-mask.json').write_text(json.dumps(proof,indent=2)+'\n')
print('HELPER_MASK',json.dumps(proof))
if not proof['ok']: raise SystemExit(1)
HELPER_PROOF
run_qml() {
  local key
  local -a clean=()
  for key in HOME PATH TZ XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME XDG_RUNTIME_DIR XDG_STATE_HOME QT_QPA_PLATFORM QT_QPA_PLATFORMTHEME QT_QUICK_BACKEND QML2_IMPORT_PATH VALLUM_CANDIDATE_DIR VALLUM_SCENARIO VALLUM_BLOCK_READY VALLUM_FAKE_PLUGIN VALLUM_FIXTURE_ROOT VALLUM_FIXTURE_MODE VALLUM_LISTENER_DELAY VALLUM_ACCEPT_RECORD VALLUM_CHECK VALLUM_VIEW VALLUM_KUB0 VALLUM_QUERY VALLUM_UX VALLUM_SHOT VALLUM_SYSTEM_FIXTURE VALLUM_SYSTEM_MISSING; do
    [[ -v "$key" ]] && clean+=("$key=${!key}")
  done
  env -i "${clean[@]}" quickshell "$@"
}
export -f run_qml
export HOME="$WORKDIR/home"
export XDG_CONFIG_HOME="$WORKDIR/config"
export XDG_DATA_HOME="$WORKDIR/data"
export XDG_CACHE_HOME="$WORKDIR/cache"
export XDG_RUNTIME_DIR="$WORKDIR/runtime"
export XDG_STATE_HOME="$WORKDIR/state"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_CACHE_HOME" "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME"
export QT_QPA_PLATFORM=offscreen
export QT_QPA_PLATFORMTHEME=generic
export QT_QUICK_BACKEND=software
export TZ=America/Bogota
unset HYPRLAND_INSTANCE_SIGNATURE WAYLAND_DISPLAY DISPLAY
export VALLUM_CANDIDATE_DIR="$ROOT"
export VALLUM_FAKE_PLUGIN="$ROOT/tests/qml/fake-plugin"
export PATH="$VALLUM_FAKE_PLUGIN/bin:/usr/bin:/bin"
export QML2_IMPORT_PATH="/usr/share/omarchy/shell"
unset DBUS_SESSION_BUS_ADDRESS DBUS_SYSTEM_BUS_ADDRESS SSH_AUTH_SOCK SSH_AGENT_PID
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE AWS_DEFAULT_PROFILE
unset GITHUB_TOKEN GH_TOKEN GIT_ASKPASS GIT_CONFIG_GLOBAL KUBECONFIG GOOGLE_APPLICATION_CREDENTIALS
# A shadow Ui/: every file links to the shell's, except KeyboardPanel, which
# is a PanelWindow and cannot load without a layer-shell backend.
mkdir -p "$WORKDIR/Ui"
for f in /usr/share/omarchy/shell/Ui/*; do ln -sfn "$f" "$WORKDIR/Ui/$(basename "$f")"; done
ln -sfn "$QML/stubs/KeyboardPanel.qml" "$WORKDIR/Ui/KeyboardPanel.qml"
ln -sfn /usr/share/omarchy/shell/Commons "$WORKDIR/Commons"
cp "$QML/service-harness.qml" "$QML/panel-harness.qml" "$QML/Fixture.js" "$QML/endpoints-harness.qml" "$WORKDIR/"

# Screenshots only. VALLUM_SHOTS="view:textSize:density:width:height[:timeStyle:byteUnits[:scenario]] ..."
# renders the panel at each setting and leaves one PNG per entry in the workdir,
# then stops: nothing below runs and no check reads the pictures. For looking at
# a layout change, e.g.
#   VALLUM_SHOTS="apps:larger:compact:normal:normal settings:small:roomy:wide:tall" tests/qml/run-runtime.sh
# The scenario is a model in Fixture.js; "showcase" is the one preview.png is
# made from (tests/qml/make-preview.sh).
if [[ -n "${VALLUM_SHOTS:-}" ]]; then
  export VALLUM_FIXTURE_ROOT="$XDG_RUNTIME_DIR" VALLUM_KUB0=1 VALLUM_CHECK=ux-shots
  shots_rc=0
  for spec in $VALLUM_SHOTS; do
    IFS=: read -r shot_view shot_text shot_density shot_width shot_height shot_time shot_bytes shot_scenario <<<"$spec"
    export VALLUM_SCENARIO="${shot_scenario:-populated}"
    if [[ "$VALLUM_SCENARIO" == "showcase" ]]; then export VALLUM_BLOCK_READY=1; else unset VALLUM_BLOCK_READY; fi
    export VALLUM_VIEW="$shot_view" VALLUM_UX="$shot_text,$shot_density,$shot_width,$shot_height,$shot_time,$shot_bytes"
    export VALLUM_SHOT="$WORKDIR/shot-${spec//:/-}.png"
    timeout 15 bash -c 'run_qml "$@"' _ -p "$WORKDIR/panel-harness.qml" --no-color >"$WORKDIR/shot-${spec//:/-}.log" 2>&1 || true
    if grep -q 'HARNESS_SHOT true' "$WORKDIR/shot-${spec//:/-}.log"; then
      echo "SHOT $VALLUM_SHOT"
    else
      echo "SHOT_FAILED $spec"; tail -n 5 "$WORKDIR/shot-${spec//:/-}.log"; shots_rc=1
    fi
  done
  exit "$shots_rc"
fi

run_service_fixture() {
  local mode="$1" delay="$2" tag="$3"
  local runtime="$WORKDIR/$tag-runtime"
  mkdir -p "$runtime"
  export XDG_RUNTIME_DIR="$runtime"
  export VALLUM_FIXTURE_ROOT="$runtime"
  export VALLUM_FIXTURE_MODE="$mode" VALLUM_LISTENER_DELAY="$delay"
  export VALLUM_ACCEPT_RECORD="$WORKDIR/$tag-accepts.json"
  export VALLUM_CHECK=""
  echo "== service fixture $tag (offscreen) =="
  local before_hash="$(sha256sum "$XDG_CONFIG_HOME/vallum/ui.json" | cut -d' ' -f1)"
  local rc=0
  timeout 13 bash -c 'run_qml "$@"' _ -p "$QML/service-harness.qml" --no-color >"$WORKDIR/$tag.log" 2>&1 || rc=$?
  if python3 - "$WORKDIR/$tag.log" "$WORKDIR/$tag-accepts.json" "$tag" "$rc" "$XDG_CONFIG_HOME/vallum/ui.json" "$before_hash" <<'PYFIX'
import json,sys,os,time,hashlib
log=open(sys.argv[1]).read()
print(log[-3500:])
states=[]
for line in log.splitlines():
    if 'SERVICE_STATE ' in line:
        try: states.append(json.loads(line.split('SERVICE_STATE ',1)[1]))
        except Exception: pass
accepts={}
try: accepts=json.load(open(sys.argv[2]))
except Exception: pass
mode=sys.argv[3]
current_states=[s for s in states if s.get('monitoring')=='current' and s.get('current') and s.get('snapshot') and s.get('socket') and s.get('count',0)==1 and s.get('uniqueRow') and not s.get('fallback')]
connected=len(current_states)>=4 and any(s.get('monitoring')=='current' and s.get('current') and s.get('snapshot') and s.get('socket') and s.get('count',0)==1 and s.get('uniqueRow') and not s.get('fallback') for s in states)
maxgen=max([s.get('generation',0) for s in states] or [0])
maxretry=max([s.get('retries',0) for s in states] or [0])
prefs_bytes=open(sys.argv[5],'rb').read()
expected=json.loads(prefs_bytes)
expected.pop('version',None)
prefs_ok=any(s.get('prefsLoaded') and s.get('prefs',{})==expected for s in states)
after_hash=hashlib.sha256(prefs_bytes).hexdigest()

if mode in ('delayed', 'delayed-missing'): ok=connected and prefs_ok and accepts.get('accepts',0)>=1 and len(accepts.get('pids',[]))==1 and maxgen < 20 and maxretry < 12
elif mode=='missing': ok=prefs_ok and not any(s.get('current') or s.get('socket') or s.get('snapshot') for s in states) and accepts.get('accepts',0)==0 and len(accepts.get('pids',[]))==1 and 1 < maxgen < 12 and 0 < maxretry < 10
elif mode=='rebind': ok=connected and prefs_ok and accepts.get('accepts',0)>=2 and len(accepts.get('pids',[]))==1 and maxgen < 20 and maxretry < 12
else: ok=connected and prefs_ok and accepts.get('accepts',0)>=2 and len(accepts.get('pids',[]))>=2 and maxgen < 20 and maxretry < 12
if mode in ('delayed', 'delayed-missing'):
    ok = ok and maxretry > 0 and maxgen > 1 and states and not states[0].get('current')
if mode != 'missing':
    ok = ok and set(range(1, accepts.get('accepts', 0)+1)) <= set(accepts.get('panelOpens', []))
dead = True
for pid in accepts.get('pids', []):
    try:
        os.kill(pid, 0)
        dead = False
    except ProcessLookupError:
        pass
ok = ok and dead and accepts.get('overlapFailures', 0)==0 and not os.path.exists(os.path.join(os.environ['VALLUM_FIXTURE_ROOT'],'daemon-overlap')) and all(s.get('sameService') for s in states) and 'SERVICE_DESTROYED' in log
if mode in ('rebind', 'restart'):
    identities = {tuple(s.get('rowIds', [])) for s in current_states}
    groups = [[s for s in current_states if tuple(s.get('rowIds', [])) == identity] for identity in identities]
    ok = ok and len(groups) >= 2 and sum(len(g)>=2 for g in groups)>=2
    recovered = False
    for i, sample in enumerate(states):
        if sample in current_states:
            for j in range(i+1, len(states)):
                if states[j] in current_states and states[j].get('rowIds') != sample.get('rowIds') and any(not s.get('current') for s in states[i+1:j]):
                    recovered = True
    ok = ok and recovered
# A retired receiver must never restore an earlier accepted connection identity.
serials=[int(s['rowIds'][0].rsplit('-',1)[1]) for s in current_states if len(s.get('rowIds',[]))==1]
ok = ok and serials==sorted(serials)
errors=[line for line in log.splitlines() if any(t in line for t in ('ReferenceError:', 'TypeError:', 'SyntaxError:', 'Failed to load configuration', 'Cannot assign'))]
ok=bool(ok and states and not errors and int(sys.argv[4])==0 and sys.argv[6]==after_hash)
observation={'mode':mode,'states':len(states),'accepts':accepts,'currentSnapshotRow':connected,'seededPreferencesLoaded':prefs_ok,'maxGeneration':maxgen,'maxRetries':maxretry,'ok':ok,'childrenGone':dead,'samples':states,'errors':errors,'exitCode':int(sys.argv[4]),'prefsPath':sys.argv[5],'prefsBeforeHash':sys.argv[6],'prefsAfterHash':after_hash}
open(sys.argv[1]+'.json','w').write(json.dumps(observation,indent=2)+'\n')
print('FIXTURE_OBSERVATION',json.dumps(observation))
sys.exit(0 if ok and states and not any(token in log for token in ('ReferenceError:', 'TypeError:', 'SyntaxError:', 'Failed to load configuration', 'Cannot assign')) and int(sys.argv[4])==0 else 1)
PYFIX
  then return 0; else return $?; fi
}
# An absent designated root must refuse before binding any socket.
if env -u VALLUM_FIXTURE_ROOT "$VALLUM_FAKE_PLUGIN/bin/kub0d" --socket "$WORKDIR/no-root.sock" >"$WORKDIR/root-refusal.log" 2>&1; then
  echo "fixture accepted an unset root"; exit 1
fi
[[ ! -e "$WORKDIR/no-root.sock" ]] || exit 1
# Keep the user's seeded preference file untouched through all service cases.
# It is seeded where 0.4.6 and earlier kept it (~/.config/vallum), with nothing
# in ~/.config/kub0: the service has to load it from there, carry it to the
# new folder and leave the old file as it was.
mkdir -p "$XDG_CONFIG_HOME/vallum"
node - "$ROOT/js/Prefs.js" "$XDG_CONFIG_HOME/vallum/ui.json" <<'PREFSEED'
const fs = require('fs');
const prefs = require(process.argv[2]);
const value = {startupView:'history',lastView:'settings',sortKey:'connections',filterKey:'live',confirmBlocks:false,showWorldMap:false,captureEnabled:false};
const bytes = prefs.serialize(value);
if (prefs.changed(value, prefs.parse(bytes).prefs)) throw new Error('invalid preference seed');
fs.writeFileSync(process.argv[3], bytes);
PREFSEED
PREFS_HASH="$(sha256sum "$XDG_CONFIG_HOME/vallum/ui.json" | cut -d' ' -f1)"
if run_service_fixture refused-delayed 1.4 delayed; then delayed_ok=0; else delayed_ok=$?; fi
if run_service_fixture reconnect 1.4 delayed-missing; then missing_delayed_ok=0; else missing_delayed_ok=$?; fi
if run_service_fixture rebind 0.2 rebind; then rebind_ok=0; else rebind_ok=$?; fi
if run_service_fixture missing 0 missing; then missing_ok=0; else missing_ok=$?; fi
if run_service_fixture restart-once 0.2 restart; then restart_ok=0; else restart_ok=$?; fi
AFTER_HASH="$(sha256sum "$XDG_CONFIG_HOME/vallum/ui.json" | cut -d' ' -f1)"
[[ "$PREFS_HASH" == "$AFTER_HASH" ]] || { echo "seeded preferences changed"; exit 1; }
node - "$ROOT/js/Prefs.js" "$XDG_CONFIG_HOME/vallum/ui.json" "$XDG_CONFIG_HOME/kub0/ui.json" <<'PREFCARRIED'
const fs = require('fs');
const prefs = require(process.argv[2]);
if (!fs.existsSync(process.argv[4])) { console.log('settings were not carried to ~/.config/kub0/ui.json'); process.exit(1); }
const was = prefs.parse(fs.readFileSync(process.argv[3], 'utf8'));
const now = prefs.parse(fs.readFileSync(process.argv[4], 'utf8'));
if (was.error || now.error || prefs.changed(was.prefs, now.prefs)) { console.log('carried settings differ from the seeded ones'); process.exit(1); }
console.log('PREFS_CARRIED_TO_KUB0 true');
PREFCARRIED

echo "== service demo isolation (offscreen) =="
RUNTIME_SOCK2="$(mktemp -d "$WORKDIR/service-demo-XXXXXX")"
export XDG_RUNTIME_DIR="$RUNTIME_SOCK2"
export VALLUM_FIXTURE_ROOT="$RUNTIME_SOCK2"
export VALLUM_ACCEPT_RECORD="$WORKDIR/accepts-demo.json"
export VALLUM_CHECK=demo
export VALLUM_FIXTURE_MODE=demo-exit VALLUM_LISTENER_DELAY=0.2
set +e
demo_rc=0
timeout 15 bash -c 'run_qml "$@"' _ -p "$QML/service-harness.qml" --no-color >"$WORKDIR/service-demo.log" 2>&1 || demo_rc=$?
python3 - "$WORKDIR/service-demo.log" "$VALLUM_ACCEPT_RECORD" "$demo_rc" <<'PY'
import json,sys
log=open(sys.argv[1]).read()
print(log[-4000:])
demo={}
for tag in ('DEMO_ENTER','DEMO_EXIT','DEMO_PAUSED'):
    for line in log.splitlines():
        if tag+' ' in line:
            demo[tag]=json.loads(line.split(tag+' ',1)[1])
print('DEMO',json.dumps(demo))
accepts=json.load(open(sys.argv[2]))
ok=all(demo.get(t,{}).get('role')=='unknown' and demo.get(t,{}).get('enforcing') is False for t in ('DEMO_ENTER','DEMO_PAUSED','DEMO_EXIT')) and demo.get('DEMO_PAUSED',{}).get('daemonRunning') is False and 'DEMO_FRESH_HELLO user' in log and 'DEMO_SEEDED {"role":"system","enforcing":true}' in log and len(demo)==3 and all(demo[t].get('count')==0 and demo[t].get('blocked') for t in ('DEMO_ENTER','DEMO_EXIT')) and demo['DEMO_PAUSED'].get('generationStable') and demo['DEMO_PAUSED'].get('retriesStable') and not demo['DEMO_PAUSED'].get('current') and 'DEMO_FIXTURE 1' in log and 'SERVICE_DESTROYED' in log and not any(x in log for x in ('ReferenceError:', 'TypeError:', 'SyntaxError:'))
import os
for pid in accepts.get('pids',[]):
    try:
        os.kill(pid,0)
        ok=False
    except ProcessLookupError:
        pass
ok=bool(ok and int(sys.argv[3])==0 and accepts.get('overlapFailures',0)==0 and not os.path.exists(os.path.join(os.environ['VALLUM_FIXTURE_ROOT'],'daemon-overlap')))
open(sys.argv[1]+'.json','w').write(json.dumps({'demo':demo,'accepts':accepts,'ok':ok},indent=2)+'\n')
sys.exit(0 if ok else 1)
PY
demo_ok=$?
set -e

echo "== service changes over the system socket (offscreen) =="
# A stand-in system daemon on a private path: greets as a system daemon that
# answers requests, broadcasts a row the request connection must skip, and
# answers each request with a verified cgroup block. It records what it got.
#
# One daemon (#61): once the service finds that daemon usable it reads its
# stream as well, on a second connection, and stops its own kub0d. That row is
# then one of the panel's (the whole host), and the service's watch and name
# changes arrive here as requests, not as the lines its own daemon takes.
RUNTIME_SYS="$(mktemp -d "$WORKDIR/service-system-XXXXXX")"
export XDG_RUNTIME_DIR="$RUNTIME_SYS"
export VALLUM_FIXTURE_ROOT="$RUNTIME_SYS"
export VALLUM_ACCEPT_RECORD="$WORKDIR/accepts-system.json"
export VALLUM_CHECK=system
export VALLUM_FIXTURE_MODE=reconnect VALLUM_LISTENER_DELAY=0.2
export VALLUM_SYSTEM_FIXTURE="$RUNTIME_SYS/system.sock"
export VALLUM_SYSTEM_MISSING="$RUNTIME_SYS/absent.sock"
python3 - "$VALLUM_SYSTEM_FIXTURE" "$WORKDIR/system-requests.json" <<'SYSTEM_FIXTURE' &
import json, os, socket, sys, threading
path, record = sys.argv[1], sys.argv[2]
got = []
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(4)
srv.settimeout(14)
# The policy the daemon holds: in its `policies` reply and, as a real system
# daemon sends it, in the fleet frame of its stream.
POLICY = {"netpolicyEnforcement": {"state": "enforcing", "enforcing": True, "rules": ["r"], "appliedTs": 1},
          "netpolicies": [{"id": "p", "name": "Fixture", "mode": "block", "rules": [{"id": "r", "kind": "ip", "label": "r",
            "action": "block", "effectiveAction": "block", "enforced": True, "canSnooze": True, "snoozedUntil": 4102444800000}]}]}
def serve(conn):
    conn.sendall(b'{"type":"hello","version":"fixture","pid":1,"coverage":"tcp","rdns":false,"mode":"system","requests":true,"as_uid":true,"account":{"connected":true,"github_username":"fixture-user","node_name":"fixture-node","last_heartbeat_ok":true}}\n')
    conn.sendall((json.dumps({"type": "fleet", "connected": True, "selfState": "enforcing", "orgEndpoints": 1, "nodeLimit": 5,
                              "sharingDestinations": True,
                              "netpolicyRefreshOk": True, "netpolicyEnforcement": POLICY["netpolicyEnforcement"],
                              "netpolicies": POLICY["netpolicies"]}) + "\n").encode())
    conn.sendall(b'{"type":"snapshot","ts":1,"connections":[{"id":"another-user","proto":"tcp","inode":77,"app":{"id":"whole-host-app","name":"whole-host-app","icon":"","desktop":"","pid":4321,"system":false},"local":{"ip":"192.0.2.254","port":40001},"remote":{"ip":"192.0.2.9","port":443},"state":"ESTABLISHED","country":"","lat":0,"lon":0,"unresolved":false,"newNetwork":false,"networkKey":"192.0.2.0/24","hostname":""}]}\n')
    buf = b""
    while True:
        data = conn.recv(4096)
        if not data:
            return
        buf += data
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            req = json.loads(line)
            got.append(req)
            open(record, "w").write(json.dumps(got))
            if "req" not in req:
                continue  # a line on the event connection (panel-open): no reply
            result = {"ok": True, "verified": True, "mechanism": "cgroup", "app": req.get("app", "")}
            if req.get("cmd") == "status":
                result = {"account": {"connected": True, "githubUsername": "fixture-user", "nodeName": "fixture-node", "lastHeartbeatOk": True},
                          "fleet": {"selfState": "enforcing", "orgEndpoints": 1, "nodeLimit": 5}, "peer": {"uid": os.getuid()}}
            elif req.get("cmd") == "policies":
                result = dict(POLICY, connected=True, netpolicyRefreshOk=True)
            elif req.get("cmd") == "rules":
                result = {"connected": True, "denylist": []}
            reply = {"type": "reply", "req": req["req"], "ok": True, "partial": False, "result": result, "error": ""}
            conn.sendall((json.dumps(reply) + "\n").encode())
try:
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()
except socket.timeout:
    pass
SYSTEM_FIXTURE
system_fixture_pid=$!
system_ok=0
for _ in $(seq 50); do [[ -S "$VALLUM_SYSTEM_FIXTURE" ]] && break; sleep 0.1; done
timeout 15 bash -c 'run_qml "$@"' _ -p "$QML/service-harness.qml" --no-color >"$WORKDIR/service-system.log" 2>&1 || system_ok=$?
kill "$system_fixture_pid" 2>/dev/null || true
wait "$system_fixture_pid" 2>/dev/null || true
python3 - "$WORKDIR/service-system.log" "$WORKDIR/system-requests.json" <<'SYSTEM_RESULT' || system_ok=1
import json, pathlib, sys
log = pathlib.Path(sys.argv[1]).read_text()
def frame(tag):
    for line in log.splitlines():
        if tag + ' ' in line:
            return json.loads(line.split(tag + ' ', 1)[1])
    return None
missing, submitted, block, view = frame('SYSTEM_MISSING'), frame('SYSTEM_SUBMITTED'), frame('SYSTEM_BLOCK'), frame('SYSTEM_VIEW')
before, stream, writes = frame('STREAM_BEFORE'), frame('STREAM_READ'), frame('STREAM_WRITES')
try:
    everything = json.loads(pathlib.Path(sys.argv[2]).read_text())
except Exception:
    everything = []
requests = [r for r in everything if 'req' in r]
lines = [r for r in everything if 'req' not in r]
print('SYSTEM', json.dumps({'missing': missing, 'submitted': submitted, 'block': block, 'view': view, 'requests': requests,
                            'before': before, 'stream': stream, 'writes': writes, 'lines': lines}))
ok = (missing is not None and missing['reachable'] is False and missing['ms'] < 4000
      and submitted is not None and submitted['queued'] is True
      and block is not None and block['blocked'] is True and block['mechanism'] == 'cgroup'
      and block['busy'] is False and block['error'] == ''
      and len(requests) >= 1 and requests[0].get('cmd') == 'block' and requests[0].get('app') == 'system-app'
      and requests[0].get('pids') == ['1234'] and str(requests[0].get('req', '')).startswith('panel-')
      and sorted(r.get('cmd') for r in requests[1:4]) == ['policies', 'rules', 'status']
      and view is not None and view['user'] == 'fixture-user' and view['node'] == 'fixture-node'
      and view['connected'] is True and view['policies'] == 1 and view['snoozedUntil'] == 4102444800000)
print('SYSTEM_CHANGES_OVER_THE_SOCKET', ok)
# The panel reads that daemon: before it was found the service ran its own
# kub0d; after, the stream is the system daemon's, the row it broadcast is in
# the model, no kub0d of the panel's own runs, and the watch and the name went
# out as requests. The only lines without a `req` are the panel's open/close.
watch = [r for r in requests if r.get('cmd') == 'watch-set']
tag = [r for r in requests if r.get('cmd') == 'tag']
stream_ok = (before is not None and before['source'] == 'user' and before['own'] is True
             and stream is not None and stream['source'] == 'system' and stream['own'] is False
             and stream['row'] is True and stream['mode'] == 'system' and stream['status'] == 'connected'
             # The account card above came from that stream (its hello and fleet
             # frame), not from the read laid over it; the read told the panel
             # which uid it is.
             and stream['uid'] >= 0
             and writes is not None and writes['watchError'] == '' and writes['tagNotice'] == ''
             and len(watch) == 1 and watch[0].get('kind') == 'asn' and watch[0].get('value') == '64500'
             and len(tag) == 1 and tag[0].get('networkKey') == '203.0.113.0/24' and tag[0].get('label') == 'Fixture net'
             # Destination sharing is that daemon's setting: the switch shows what
             # its fleet frame says, and turning it off is a request to it.
             and stream['sharing'] is True and writes['sharingBefore'] is False
             and len([r for r in requests if r.get('cmd') == 'share-off']) == 1
             and all(l.get('type') in ('panel-open', 'panel-close') for l in lines)
             and any(l.get('type') == 'panel-open' for l in lines))
print('PANEL_READS_THE_SYSTEM_DAEMON', stream_ok)
sys.exit(0 if ok and stream_ok else 1)
SYSTEM_RESULT

echo "== private tenant inventory view (offscreen) =="
endpoint_ok=0
timeout --kill-after=2 12 bash -c 'run_qml "$@"' _ -p "$WORKDIR/endpoints-harness.qml" --no-color >"$WORKDIR/endpoints.log" 2>&1 || endpoint_ok=$?
cat "$WORKDIR/endpoints.log"
python3 - "$WORKDIR/endpoints.log" "$endpoint_ok" <<'ENDPOINT_RESULT' || endpoint_ok=1
import json, pathlib, sys
log = pathlib.Path(sys.argv[1]).read_text()
frames = [line.split('ENDPOINT_NATIVE_RESULT ', 1)[1]
          for line in log.splitlines() if 'ENDPOINT_NATIVE_RESULT ' in line]
result = None
if len(frames) == 1:
    try:
        result = json.loads(frames[0])
    except ValueError:
        pass
errors = any(token in log for token in (
    'ReferenceError:', 'TypeError:', 'SyntaxError:', 'Failed to load configuration',
    'Cannot assign', 'is not a type', 'Binding loop detected'))
ok = (int(sys.argv[2]) == 0 and len(frames) == 1
      and isinstance(result, dict) and result.get('ok') is True
      and result.get('checks') == 10 and not errors)
print('ENDPOINT_RESULT_VALID', ok)
sys.exit(0 if ok else 1)
ENDPOINT_RESULT

echo "== actual panel policy evidence (offscreen) =="
export VALLUM_VIEW=settings VALLUM_KUB0=1 VALLUM_CHECK=policy-status
policy_ok=0
timeout 12 bash -c 'run_qml "$@"' _ -p "$WORKDIR/panel-harness.qml" --no-color >"$WORKDIR/panel-policy.log" 2>&1 || policy_ok=$?
cat "$WORKDIR/panel-policy.log"
rg -q 'POLICY_NATIVE_RESULT.*"ok":true' "$WORKDIR/panel-policy.log" || policy_ok=1

echo "== panel protection sections (offscreen) =="
export VALLUM_VIEW=settings
export VALLUM_KUB0=1
export VALLUM_CHECK=protection
set +e
timeout 12 bash -c 'run_qml "$@"' _ -p "$WORKDIR/panel-harness.qml" --no-color >"$WORKDIR/panel-protection.log" 2>&1
prot_rc=$?
python3 - "$WORKDIR/panel-protection.log" <<'PY'
import sys
log=open(sys.argv[1]).read()
print(log[-4000:])
need=["kub0 endpoint:","Per-app helper","Fleet policy"]
ok=all(n in log for n in need)
print("PROTECTION_SECTIONS", ok)
sys.exit(0 if ok else 1)
PY
prot_ok=$?
[[ $prot_rc -eq 0 ]] || prot_ok=1
set -e

echo "== panel search filters while typing (offscreen) =="
export VALLUM_VIEW=apps
export VALLUM_KUB0=0
export VALLUM_CHECK=search-while-typing
export VALLUM_QUERY=Firefox
set +e
timeout 12 bash -c 'run_qml "$@"' _ -p "$WORKDIR/panel-harness.qml" --no-color >"$WORKDIR/panel-search.log" 2>&1
search_rc=$?
python3 - "$WORKDIR/panel-search.log" <<'PY'
import json,sys
log=open(sys.argv[1]).read()
got=None
for line in log.splitlines():
    if 'HARNESS_SEARCH ' in line:
        got=json.loads(line.split('HARNESS_SEARCH ',1)[1])
print('SEARCH',json.dumps(got))
# The field is still focused, the query matches at least one app, and the
# rows on screen are exactly the matches: not the unfiltered list.
ok=bool(got) and got['searchOpen'] and len(got['filtered'])>=1 and got['rendered']==got['filtered']
print('SEARCH_FILTERS_WHILE_TYPING', ok)
sys.exit(0 if ok else 1)
PY
search_ok=$?
[[ $search_rc -eq 0 ]] || search_ok=1
set -e

echo "== settings: scroll speed and momentum reach the wheel handlers (offscreen) =="
export VALLUM_VIEW=settings
export VALLUM_KUB0=0
export VALLUM_CHECK=scroll-settings
set +e
timeout 12 bash -c 'run_qml "$@"' _ -p "$WORKDIR/panel-harness.qml" --no-color >"$WORKDIR/panel-scroll.log" 2>&1
python3 - "$WORKDIR/panel-scroll.log" <<'PY'
import json,sys
log=open(sys.argv[1]).read()
got=None
for line in log.splitlines():
    if 'HARNESS_SCROLL_SETTINGS ' in line:
        got=json.loads(line.split('HARNESS_SCROLL_SETTINGS ',1)[1])
print('SCROLL_SETTINGS',json.dumps(got))
b=(got or {}).get('before') or {}
a=(got or {}).get('after') or {}
# Both controls are on the page showing the defaults; one pick and one flip
# later the store holds the new values and the panel is handing them on.
ok=(bool(got) and b.get('shown') is True
    and b.get('choices')==['slow','normal','fast','fastest']
    and b.get('selected')=='normal' and b.get('speed')=='normal'
    and b.get('momentum') is True and b.get('checked') is True
    and a.get('selected')=='fastest' and a.get('speed')=='fastest'
    and a.get('momentum') is False and a.get('checked') is False
    and a.get('saved')=={'scrollSpeed':'fastest','scrollMomentum':False})
print('SCROLL_SETTINGS_REACH_THE_HANDLERS', ok)
sys.exit(0 if ok else 1)
PY
scroll_ok=$?
set -e

echo "== settings: text size, spacing, panel size, time and units reach the panel (offscreen) =="
export VALLUM_VIEW=settings
export VALLUM_KUB0=0
export VALLUM_CHECK=ux-settings
set +e
timeout 12 bash -c 'run_qml "$@"' _ -p "$WORKDIR/panel-harness.qml" --no-color >"$WORKDIR/panel-ux.log" 2>&1
python3 - "$WORKDIR/panel-ux.log" <<'PY'
import json,sys
log=open(sys.argv[1]).read()
got=None
for line in log.splitlines():
    if 'HARNESS_UX_SETTINGS ' in line:
        got=json.loads(line.split('HARNESS_UX_SETTINGS ',1)[1])
print('UX_SETTINGS',json.dumps(got))
b=(got or {}).get('before') or {}
a=(got or {}).get('after') or {}
normal={'textSize':'normal','density':'normal','panelWidth':'normal','panelHeight':'normal','timeStyle':'mixed','byteUnits':'binary'}
picked={'textSize':'larger','density':'compact','panelWidth':'wide','panelHeight':'tall','timeStyle':'relative','byteUnits':'decimal'}
bu=b.get('ux') or {}
au=a.get('ux') or {}
# All six choices are on the page showing the defaults, and at the defaults
# the panel hands js/ no formatter at all. One pick each later the store holds
# them, the text the panel lays out with is 1.3 times the kit's, the gaps are
# 0.6 times, the panel asks for the larger size, and a size and a time print
# in the chosen units and style.
ok=(bool(got) and b.get('shown') is True and b.get('selected')==normal
    and b.get('choices')=={'textSize':['small','normal','large','larger'],'density':['compact','normal','roomy'],
                           'panelWidth':['normal','wide','widest'],'panelHeight':['normal','tall','full'],
                           'timeStyle':['mixed','relative','clock'],'byteUnits':['binary','decimal']}
    and b.get('prints')=={'bytes':None,'time':None}
    and a.get('prints')=={'bytes':'1.5 MB','time':'2m ago'}
    and bu.get('text')==1 and bu.get('gap')==1 and b.get('size')==[560,520]
    and a.get('selected')==picked and a.get('saved')==picked
    and au.get('text')==1.3 and au.get('gap')==0.6
    and au.get('body')==round(bu.get('body',0)*1.3) and au.get('caption')==round(bu.get('caption',0)*1.3)
    and a.get('size')==[720,760])
print('UX_SETTINGS_REACH_THE_LAYOUT', ok)
sys.exit(0 if ok else 1)
PY
ux_ok=$?
set -e

# The pair to the check above: a query change now bypasses the engagement
# hold, so prove the hold still holds for what it exists for. An app that
# disappears in a background sample while the list is engaged keeps its row
# until the hold releases. (The harness's selection-scroll check cannot show
# this: selection is kept by id either way, and offscreen the list is tall
# enough that its contentY clamps to 0 whatever the hold does.)
echo "== panel holds a background change while engaged (offscreen) =="
export VALLUM_CHECK=hold-defers
unset VALLUM_QUERY
set +e
timeout 12 bash -c 'run_qml "$@"' _ -p "$WORKDIR/panel-harness.qml" --no-color >"$WORKDIR/panel-hold.log" 2>&1
hold_rc=$?
python3 - "$WORKDIR/panel-hold.log" <<'PY'
import json,sys
log=open(sys.argv[1]).read()
held=released=None
for line in log.splitlines():
    if 'HARNESS_HOLD_HELD ' in line:
        held=json.loads(line.split('HARNESS_HOLD_HELD ',1)[1])
    if 'HARNESS_HOLD_RELEASED ' in line:
        released=json.loads(line.split('HARNESS_HOLD_RELEASED ',1)[1])
print('HOLD',json.dumps(held),json.dumps(released))
ok=(bool(held) and bool(released)
    and 'fixture-3' in held['before']
    and held['during']==held['before'] and held['pending']
    and released['after']==released['want'] and 'fixture-3' not in released['after']
    and not released['pending'])
print('HOLD_DEFERS_THEN_RECONCILES', ok)
sys.exit(0 if ok else 1)
PY
hold_ok=$?
[[ $hold_rc -eq 0 ]] || hold_ok=1
set -e

[[ "$PREFS_HASH" == "$(sha256sum "$XDG_CONFIG_HOME/vallum/ui.json" | cut -d' ' -f1)" ]] || { echo "seeded preferences changed"; exit 1; }
qml_errors=0
python3 - "$WORKDIR" <<'QML_ERRORS' || qml_errors=$?
import pathlib, sys
root = pathlib.Path(sys.argv[1])
errors = []
for path in root.glob('*.log'):
    text = path.read_text()
    if not text.strip():
        errors.append(str(path) + ': empty log')
    for line in text.splitlines():
        if any(token in line for token in ('ReferenceError:', 'TypeError:', 'SyntaxError:', 'Failed to load configuration', 'Cannot assign', 'is not a type', 'Binding loop detected')):
            errors.append(str(path) + ': ' + line)
print('QML_ERRORS', errors)
sys.exit(bool(errors))
QML_ERRORS
echo "service_delayed=$delayed_ok service_missing=$missing_ok service_restart=$restart_ok demo_isolation=$demo_ok system_socket=$system_ok protection_sections=$prot_ok search_while_typing=$search_ok scroll_settings=$scroll_ok ux_settings=$ux_ok hold=$hold_ok workdir=$WORKDIR"
exit $(( system_ok != 0 || endpoint_ok != 0 || policy_ok != 0 || qml_errors != 0 || missing_delayed_ok != 0 || rebind_ok != 0 || delayed_ok != 0 || missing_ok != 0 || restart_ok != 0 || demo_ok != 0 || prot_ok != 0 || search_ok != 0 || scroll_ok != 0 || ux_ok != 0 || hold_ok != 0 ))
