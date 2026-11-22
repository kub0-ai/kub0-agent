"use strict";
// The panel's changes go to the system daemon (#61 step 1b, the hybrid), run
// through the actual Service.qml functions: a raise as a control request on a
// request-only connection, a lowering change through `pkexec kub0 --json`,
// and the helper as before when the system socket cannot be reached.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const CM = require("../ConnectionModel.js");
const H = require("../js/Health.js");
const K = require("../js/Kub0.js");
const Control = require("../js/Control.js");

const source = fs.readFileSync(path.join(__dirname, "../Service.qml"), "utf8");
const functions = Array.from(source.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));
const fn = (name) => {
  const f = functions.find((x) => x[1] === name);
  assert.ok(f, "missing actual Service function " + name);
  return f[0];
};

const timer = () => ({ running: false, restart() { this.running = true; }, stop() { this.running = false; } });

function service() {
  const row = {
    id: "c1", proto: "tcp", inode: 1,
    app: { id: "firefox", name: "Firefox", icon: "", desktop: "", pid: 4242, system: false },
    local: { ip: "192.0.2.254", port: 40000 }, remote: { ip: "203.0.113.9", port: 443 },
    state: "ESTABLISHED", country: "", lat: 0, lon: 0, unresolved: false, newNetwork: false,
    networkKey: "203.0.113.0/24", hostname: ""
  };
  const model = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1000, connections: [row] }), 1000);
  const s = {
    Control, Kub0: K, ConnectionModel: CM, Health: H, model,
    Object, JSON, String, Number, Date: { now: () => 1000 },
    shuttingDown: false, lastBlockError: "", pendingIpsApp: "", hostCriticalIps: [],
    temporaryRules: [], enforcementPaused: false,
    helperMutationGeneration: 0, statusRefreshPending: false,
    pkexecPath: "/usr/bin/pkexec", kub0Path: "/usr/bin/kub0", kub0Installed: true,
    systemSocketPath: "/private/run/kub0.sock",
    sysSock: null, sysGeneration: 0, sysState: "idle", sysWaiters: [], sysPending: {}, sysSerial: 0,
    changeInFlight: null, kub0Exit: {},
    blockProc: { running: false, command: [] }, kub0Proc: { running: false, command: null },
    sysDeadline: timer(), sysIdle: timer(), sysRequestTimeout: timer(),
    helperCalls: [], probes: 0, notes: [], sockets: [],
    connectState: "idle", connectCode: "", connectUrl: "", connectExpiresAt: 0, connectError: "",
    connectVia: "", connectBuffer: [], connectPending: false, vallumdPath: "/fixture/kub0d",
    connectProc: { running: false, command: null }, disconnectProc: { running: false, command: null },
    kub0: K.emptyKub0(), kub0Account: {}, kub0Revision: 0,
    userKub0: K.emptyKub0(), systemView: null, systemViewPending: false, policyViewBlind: false, tagNotice: "",
    // Which daemon the event stream is read from; "user" is the panel's own.
    eventSource: "user", watchError: "", watchRevision: 0, switchedToSystem: 0, sessionUid: -1,
    prefsSet: [], setPref: (key, value) => { s.prefsSet.push([key, value]); },
    // The real one swaps the event socket; here only that it was asked matters.
    useSystemSource: () => { s.switchedToSystem += 1; },
    localKub0Path: "/fixture/bin/kub0",
    adapter: { stateDir: () => "/private/state", socketPath: () => "/private/run-user/vallum.sock" },
    Qt: { callLater: (f) => f() },
    syncFromModel() {},
    runHelper: (args) => { s.helperCalls.push(Array.from(args)); },
    probeHelperStatus: () => { s.probes += 1; },
    writeSock: (line) => { s.notes.push(JSON.parse(line)); return true; },
    systemSocketComponent: {
      createObject: (_parent, props) => {
        const sock = Object.assign({ connected: false, written: [], dead: false,
          write(line) { this.written.push(line); }, flush() {}, destroy() { this.dead = true; } }, props);
        s.sockets.push(sock);
        return sock;
      }
    }
  };
  s.root = s;
  vm.createContext(s);
  for (const name of ["changeRunning", "submitChange", "dispatchChange", "finishChange", "onKub0Part",
    "withSystem", "flushSystemWaiters", "systemUnreachable", "closeSystemSocket", "failSystemRequests",
    "controlRequest", "onSystemSocketRead", "onSystemSocketConnected", "applyChangeOutcome", "appById",
    "openSystemSocket", "systemConnectFailed",
    "offerIpsFallback", "noteActivity", "requestConnect", "startConnect", "onConnectStdout",
    "onKub0LoginExit", "applyConnectEvent", "applyConnectFields", "cancelConnect",
    "requestDisconnect", "startDisconnect", "publishKub0", "refreshSystemView", "loadSystemView",
    "sendSystemRead", "tagNetwork", "tagOnSystem", "snoozePolicyRule", "resumePolicyRule",
    "userDaemonPolicyChange", "setWatch", "deleteWatch", "watchOnSystem", "setSharing", "systemSharingOf"]) {
    vm.runInContext(fn(name), s);
  }
  // The two bindings the switch reads, computed the way Service.qml binds them.
  Object.defineProperty(s, "systemSharing", { get() { return s.systemSharingOf(s.systemView); } });
  Object.defineProperty(s, "sharingIsSystems", { get() { return s.eventSource === "system" || s.systemSharing !== null; } });
  return s;
}

// The system daemon greets the request connection.
function greet(s, hello) {
  const sock = s.sysSock;
  sock.connected = true;
  s.onSystemSocketRead(sock, s.sysGeneration, JSON.stringify(Object.assign({ type: "hello", version: "0.4.4" }, hello || { mode: "system", requests: true })));
  return sock;
}

function sent(sock) {
  return sock.written.map((l) => JSON.parse(l));
}

function reply(s, sock, req, body) {
  s.onSystemSocketRead(sock, s.sysGeneration, JSON.stringify(Object.assign({ type: "reply", req }, body)));
}

// A raise goes to the system daemon as a control request, never the helper.
{
  const s = service();
  assert.strictEqual(s.submitChange(["block-app", "firefox", "4242"]), true);
  assert.strictEqual(s.sysState, "connecting");
  assert.strictEqual(s.sockets[0].path, "/private/run/kub0.sock");
  assert.ok(s.changeRunning(), "busy while the socket is probed");
  assert.strictEqual(s.submitChange(["block-app", "other", "1"]), false, "one change at a time");
  const sock = greet(s);
  const req = sent(sock);
  assert.strictEqual(req.length, 1);
  assert.deepStrictEqual(req[0], { app: "firefox", pids: ["4242"], req: "panel-1", cmd: "block" });
  assert.strictEqual(s.helperCalls.length, 0);
  // The ruleset of rows the system daemon broadcasts is skipped.
  s.onSystemSocketRead(sock, s.sysGeneration, JSON.stringify({ type: "snapshot", ts: 1, connections: [{ id: "other user" }] }));
  assert.ok(s.changeRunning());
  reply(s, sock, "panel-1", { ok: true, result: { ok: true, verified: true, mechanism: "cgroup" } });
  assert.strictEqual(s.changeRunning(), false);
  assert.strictEqual(s.model.blocked.firefox.mechanism, "cgroup");
  assert.strictEqual(s.lastBlockError, "");
  assert.strictEqual(s.probes, 1, "the helper status is re-read after the change");
  // The user daemon's activity log is the panel's: one note, there.
  assert.deepStrictEqual(s.notes, [{ cmd: "note", kind: "block", app: { id: "firefox", name: "Firefox" }, detail: { mechanism: "cgroup" } }]);
  assert.ok(s.sysIdle.running, "the request connection closes once idle");
  // The next change reuses the open connection.
  s.submitChange(["resume"]);
  assert.deepStrictEqual(sent(sock)[1], { req: "panel-2", cmd: "resume" });
  assert.strictEqual(s.sockets.length, 1);
  reply(s, sock, "panel-2", { ok: true, result: { ok: true, paused: false, verified: true } });
  assert.strictEqual(s.enforcementPaused, false);
}

// A refused block keeps the helper's rollback/code for the address-block
// offer, and the failure is noted once on the user daemon.
{
  const s = service();
  let offered = null;
  s.offerIpsFallback = (app, err) => { offered = [app, err]; };
  s.submitChange(["block-app", "firefox", "4242"]);
  const sock = greet(s);
  reply(s, sock, "panel-1", { ok: false, error: "no live processes in the application forest",
    result: { ok: false, error: "no live processes in the application forest", code: "empty-forest", rollback: true } });
  assert.deepStrictEqual(offered, ["firefox", "no live processes in the application forest"]);
  assert.match(s.lastBlockError, /no live processes/);
  assert.deepStrictEqual(s.notes.map((n) => n.kind), ["block_failed"]);
  assert.ok(!s.model.blocked.firefox);
}

// A change the daemon keeps to root runs pkexec kub0, and its JSON is read
// the way the helper's was.
{
  const s = service();
  s.model.blocked.firefox = { mechanism: "endpoints" };
  s.submitChange(["unblock-ips", "firefox"]);
  greet(s);
  assert.deepStrictEqual(Array.from(s.kub0Proc.command), ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "unblock", "firefox", "--ips"]);
  assert.strictEqual(sent(s.sysSock).length, 0, "no control request for a lowering change");
  assert.strictEqual(s.helperCalls.length, 0);
  s.kub0Proc.running = true;
  s.onKub0Part("out", '{\n  "ok": true,\n  "mechanism": "endpoints"\n}\n');
  s.onKub0Part("code", 0);
  assert.notStrictEqual(s.changeInFlight, null, "not done until stdout, stderr and the exit are in");
  s.kub0Proc.running = false;
  s.onKub0Part("err", "");
  assert.strictEqual(s.changeRunning(), false);
  assert.ok(!s.model.blocked.firefox);
  assert.deepStrictEqual(s.notes.map((n) => [n.kind, n.detail.mechanism]), [["unblock", "endpoints"]]);
}

// The address-block fallback is a root change: pkexec kub0 block --ip.
{
  const s = service();
  s.submitChange(["block-ips", "firefox", "203.0.113.9"]);
  greet(s);
  assert.deepStrictEqual(Array.from(s.kub0Proc.command), ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "block", "firefox", "--ip", "203.0.113.9"]);
  // A dismissed prompt is a failure where lastBlockError shows it.
  s.onKub0Part("code", 126);
  s.onKub0Part("out", "");
  s.onKub0Part("err", "");
  assert.match(s.lastBlockError, /refused or cancelled/);
  assert.deepStrictEqual(s.notes.map((n) => n.kind), ["block_failed"]);
}

// No system daemon this user can reach: the helper, as before. There is one
// socket to try: 0.4.5 and 0.4.6 went on to a 0.4.x daemon's, and a refused
// connect there was the second step before the helper.
{
  const s = service();
  s.submitChange(["block-app", "firefox", "4242"]);
  s.onSystemSocketConnected(s.sysSock, s.sysGeneration, false); // connect refused
  assert.deepStrictEqual(s.sockets.map((k) => k.path), ["/private/run/kub0.sock"],
    "one socket: no 0.4.x one is tried");
  assert.deepStrictEqual(s.helperCalls, [["block-app", "firefox", "4242"]], "unreachable at once, so the helper");
  assert.strictEqual(s.changeInFlight, null, "the helper's process is the busy flag now");
  assert.strictEqual(s.sockets[0].dead, true);
  assert.strictEqual(s.sysState, "idle");
}
{
  // Silence until the deadline is unreachable too, and so is a daemon that
  // does not answer requests, or a user daemon at that path.
  for (const hello of [null, { mode: "system", requests: false }, { mode: "user", requests: true }]) {
    const s = service();
    s.submitChange(["pause"]);
    if (hello) greet(s, hello);
    else s.systemUnreachable();
    assert.deepStrictEqual(s.helperCalls, [["pause"]], JSON.stringify(hello));
    assert.strictEqual(s.kub0Proc.command, null);
  }
}
{
  // A root change with no installed kub0 stays on the helper.
  const s = service();
  s.kub0Installed = false;
  s.submitChange(["execgate-trust", "a".repeat(64)]);
  greet(s);
  assert.deepStrictEqual(s.helperCalls, [["execgate-trust", "a".repeat(64)]]);
  assert.strictEqual(s.kub0Proc.command, null);
}

// A connection that drops with a request outstanding fails it where the
// panel shows failures, and a stale socket cannot answer anything.
{
  const s = service();
  s.submitChange(["block-scoped", "firefox", "203.0.113.9", "900", "4242"]);
  const sock = greet(s);
  assert.deepStrictEqual(sent(sock)[0], { app: "firefox", ip: "203.0.113.9", seconds: 900, pids: ["4242"], req: "panel-1", cmd: "block-dest" });
  s.onSystemSocketRead(sock, s.sysGeneration - 1, JSON.stringify({ type: "reply", req: "panel-1", ok: true, result: { ok: true } }));
  assert.ok(s.changeRunning(), "a reply on an older generation is ignored");
  reply(s, sock, "panel-1", { ok: true, partial: true, result: {} });
  assert.ok(s.changeRunning(), "a partial reply does not finish a change");
  s.onSystemSocketConnected(sock, s.sysGeneration, false);
  assert.strictEqual(s.changeRunning(), false);
  assert.match(s.lastBlockError, /closed before it answered/);
}

// Connect: the system daemon's login when it is reachable, parsed line by
// line and at exit.
{
  const s = service();
  s.requestConnect();
  greet(s);
  assert.deepStrictEqual(Array.from(s.connectProc.command), ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "login"]);
  assert.strictEqual(s.connectVia, "kub0");
  assert.strictEqual(s.connectState, "waiting");
  s.onConnectStdout(JSON.stringify({ code: "ABCD-EFGH", url: "https://kub0.ai/connect", expiresIn: 900, interval: 5, minted: 1, max: 4 }));
  assert.strictEqual(s.connectCode, "ABCD-EFGH");
  assert.strictEqual(s.connectUrl, "https://kub0.ai/connect");
  assert.strictEqual(s.connectExpiresAt, 1000 + 900 * 1000);
  for (const line of ["{", '  "account": "/var/lib/kub0/account.json",', '  "githubUsername": "octo",', '  "serverUrl": "https://kub0.ai"', "}"])
    s.onConnectStdout(line);
  assert.strictEqual(s.connectState, "waiting", "the final reply is read at exit");
  s.onKub0LoginExit("", 0);
  assert.strictEqual(s.connectState, "connected");
  assert.strictEqual(s.kub0.connected, true);
  assert.strictEqual(s.kub0.githubUsername, "octo");
  assert.strictEqual(s.connectVia, "");
}
{
  const s = service();
  s.requestConnect();
  greet(s);
  s.onKub0LoginExit("kub0 login: device login expired\n", 1);
  assert.strictEqual(s.connectState, "error");
  assert.strictEqual(s.connectError, "device login expired");
}
{
  // Without a reachable system daemon, the user daemon's own account, through
  // the local kub0 on its socket (the daemon's `connect` is retired).
  const s = service();
  s.requestConnect();
  s.systemUnreachable();
  assert.deepStrictEqual(Array.from(s.connectProc.command), ["/fixture/bin/kub0", "--socket", "/private/run-user/vallum.sock", "--json", "login"]);
  assert.strictEqual(s.connectVia, "kub0", "the same parser as the system path");
  s.requestDisconnect();
  s.systemUnreachable();
  assert.deepStrictEqual(Array.from(s.disconnectProc.command), ["/fixture/bin/kub0", "--socket", "/private/run-user/vallum.sock", "logout"]);
  // No kub0 built: Connect says so rather than running a retired verb.
  const t = service();
  t.localKub0Path = "";
  t.requestConnect();
  t.systemUnreachable();
  assert.strictEqual(t.connectProc.command, null);
  assert.strictEqual(t.connectState, "error");
  assert.match(t.connectError, /kub0 is not built/);
}
{
  // Disconnect undoes Connect on the same daemon.
  const s = service();
  s.requestDisconnect();
  greet(s);
  assert.deepStrictEqual(Array.from(s.disconnectProc.command), ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "logout"]);
}

// -- #61 step 2: snooze, resume, the policy list, the account card, tags, watches --

// The system daemon's three reads, answered in order; returns the requests.
function answerSystemView(s, sock, status, policies, rules) {
  const asked = sent(sock).filter((r) => ["status", "policies", "rules"].includes(r.cmd));
  for (const r of asked) {
    const result = r.cmd === "status" ? status : r.cmd === "policies" ? policies : rules;
    reply(s, sock, r.req, { ok: true, result });
  }
  return asked;
}

const STATUS = { account: { connected: true, githubUsername: "octo", nodeName: "host-a", lastHeartbeatOk: true, lastHeartbeatTs: 900 },
  fleet: { orgEndpoints: 3, nodeLimit: 10, selfState: "enforcing", denylistVersion: 7 } };
const POLICIES = { connected: true, netpolicyRefreshOk: true,
  netpolicyEnforcement: { state: "enforcing", enforcing: true, rules: ["r-1"], appliedTs: 800 },
  netpolicies: [{ id: "p1", name: "Block C2", mode: "block", rules: [{ id: "r-1", kind: "ip", label: "C2", action: "block",
    effectiveAction: "block", enforced: true, canSnooze: true, snoozedUntil: 5000, hits: 2 }] }] };
const RULES = { connected: true, denylist: [{ name: "Bad", comm: "bad", action: "block" }] };

// A snooze lowers protection, so it is the system daemon's, through the root
// path: never a legacy line to the user daemon, which does not enforce. On
// d97a998 the panel wrote `netpolicy-snooze` to its user daemon socket.
{
  const s = service();
  s.snoozePolicyRule("r-1", 3600);
  assert.deepStrictEqual(s.notes.filter((n) => n.cmd === "netpolicy-snooze"), [],
    "the snooze went to the user daemon socket, which enforces nothing");
  assert.ok(s.sysSock, "a snooze asks for the system daemon first");
  greet(s);
  assert.deepStrictEqual(Array.from(s.kub0Proc.command),
    ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "policy", "snooze", "r-1", "--for", "3600s"]);
  assert.strictEqual(s.notes.filter((n) => n.cmd === "netpolicy-snooze").length, 0, "no snooze to the user daemon");
  assert.strictEqual(sent(s.sysSock).filter((r) => r.cmd === "policy-snooze").length, 0, "a lowering change is not a request");
  s.onKub0Part("out", '{\n  "rule": "r-1",\n  "snoozedUntil": 5000\n}\n');
  s.onKub0Part("err", "");
  s.onKub0Part("code", 0);
  assert.strictEqual(s.lastBlockError, "");
  // The list is read back from the system daemon, so the snooze shown is its own.
  const asked = answerSystemView(s, s.sysSock, STATUS, POLICIES, RULES);
  assert.deepStrictEqual(asked.map((r) => r.cmd).sort(), ["policies", "rules", "status"]);
  assert.strictEqual(s.kub0.netpolicies[0].rules[0].snoozedUntil, 5000);
  assert.strictEqual(s.kub0.netpolicyEnforcement.state, "enforcing");
}
{
  // The org's refusal reaches the panel where change failures show.
  const s = service();
  s.snoozePolicyRule("r-1", 3600);
  greet(s);
  s.onKub0Part("out", "");
  s.onKub0Part("err", "kub0 policy-snooze: your organization does not allow snoozing this rule\n");
  s.onKub0Part("code", 1);
  assert.strictEqual(s.lastBlockError, "your organization does not allow snoozing this rule");
}
{
  // A resume raises protection: a control request, no prompt.
  const s = service();
  s.resumePolicyRule("r-1");
  assert.deepStrictEqual(s.notes.filter((n) => n.cmd === "netpolicy-resume"), [],
    "the resume went to the user daemon socket, not the system daemon");
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "policy-resume");
  assert.deepStrictEqual(req, { rule: "r-1", req: req.req, cmd: "policy-resume" });
  assert.strictEqual(s.kub0Proc.command, null);
  reply(s, sock, req.req, { ok: true, result: { rule: "r-1", resumed: true } });
  assert.ok(sent(sock).some((r) => r.cmd === "policies"), "the list is read back");
}
{
  // A user-only install (no /usr/bin/kub0): nothing enforces, so the snooze
  // stays the user daemon's legacy line (it only quiets alerts), and so does
  // the resume.
  const s = service();
  s.kub0Installed = false;
  s.snoozePolicyRule("r-1", 600);
  s.systemUnreachable();
  assert.deepStrictEqual(s.notes, [{ cmd: "netpolicy-snooze", ruleId: "r-1", seconds: 600 }]);
  assert.strictEqual(s.kub0Proc.command, null);
  assert.strictEqual(s.helperCalls.length, 0, "never the helper");
  s.resumePolicyRule("r-1");
  s.systemUnreachable();
  assert.deepStrictEqual(s.notes[1], { cmd: "netpolicy-resume", ruleId: "r-1" });
}
{
  // A system install this session cannot reach (not in the kub0 group yet, or
  // no login since): the snooze still goes to the system daemon, through
  // pkexec kub0 as root, never to the user daemon that enforces nothing. The
  // panel says it cannot show the result.
  const s = service();
  s.snoozePolicyRule("r-1", 600);
  s.systemUnreachable();
  assert.deepStrictEqual(s.notes, [], "the snooze went to the user daemon socket on a system install");
  assert.strictEqual(s.helperCalls.length, 0, "never the helper");
  assert.deepStrictEqual(Array.from(s.kub0Proc.command),
    ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "policy", "snooze", "r-1", "--for", "600s"]);
  s.onKub0Part("out", JSON.stringify({ rule: "r-1", snoozed_until: 1 }) + "\n");
  s.onKub0Part("err", "");
  s.onKub0Part("code", 0);
  s.systemUnreachable();
  assert.ok(/^Snoozed on the system daemon\. This panel cannot read/.test(s.lastBlockError), s.lastBlockError);
  assert.strictEqual(s.policyViewBlind, false);
  s.kub0Proc.running = false;
  // The resume takes the same way, since the system path is closed too.
  s.resumePolicyRule("r-1");
  s.systemUnreachable();
  assert.deepStrictEqual(s.notes, []);
  assert.deepStrictEqual(Array.from(s.kub0Proc.command).slice(2), ["--json", "policy", "resume", "r-1"]);
}

// The account card and the policy list are the system daemon's when it is
// reachable, and a later frame from the user daemon does not take them back.
{
  const s = service();
  s.refreshSystemView();
  const sock = greet(s);
  answerSystemView(s, sock, STATUS, POLICIES, RULES);
  assert.strictEqual(s.kub0.connected, true);
  assert.strictEqual(s.kub0.githubUsername, "octo");
  assert.strictEqual(s.kub0.nodeName, "host-a");
  assert.strictEqual(s.kub0.selfState, "enforcing");
  assert.strictEqual(s.kub0.denylist.length, 1);
  assert.deepStrictEqual(JSON.parse(JSON.stringify(s.kub0Account)), { connected: true, node_name: "host-a", last_heartbeat_ok: true });
  // The user daemon (no account of its own) reports in.
  s.userKub0 = K.applyFleet(s.userKub0, { connected: false });
  s.publishKub0();
  assert.strictEqual(s.kub0.connected, true, "the user daemon's frame does not hide the system account");
  assert.strictEqual(s.kub0.netpolicies.length, 1);
}
{
  // Not reachable: the user daemon's own, as before.
  const s = service();
  s.userKub0 = K.applyHelloAccount(s.userKub0, { connected: true, github_username: "local", node_name: "host-b" });
  s.systemView = { status: STATUS };
  s.refreshSystemView();
  s.systemUnreachable();
  assert.strictEqual(s.systemView, null);
  assert.strictEqual(s.kub0.githubUsername, "local");
}

// Tags go to both daemons; when the system daemon refuses or is unreachable
// the user daemon's copy still applies, and the panel says so.
{
  const s = service();
  s.tagNetwork("203.0.113.0/24", "Office VPN", "service");
  assert.deepStrictEqual(s.notes, [{ type: "tag", networkKey: "203.0.113.0/24", label: "Office VPN", kind: "service" }],
    "the user daemon gets it at once");
  assert.ok(s.sysSock, "the tag goes to the system daemon too");
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "tag");
  assert.deepStrictEqual(req, { networkKey: "203.0.113.0/24", label: "Office VPN", kind: "service", req: req.req, cmd: "tag" });
  reply(s, sock, req.req, { ok: true, result: { networkKey: "203.0.113.0/24", label: "Office VPN", deleted: false } });
  assert.strictEqual(s.tagNotice, "");
}
{
  const s = service();
  s.tagNetwork("203.0.113.0/24", "Office VPN", "service");
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "tag");
  reply(s, sock, req.req, { ok: false, error: "tag: label exceeds 64 characters" });
  assert.match(s.tagNotice, /panel only.*refused.*64 characters/);
  assert.strictEqual(s.notes.length, 1, "the user daemon's copy stands");
}
{
  const s = service();
  s.tagNetwork("203.0.113.0/24", "Office VPN", "service");
  s.systemUnreachable();
  assert.strictEqual(s.notes.length, 1);
  assert.match(s.tagNotice, /panel only.*not reachable/);
}

// On its own daemon the panel's watch rules stay with that daemon: no system
// connection at all.
{
  const s = service();
  s.setWatch("country", "KP", "note");
  s.deleteWatch("w-1");
  assert.deepStrictEqual(s.notes.map((n) => [n.cmd, n.action]), [["watch", "set"], ["watch", "delete"]]);
  assert.strictEqual(s.sockets.length, 0, "a watch never opens the system socket");
}

// One daemon (#61): reading the system daemon, every change the panel used to
// write to its own daemon goes to the system daemon as a request, or is not
// sent at all. That daemon takes the legacy `watch`, `tag` and `note` lines
// from root only.
{
  const s = service();
  s.eventSource = "system";
  assert.strictEqual(s.setWatch("country", "KP", "note"), true);
  const sock = greet(s);
  const set = sent(sock).find((r) => r.cmd === "watch-set");
  assert.deepStrictEqual(set, { kind: "country", value: "KP", note: "note", req: set.req, cmd: "watch-set" });
  reply(s, sock, set.req, { ok: true, result: { rule: { id: "w-1" } } });
  assert.strictEqual(s.watchError, "", "the watchlist frame is the acknowledgement");
  s.deleteWatch("w-1");
  const del = sent(sock).find((r) => r.cmd === "watch-delete");
  assert.deepStrictEqual(del, { id: "w-1", req: del.req, cmd: "watch-delete" });
  // Another member's rule: the refusal is this panel's to show.
  reply(s, sock, del.req, { ok: false, error: "watch rule w-1 was set by uid 1001" });
  assert.strictEqual(s.watchError, "watch rule w-1 was set by uid 1001");
  assert.strictEqual(s.watchRevision, 1);
  assert.deepStrictEqual(s.notes, [], "no watch line is written to the event socket");
}
{
  const s = service();
  s.eventSource = "system";
  s.setWatch("asn", "64500", "");
  s.systemUnreachable();
  assert.match(s.watchError, /not reachable.*not changed/);
}
{
  // A name: the `tag` request is the whole change, and a refusal means nothing
  // was named (on its own daemon the panel would still have its copy).
  const s = service();
  s.eventSource = "system";
  s.tagNetwork("203.0.113.0/24", "Office VPN", "service");
  assert.deepStrictEqual(s.notes, [], "no tag line is written to the event socket");
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "tag");
  assert.deepStrictEqual(req, { networkKey: "203.0.113.0/24", label: "Office VPN", kind: "service", req: req.req, cmd: "tag" });
  reply(s, sock, req.req, { ok: false, error: "tag: label exceeds 64 characters" });
  assert.strictEqual(s.tagNotice, "Not named: the system daemon refused it (tag: label exceeds 64 characters).");
}
{
  const s = service();
  s.eventSource = "system";
  s.tagNetwork("203.0.113.0/24", "Office VPN", "service");
  s.systemUnreachable();
  assert.strictEqual(s.tagNotice, "Not named: the system daemon is not reachable.");
}
{
  // The system daemon records what it did; the panel's note would be refused.
  const s = service();
  s.eventSource = "system";
  s.noteActivity("block", { id: "firefox", name: "Firefox" }, { mechanism: "cgroup" });
  assert.deepStrictEqual(s.notes, []);
  s.eventSource = "user";
  s.noteActivity("block", { id: "firefox", name: "Firefox" }, { mechanism: "cgroup" });
  assert.strictEqual(s.notes.length, 1);
}
{
  // The `status` read says which uid this session is to the system daemon: a
  // block on the whole host's rows names only that account's processes.
  const s = service();
  s.refreshSystemView();
  const sock = greet(s);
  answerSystemView(s, sock, Object.assign({ peer: { uid: 1000 } }, STATUS), POLICIES, RULES);
  assert.strictEqual(s.sessionUid, 1000);
}
{
  // Reading the system daemon, the account is that daemon's: Connect and
  // Disconnect go to `pkexec kub0` even when this one request connection did
  // not come up. No daemon of the panel's own is there to log in or out, and
  // a logout sent to its socket would blank the card with nothing logged out.
  const s = service();
  s.eventSource = "system";
  s.requestConnect();
  s.systemUnreachable();
  assert.deepStrictEqual(Array.from(s.connectProc.command), ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "login"]);
  const d = service();
  d.eventSource = "system";
  d.requestDisconnect();
  d.systemUnreachable();
  assert.deepStrictEqual(Array.from(d.disconnectProc.command), ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "logout"]);
  // On its own daemon the fallback is that daemon's account, as before.
  const u = service();
  u.requestConnect();
  u.systemUnreachable();
  assert.deepStrictEqual(Array.from(u.connectProc.command), ["/fixture/bin/kub0", "--socket", "/private/run-user/vallum.sock", "--json", "login"]);
}
{
  // The system daemon answers while the panel is still on its own daemon
  // (installed since, or down when the source was chosen): the panel moves.
  const s = service();
  s.refreshSystemView();
  const sock = greet(s);
  assert.strictEqual(s.switchedToSystem, 1);
  answerSystemView(s, sock, STATUS, POLICIES, RULES);
  // Already reading it: nothing to move.
  s.eventSource = "system";
  s.refreshSystemView();
  assert.strictEqual(s.switchedToSystem, 1);
  // Unreachable: it stays where it is.
  const u = service();
  u.refreshSystemView();
  u.systemUnreachable();
  assert.strictEqual(u.switchedToSystem, 0);
}

// Destination sharing (#61, one daemon). Reading the system daemon the switch
// changes that daemon's setting: on asks root once (`pkexec kub0 share on`),
// off is a request. It used to set a preference that only restarted the
// panel's own daemon, which next to a logged-in system daemon reports nothing.
{
  const s = service();
  s.eventSource = "system";
  s.setSharing(true);
  greet(s);
  assert.deepStrictEqual(Array.from(s.kub0Proc.command), ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "share", "on"]);
  assert.deepStrictEqual(s.prefsSet, [], "not the panel's preference: nothing has changed yet");
  assert.deepStrictEqual(s.helperCalls, []);
}
{
  // The panel on its own daemon (capture on) beside a system daemon that has
  // said what its setting is: that daemon reports the host, so the switch is
  // still its setting. (It used to show and flip the preference, which next
  // to a logged-in system daemon decides nothing: the switch read Off while
  // the host shared.)
  const s = service();
  s.systemView = { status: { account: {}, fleet: { sharingDestinations: true } } };
  assert.strictEqual(s.sharingIsSystems, true);
  s.setSharing(false);
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "share-off");
  assert.ok(req, "share-off goes to the system daemon");
  assert.deepStrictEqual(s.prefsSet, []);
  // Done: the preference follows the owner's last choice, and the switch is
  // read again from the system daemon.
  reply(s, sock, req.req, { ok: true, result: { sharingDestinations: false } });
  assert.deepStrictEqual(s.prefsSet, [["shareDestinations", false]]);
  assert.ok(sent(sock).some((r) => r.cmd === "status"), "the system daemon's status is read back");
  // A system daemon that has not said (older than 0.5, or not read): the preference.
  const old = service();
  old.systemView = { status: { account: {}, fleet: {} } };
  assert.strictEqual(old.sharingIsSystems, false);
  old.setSharing(true);
  assert.deepStrictEqual(old.prefsSet, [["shareDestinations", true]]);
}
{
  // A refusal changes nothing, the preference included.
  const s = service();
  s.eventSource = "system";
  s.setSharing(false);
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "share-off");
  reply(s, sock, req.req, { ok: false, error: "share-off: the setting was not saved" });
  assert.deepStrictEqual(s.prefsSet, []);
}
{
  // share-off is a request: it needs no installed kub0 when the daemon answers.
  const s = service();
  s.eventSource = "system";
  s.kub0Installed = false;
  s.setSharing(false);
  const sock = greet(s);
  assert.ok(sent(sock).some((r) => r.cmd === "share-off"));
  assert.strictEqual(s.lastBlockError, "");
  // share-on needs root, and root needs kub0: said, not sent to the helper.
  const on = service();
  on.eventSource = "system";
  on.kub0Installed = false;
  on.setSharing(true);
  greet(on);
  assert.match(on.lastBlockError, /kub0 is not installed here/);
  assert.deepStrictEqual(on.helperCalls, []);
  assert.strictEqual(on.changeInFlight, null);
}
{
  const s = service();
  s.eventSource = "system";
  s.setSharing(false);
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "share-off");
  assert.deepStrictEqual(req, { req: req.req, cmd: "share-off" });
  reply(s, sock, req.req, { ok: true, result: { sharingDestinations: false } });
  assert.strictEqual(s.lastBlockError, "");
  assert.strictEqual(s.changeInFlight, null);
}
{
  // A refusal is shown where change failures show.
  const s = service();
  s.eventSource = "system";
  s.setSharing(false);
  const sock = greet(s);
  const req = sent(sock).find((r) => r.cmd === "share-off");
  reply(s, sock, req.req, { ok: false, error: "share-off: the setting was not saved (disk full); nothing changed" });
  assert.match(s.lastBlockError, /not saved/);
}
{
  // The request connection did not come up: root still reaches the daemon.
  // Never the helper, which has no such verb.
  for (const on of [true, false]) {
    const s = service();
    s.eventSource = "system";
    s.setSharing(on);
    s.systemUnreachable();
    assert.deepStrictEqual(Array.from(s.kub0Proc.command).slice(2), ["--json", "share", on ? "on" : "off"]);
    assert.deepStrictEqual(s.helperCalls, []);
  }
  // No kub0 at all (cannot be the system source, but the helper is still never run).
  const none = service();
  none.kub0Installed = false;
  none.submitChange(["share-on"]);
  none.systemUnreachable();
  assert.deepStrictEqual(none.helperCalls, []);
  assert.match(none.lastBlockError, /setting of the system daemon/);
  assert.strictEqual(none.changeInFlight, null);
}
{
  // On its own daemon it is the panel's preference, as before.
  const s = service();
  s.setSharing(true);
  s.setSharing(false);
  assert.deepStrictEqual(s.prefsSet, [["shareDestinations", true], ["shareDestinations", false]]);
  assert.strictEqual(s.sockets.length, 0);
}

console.log("test_panel_changes.js ok");
