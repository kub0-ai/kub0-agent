"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const H = require("../js/Health.js");
const CM = require("../ConnectionModel.js");

const source = fs.readFileSync(path.join(__dirname, "../Service.qml"), "utf8");
const functions = Array.from(source.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));

// A panel opened before the socket is ready must leave a desired state for
// every later daemon connection, including a reconnect after a restart.
{
  const sent = [];
  const c = {
    panelVisible: false, eventSock: { connected: false },
    model: CM.emptyState(), ConnectionModel: CM,
    writeSock: (line) => sent.push(JSON.parse(line)),
    refreshInstallState() {}, refreshSystemView() {}, syncFromModel() {}
  };
  c.root = c;
  vm.createContext(c);
  for (const name of ["replayPanelState", "markLooked", "markClosed"]) {
    const found = functions.find((x) => x[1] === name);
    assert.ok(found, "Missing actual QML function " + name);
    vm.runInContext(found[0], c);
  }
  c.markLooked();
  assert.strictEqual(c.panelVisible, true);
  assert.strictEqual(sent.length, 0);
  c.eventSock.connected = true;
  c.replayPanelState();
  assert.strictEqual(sent[0].type, "panel-open");
  c.eventSock.connected = false;
  c.eventSock.connected = true;
  c.replayPanelState();
  assert.strictEqual(sent[1].type, "panel-open");
  c.markClosed();
  assert.strictEqual(sent[2].type, "panel-close");
  c.replayPanelState();
  assert.strictEqual(sent.length, 3);
  assert.ok(source.includes("replayPanelState()"), "socket connect replays desired panel state");
}

function fresh() {
  let h = H.markSocketUp(H.markDaemonAvailable(H.emptyHealth(), true), 1000);
  let m = CM.emptyState();
  const row = {
    id: "fixture-flow", proto: "tcp", inode: 123,
    app: { id: "fixture-app", name: "Fixture", icon: "", desktop: "", pid: 1234, system: false },
    local: { ip: "192.0.2.254", port: 45678 },
    remote: { ip: "192.0.2.1", port: 443 },
    state: "ESTABLISHED", country: "", lat: 0, lon: 0,
    unresolved: false, newNetwork: false, networkKey: "192.0.2.0/24", hostname: ""
  };
  return H.applyIngest(h, m, JSON.stringify({ type: "snapshot", ts: 1000, connections: [row] }), 1000, CM.applyLine);
}

function serviceAt(now) {
  const state = fresh();
  const calls = [];
  const context = {
    Health: H, ConnectionModel: CM, model: state.model, health: state.health,
    blockingReady: true, lastBlockError: "", pendingIpsApp: "", hostCriticalIps: [],
    blockHint: "helper down",
    // Which daemon the rows are read from, and this session's uid as the
    // system daemon reported it (-1: not read yet).
    eventSource: "user", sessionUid: -1, otherAccountsApp: "This app is running under another account.",
    helperBusy: false,
    Date: { now: () => now },
    // Every change goes through submitChange, which routes it (system daemon,
    // pkexec kub0, or the helper fallback); these tests pin what is asked.
    submitChange: (args) => calls.push(Array.from(args))
  };
  vm.createContext(context);
  for (const name of ["appById", "requestBlock", "requestBlockIps", "requestDestinationBlock", "ownPids"]) {
    const found = functions.find((x) => x[1] === name);
    assert.ok(found, "Missing actual QML function " + name);
    vm.runInContext(found[0], context);
  }
  return { context, calls };
}

{
  const { context: c, calls } = serviceAt(1100);
  c.requestBlock("fixture-app");
  assert.deepStrictEqual(calls, [["block-app", "fixture-app", "1234"]]);
}
{
  const { context: c, calls } = serviceAt(1000 + H.STALE_MS + 1);
  c.requestBlock("fixture-app");
  c.requestBlockIps("fixture-app");
  assert.strictEqual(calls.length, 0);
}
{
  const { context: c, calls } = serviceAt(1100);
  c.health = H.markSocketUp(H.markSocketDown(c.health), 1100);
  c.requestBlock("fixture-app");
  c.requestBlockIps("fixture-app");
  assert.strictEqual(calls.length, 0);
}
for (const mechanism of ["cgroup", "endpoints"]) {
  const { context: c, calls } = serviceAt(10000);
  c.model.blocked.departed = { mechanism };
  c.requestBlock("departed");
  assert.deepStrictEqual(calls, [[mechanism === "endpoints" ? "unblock-ips" : "unblock-app", "departed"]]);
}

assert.ok(source.indexOf("scheduleSocketRetry") !== -1);
assert.ok(source.indexOf("resetDemoObservations") !== -1);
assert.ok(source.indexOf("resumeLiveSource") !== -1);
assert.ok(source.indexOf("model = out.model") !== -1);
assert.ok(source.indexOf("daemonStatus = \"reconnecting\"") !== -1);

// Whole host (#61): reading the system daemon, one row can hold another
// account's processes, because that daemon gives a binary the same app id
// under every account. A block names only this session's processes; the
// helper refuses the whole block when one pid is someone else's.
{
  const { context: c, calls } = serviceAt(1100);
  const mine = { id: "mine", proto: "tcp", inode: 1, uid: 1000,
    app: { id: "shared-app", name: "Shared", icon: "", desktop: "", pid: 4242, system: false, owner: { uid: 1000, name: "me" } },
    local: { ip: "192.0.2.254", port: 40000 }, remote: { ip: "192.0.2.1", port: 443 }, state: "ESTABLISHED",
    country: "", lat: 0, lon: 0, unresolved: false, newNetwork: false, networkKey: "192.0.2.0/24", hostname: "" };
  const theirs = JSON.parse(JSON.stringify(mine));
  theirs.id = "theirs"; theirs.inode = 2; theirs.uid = 1001; theirs.app.pid = 5151; theirs.app.owner = { uid: 1001, name: "them" };
  const only = JSON.parse(JSON.stringify(theirs));
  only.id = "only-theirs"; only.inode = 3; only.app.id = "their-app"; only.app.name = "Theirs"; only.app.pid = 6161;
  c.model = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1000, connections: [mine, theirs, only] }), 1000);
  c.health = H.applyIngest(H.markSocketUp(H.markDaemonAvailable(H.emptyHealth(), true), 1000), CM.emptyState(),
    JSON.stringify({ type: "snapshot", ts: 1000, connections: [mine, theirs, only] }), 1000, CM.applyLine).health;
  assert.deepStrictEqual(Array.from(CM.pidsOf(c.appById("shared-app"))).sort(), [4242, 5151], "the row holds both accounts' pids");
  // On its own daemon nothing is filtered: its rows are this account's.
  c.requestBlock("shared-app");
  assert.deepStrictEqual(Array.from(calls.pop()).sort(), ["4242", "5151", "block-app", "shared-app"]);
  // Reading the system daemon as uid 1000.
  c.eventSource = "system";
  c.sessionUid = 1000;
  c.requestBlock("shared-app");
  assert.deepStrictEqual(Array.from(calls.pop()), ["block-app", "shared-app", "4242"]);
  c.requestDestinationBlock("shared-app", "192.0.2.1", 900);
  assert.deepStrictEqual(Array.from(calls.pop()), ["block-scoped", "shared-app", "192.0.2.1", "900", "4242"]);
  // An app only the other account runs: nothing is sent, and the panel says why.
  c.requestBlock("their-app");
  assert.strictEqual(calls.length, 0);
  assert.match(c.lastBlockError, /another account/);
  c.lastBlockError = "";
  c.requestDestinationBlock("their-app", "192.0.2.1", 900);
  assert.strictEqual(calls.length, 0);
  assert.match(c.lastBlockError, /another account/);
  // Before the first status read the uid is not known: as before.
  c.sessionUid = -1;
  c.requestBlock("shared-app");
  assert.strictEqual(calls.pop().length, 4);
}

// Exercise the actual extracted socket lifecycle functions. Retired socket
// objects cannot mutate health or dispatch rows after replacement.
{
  const made = [];
  const c = {
    daemonAvailable: true, usingFallback: false, shuttingDown: false,
    socketGeneration: 3, eventSock: { connected: false, destroy() { this.dead = true; } },
    adapter: { socketPath: () => "/private/fixture/vallum.sock" },
    eventSource: "user", systemSocketPath: "/private/fixture/system.sock", systemStreamFailures: 0,
    sockRetry: { stop() {} },
    eventSocketComponent: { createObject(_parent, props) { const o = Object.assign({ destroy() { this.dead = true; } }, props); made.push(o); return o; } },
    daemonProc: { running: true }, Health: H, health: H.markDaemonAvailable(H.emptyHealth(), true),
    retirePolicyEvidence() {}, syncHealthView() {}, replayPanelState() {}, scheduleSocketRetry() {}, failPendingSocketRequests() {},
    ingested: 0, ingest() { this.ingested += 1; },
    Date: { now: () => 1234 }
  };
  c.root = c;
  vm.createContext(c);
  for (const name of ["eventSocketPath", "replaceEventSocket", "currentSocket", "onEventSocketConnected", "onEventSocketRead", "writeSock"]) {
    const fn = functions.find((x) => x[1] === name);
    assert.ok(fn, "missing actual Service function " + name);
    vm.runInContext(fn[0], c);
  }
  const obsolete = c.eventSock;
  c.replaceEventSocket();
  assert.strictEqual(obsolete.dead, true);
  assert.strictEqual(c.socketGeneration, 4);
  assert.strictEqual(c.eventSock.path, "/private/fixture/vallum.sock");
  assert.strictEqual(c.currentSocket(obsolete, 3), false);
  c.onEventSocketConnected(obsolete, 3, true);
  c.onEventSocketRead(obsolete, 3, "obsolete row");
  assert.strictEqual(c.ingested, 0);
  assert.notStrictEqual(H.derive(c.health, 1234, { count: 0 }).monitoring, "current");
  c.eventSock.connected = true;
  c.onEventSocketConnected(c.eventSock, 4, true);
  assert.strictEqual(H.derive(c.health, 1234, { count: 0 }).monitoring, "awaiting_snapshot");
  c.eventSock = null;
  assert.strictEqual(c.writeSock("{}"), false);
}

// One daemon (#61): the event stream comes from the system daemon when this
// session can use it and capture is off, and then the panel runs no kub0d of
// its own. Otherwise from its own daemon, as before.
function sourceService(over) {
  const made = [];
  const c = Object.assign({
    shuttingDown: false, usingFallback: false, prefs: { captureEnabled: false },
    eventSource: "user", systemStreamFailures: 0, socketGeneration: 0, eventSock: null,
    vallumdPath: "/fixture/kub0d", daemonAvailable: false, daemonStatus: "", kub0Installed: false,
    systemSocketPath: "/private/fixture/system.sock",
    adapter: { socketPath: () => "/private/fixture/user.sock" },
    daemonProc: { running: false }, started: 0,
    restartTimer: { stop() {} }, sockConnectDelay: { stop() {} }, sockRetry: { stop() {} },
    Health: H, health: H.emptyHealth(), syncHealthView() {}, retirePolicyEvidence() {}, scheduleSocketRetry() {},
    reachable: true, asked: 0,
    eventSocketComponent: { createObject(_parent, props) { const o = Object.assign({ destroy() {} }, props); made.push(o); return o; } },
    made
  }, over || {});
  c.startDaemon = () => { c.started += 1; c.daemonProc.running = true; };
  c.withSystem = (cb) => { c.asked += 1; cb(c.reachable); };
  c.root = c;
  vm.createContext(c);
  for (const name of ["eventSocketPath", "captureNeedsOwnDaemon", "chooseSource", "useSystemSource", "useUserSource",
    "retireEventSocket", "recheckSource", "retrySystemStream", "replaceEventSocket"]) {
    const fn = functions.find((x) => x[1] === name);
    assert.ok(fn, "missing actual Service function " + name);
    vm.runInContext(fn[0], c);
  }
  return c;
}
{
  // Usable system daemon: its socket is the event socket, and nothing is spawned.
  const c = sourceService();
  c.chooseSource();
  assert.strictEqual(c.eventSource, "system");
  assert.strictEqual(c.started, 0, "the panel starts no kub0d of its own");
  assert.strictEqual(c.daemonAvailable, true);
  assert.strictEqual(c.made.length, 1);
  assert.strictEqual(c.made[0].path, "/private/fixture/system.sock");
  // No kub0d binary in the plugin at all: still fine, there is nothing to start.
  const bare = sourceService({ vallumdPath: "" });
  bare.chooseSource();
  assert.strictEqual(bare.eventSource, "system");
  assert.strictEqual(bare.daemonStatus, "starting");
}
{
  // Not installed, or this session is not in group kub0: its own daemon.
  const c = sourceService({ reachable: false });
  c.chooseSource();
  assert.strictEqual(c.eventSource, "user");
  assert.strictEqual(c.started, 1);
  assert.strictEqual(c.made.length, 0, "the socket follows the daemon's start, as before");
  assert.strictEqual(c.eventSocketPath(), "/private/fixture/user.sock");
  // And with no kub0d either, it says so.
  const none = sourceService({ reachable: false, vallumdPath: "" });
  none.chooseSource();
  assert.strictEqual(none.daemonStatus, "missing");
  assert.strictEqual(none.started, 0);
  assert.strictEqual(none.health.daemonAvailable, false);
  // With kub0 installed and nothing of its own to start, what is missing is the
  // system daemon: the panel says that, not "kub0d is not built", and keeps
  // asking (sourceRecheck) instead of stopping for good.
  const waiting = sourceService({ reachable: false, vallumdPath: "", kub0Installed: true });
  waiting.chooseSource();
  assert.strictEqual(waiting.daemonStatus, "reconnecting");
  assert.match(JSON.stringify(waiting.health), /the system daemon is not answering/);
  waiting.reachable = true;
  waiting.recheckSource();
  assert.strictEqual(waiting.eventSource, "system");
  assert.strictEqual(waiting.made.length, 1);
}
{
  // Asked again only where the answer can change: on its own daemon (or none),
  // with kub0 installed, and not while capture keeps it there.
  const own = sourceService({ kub0Installed: true, daemonProc: { running: true } });
  own.recheckSource();
  assert.strictEqual(own.eventSource, "system", "a bar-only session moves too: nothing else asks while the panel is closed");
  const userOnly = sourceService({ kub0Installed: false });
  userOnly.recheckSource();
  assert.strictEqual(userOnly.asked, 0);
  const capturing = sourceService({ kub0Installed: true, prefs: { captureEnabled: true } });
  capturing.recheckSource();
  assert.strictEqual(capturing.asked, 0);
  const already = sourceService({ kub0Installed: true, eventSource: "system" });
  already.recheckSource();
  assert.strictEqual(already.asked, 0);
}
{
  // The preferences loaded while the system daemon was being asked: capture is
  // on after all, so the answer starts the panel's own daemon. (It used to end
  // on neither: no daemon, no socket.)
  const c = sourceService();
  let answer = null;
  c.withSystem = (cb) => { answer = cb; };
  c.chooseSource();
  c.prefs = { captureEnabled: true };
  answer(true);
  assert.strictEqual(c.eventSource, "user");
  assert.strictEqual(c.started, 1);
  assert.strictEqual(c.made.length, 0);
}
{
  // Capture needs a kub0d of the panel's own. With none to start, the switch
  // cannot move the panel off the system daemon (it used to leave the system
  // socket connected and write it the lines only its own daemon takes).
  const c = sourceService({ vallumdPath: "", prefs: { captureEnabled: true } });
  c.chooseSource();
  assert.strictEqual(c.eventSource, "system");
  assert.strictEqual(c.started, 0);
}
{
  // Moving to its own daemon: the system daemon's socket is retired at once,
  // before the new daemon's is there.
  const sys = { connected: true, destroy() { this.dead = true; } };
  const c = sourceService({ eventSource: "system", daemonStatus: "connected", eventSock: sys, prefs: { captureEnabled: true } });
  c.chooseSource();
  assert.strictEqual(c.eventSource, "user");
  assert.strictEqual(sys.dead, true);
  assert.strictEqual(c.eventSock, null);
  assert.strictEqual(c.started, 1);
}
{
  // Chosen again while the stream is up: a request connection that failed does
  // not move a panel that is reading the daemon.
  const c = sourceService({ eventSource: "system", daemonAvailable: true, reachable: false, daemonStatus: "connected" });
  c.chooseSource();
  assert.strictEqual(c.eventSource, "system");
  assert.strictEqual(c.started, 0);
}
{
  // Capture runs only in the panel's own daemon: the system daemon is not even asked.
  const c = sourceService({ prefs: { captureEnabled: true } });
  c.chooseSource();
  assert.strictEqual(c.eventSource, "user");
  assert.strictEqual(c.asked, 0);
  assert.strictEqual(c.started, 1);
  // Nor is a running panel moved onto it while capture is on.
  c.useSystemSource();
  assert.strictEqual(c.eventSource, "user");
}
{
  // Moving from its own daemon: that daemon is stopped, the socket replaced.
  const c = sourceService({ daemonProc: { running: true } });
  c.useSystemSource();
  assert.strictEqual(c.daemonProc.running, false);
  assert.strictEqual(c.made[0].path, "/private/fixture/system.sock");
}
{
  // The system daemon's stream is down. A restart is over in a second, so its
  // socket is tried again; only past five tries is the source chosen again,
  // which is what starts the panel's own daemon if it is gone for good.
  const c = sourceService({ eventSource: "system", daemonAvailable: true, reachable: false });
  for (let i = 0; i < 5; i++)
    c.retrySystemStream();
  assert.strictEqual(c.made.length, 5);
  assert.strictEqual(c.asked, 0);
  assert.strictEqual(c.started, 0);
  c.retrySystemStream();
  assert.strictEqual(c.asked, 1);
  assert.strictEqual(c.eventSource, "user");
  assert.strictEqual(c.started, 1);
}

// Demo retires the live receiver and cancels an in-flight history request.
// These extracted-method regressions supplement, rather than replace, QML.
{
  const stopped = [];
  const timer = (name) => ({ stop() { stopped.push(name); }, restart() {} });
  const old = { connected: true, destroy() { this.dead = true; } };
  const c = {
    eventSock: old, socketGeneration: 4, usingFallback: false, shuttingDown: false,
    health: fresh().health, Health: H, Date: { now: () => 1200 },
    historyBusy: true, historyRequest: "pending", historyError: "",
    investigateBusy: true, investigateRequest: "pending", investigateError: "",
    timelineBusy: true, timelineRequest: "pending", timelineError: "",
    historyTimeout: timer("history"), investigateTimeout: timer("investigate"), timelineTimeout: timer("timeline"), sockRetry: timer("retry"),
    sockConnectDelay: timer("connect"), restartTimer: timer("restart"),
    fallbackTimer: timer("fallback"), replayView: { text: () => "", reload() {} },
    Kub0: require('../js/Kub0.js'), kub0: require('../js/Kub0.js').emptyKub0(),
    userKub0: require('../js/Kub0.js').emptyKub0(), systemView: null, kub0Account: {},
    kub0Revision: 0, policyDaemonMode: 'system', vallumdPath: '', eventSource: 'user',
    resetDemoObservations() {}, syncHealthView() {}
  };
  vm.createContext(c);
  for (const name of ["retirePolicyEvidence", "publishKub0", "enterDemo", "failPendingSocketRequests", "currentSocket"]) {
    vm.runInContext(functions.find((x) => x[1] === name)[0], c);
  }
  // The user daemon's state is the source; `kub0` is what the panel shows.
  c.userKub0.connected = true;
  c.userKub0.netpolicyEnforcement = {state:'enforcing', enforcing:true, appliedTs:123};
  assert.strictEqual(c.enterDemo("on"), "demo");
  assert.strictEqual(c.policyDaemonMode, 'unknown');
  assert.strictEqual(c.kub0.netpolicyEnforcement.enforcing, false);
  assert.strictEqual(c.kub0.connected, true);
  assert.strictEqual(c.kub0Revision, 1);
  assert.strictEqual(c.historyBusy, false);
  assert.strictEqual(c.historyRequest, "");
  assert.match(c.historyError, /demo replay started/);
  // An in-flight investigate request is retired the same way.
  assert.strictEqual(c.investigateBusy, false);
  assert.strictEqual(c.investigateRequest, "");
  assert.match(c.investigateError, /demo replay started/);
  assert.strictEqual(c.eventSock, null);
  assert.strictEqual(old.dead, true);
  assert.strictEqual(c.currentSocket(old, 4), false);
  assert.strictEqual(c.daemonStatus, "fallback");
  assert.strictEqual(c.timelineBusy, false);
  assert.match(c.timelineError, /demo replay started/);
  for (const name of ["retry", "connect", "restart", "history", "investigate", "timeline"])
    assert.ok(stopped.includes(name));
  assert.strictEqual(c.enterDemo("off"), "off");
  assert.strictEqual(c.policyDaemonMode, 'unknown');
  assert.strictEqual(c.kub0.netpolicyEnforcement.enforcing, false);
  assert.strictEqual(c.kub0Revision, 2);
  assert.strictEqual(c.daemonStatus, "missing", "no kub0d and no system daemon being read");

  // Leaving the replay while reading the system daemon, with no kub0d in the
  // plugin: the stream is resumed. (It used to stop at "missing" for good:
  // only a kub0d of the panel's own counted as something to resume.)
  let resumed = 0, chosen = 0;
  c.resumeLiveSource = () => { resumed += 1; };
  c.chooseSource = () => { chosen += 1; };
  c.root = c;
  c.prefs = { captureEnabled: false };
  vm.runInContext(functions.find((x) => x[1] === "captureNeedsOwnDaemon")[0], c);
  c.eventSource = "system";
  c.enterDemo("on");
  assert.strictEqual(c.enterDemo("off"), "off");
  assert.strictEqual(c.daemonStatus, "reconnecting");
  assert.strictEqual(resumed, 1);
  assert.strictEqual(chosen, 0);
  // A capture switch flipped during the replay was not acted on then: now.
  c.vallumdPath = "/fixture/kub0d";
  c.prefs = { captureEnabled: true };
  c.enterDemo("on");
  c.enterDemo("off");
  assert.strictEqual(resumed, 2);
  assert.strictEqual(chosen, 1);
}

function extractAll(filename) {
  const src = fs.readFileSync(path.join(__dirname, "..", filename), "utf8");
  return Array.from(src.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));
}

function panelAndService(now, ready) {
  const state = fresh();
  const calls = [];
  const svc = {
    Health: H, ConnectionModel: CM, model: state.model, health: state.health,
    blockingReady: ready !== false, lastBlockError: "", pendingIpsApp: "fixture-app",
    hostCriticalIps: [], blockHint: "helper down", Date: { now: () => now },
    submitChange: (args) => calls.push(Array.from(args))
  };
  vm.createContext(svc);
  const svcFns = extractAll("Service.qml");
  for (const name of ["appById", "requestBlockIps", "offerIpsFallback"]) {
    const found = svcFns.find((x) => x[1] === name);
    assert.ok(found, "missing Service function " + name);
    vm.runInContext(found[0], svc);
  }
  const panel = {
    ConnectionModel: CM, liveVallum: svc, pendingIpsApp: "fixture-app", confirmIps: true
  };
  vm.createContext(panel);
  const panelFns = extractAll("Panel.qml");
  for (const name of ["cancelIps", "confirmIpsBlock"]) {
    const found = panelFns.find((x) => x[1] === name);
    assert.ok(found, "missing Panel function " + name);
    vm.runInContext(found[0], panel);
  }
  return { svc, panel, calls };
}

{
  const { svc, panel, calls } = panelAndService(1100, false);
  panel.confirmIpsBlock();
  assert.strictEqual(calls.length, 0);
  assert.strictEqual(svc.pendingIpsApp, "");
  assert.strictEqual(panel.confirmIps, false);
  const beforeRepeat = svc.pendingIpsApp;
  svc.offerIpsFallback("fixture-app", "cgroup failed again");
  assert.strictEqual(svc.pendingIpsApp, "fixture-app");
  assert.notStrictEqual(beforeRepeat, svc.pendingIpsApp);
}

{
  const { svc, panel, calls } = panelAndService(1100, true);
  panel.confirmIpsBlock();
  assert.deepStrictEqual(calls, [["block-ips", "fixture-app", "192.0.2.1"]]);
  assert.strictEqual(svc.pendingIpsApp, "");
  assert.strictEqual(panel.confirmIps, false);
}

{
  const { svc } = panelAndService(1100, true);
  svc.pendingIpsApp = "fixture-app";
  svc.offerIpsFallback("fixture-app", "again");
  assert.strictEqual(svc.pendingIpsApp, "fixture-app");
}

{
  const { context: c, calls } = serviceAt(1100);
  c.blockingReady = false;
  c.pendingIpsApp = "fixture-app";
  c.requestBlockIps("fixture-app");
  assert.strictEqual(calls.length, 0);
  assert.strictEqual(c.pendingIpsApp, "");
}

// The header power switch. Off pauses, on resumes, and the switch follows
// what the helper reports, never the click: `checked` is bound to
// enforcementPaused, so a click that did nothing must leave it where it was.
function switchService() {
  const calls = [];
  const probes = [];
  const svc = {
    Health: H, ConnectionModel: CM, model: CM.emptyState(),
    helperInstalled: true, blockingToolsReady: true, enforcementPaused: false,
    lastBlockError: "", blockProc: { command: [], running: false },
    helperMutationGeneration: 0, statusRequestGeneration: 0,
    statusRefreshPending: false,
    probeHelperStatus: () => probes.push(1),
    syncFromModel: () => {}, noteActivity: () => {}, appById: () => null,
    offerIpsFallback: () => {}, hostCriticalIps: [],
    kub0Proc: { running: false }, changeInFlight: null
  };
  svc.runHelper = (args) => {
    calls.push(Array.from(args));
    svc.blockProc.command = ["pkexec", "/usr/lib/vallum/vallum-block"].concat(args);
  };
  // The helper fallback path, which these tests drive through onBlockOutput.
  svc.submitChange = (args) => svc.runHelper(args);
  vm.createContext(svc);
  const svcFns = extractAll("Service.qml");
  for (const name of ["setEnforcementPaused", "onBlockOutput", "applyChangeOutcome", "applyHelperStatus", "changeRunning"]) {
    const found = svcFns.find((x) => x[1] === name);
    assert.ok(found, "missing Service function " + name);
    vm.runInContext(found[0], svc);
  }
  return { svc, calls, probes };
}

{
  // Status and a block use separate processes. A status snapshot taken before
  // a mutation must never erase its later result, in either direction.
  const { svc } = switchService();
  svc.helperStatusProc = { running: false, command: [] };
  svc.blockProc.running = false;
  svc.canonicalHelper = "/usr/lib/vallum/vallum-block";
  svc.pkexecPath = "/usr/bin/pkexec";
  svc.helperMutationGeneration = 0;
  svc.statusRequestGeneration = 0;
  svc.statusRefreshPending = false;
  svc.helperStatusParsed = false;
  svc.helperBlockCount = 0;
  svc.blockingToolsHint = "";
  svc.Date = { now: () => 1000 };
  for (const name of ["runHelper", "probeHelperStatus"]) {
    const found = functions.find((x) => x[1] === name);
    assert.ok(found, "Missing actual QML function " + name);
    vm.runInContext(found[0], svc);
  }
  const empty = JSON.stringify({ ok: true, blockingReady: true, table: false,
    cgroupBlocksSource: "marker", cgroupBlocksKnown: true, cgroupBlocks: [], owners: {} });
  const blocked = JSON.stringify({ ok: true, blockingReady: true, table: false,
    cgroupBlocksSource: "marker", cgroupBlocksKnown: true, cgroupBlocks: ["firefox"], owners: {} });
  svc.probeHelperStatus(); // old empty snapshot in flight
  svc.runHelper(["block-app", "firefox", "1234"]);
  svc.onBlockOutput(JSON.stringify({ ok: true, verified: true, mechanism: "cgroup" }));
  svc.blockProc.running = false;
  assert.ok(svc.model.blocked.firefox);
  svc.applyHelperStatus(empty);
  assert.ok(svc.model.blocked.firefox, "stale empty status cannot hide a live rule");
  assert.strictEqual(svc.statusRefreshPending, true);
  svc.helperStatusProc.running = false;
  svc.probeHelperStatus();
  svc.applyHelperStatus(blocked);
  assert.ok(svc.model.blocked.firefox);

  svc.helperStatusProc.running = false;
  svc.probeHelperStatus(); // old blocked snapshot in flight
  svc.runHelper(["unblock-app", "firefox"]);
  svc.onBlockOutput(JSON.stringify({ ok: true, verified: true, mechanism: "cgroup" }));
  svc.blockProc.running = false;
  assert.ok(!svc.model.blocked.firefox);
  svc.applyHelperStatus(blocked);
  assert.ok(!svc.model.blocked.firefox, "stale block status cannot resurrect an unblocked row");
  svc.helperStatusProc.running = false;
  svc.probeHelperStatus();
  svc.applyHelperStatus(empty);
  assert.ok(!svc.model.blocked.firefox);
}

{
  const { svc, calls } = switchService();
  svc.setEnforcementPaused(true);
  assert.deepStrictEqual(calls, [["pause"]]);
  assert.strictEqual(svc.enforcementPaused, false, "the click alone must not flip the switch");
  svc.onBlockOutput(JSON.stringify({ ok: true, paused: true, verified: true }));
  assert.strictEqual(svc.enforcementPaused, true);
  svc.setEnforcementPaused(false);
  svc.onBlockOutput(JSON.stringify({ ok: true, paused: false, verified: true }));
  assert.strictEqual(svc.enforcementPaused, false);
  assert.deepStrictEqual(calls, [["pause"], ["resume"]]);
}

{
  // The helper's answer wins over the click. Pausing when the marker is
  // already down is idempotent in the helper, so the switch must stay off —
  // a blind flip would turn it back on while nothing is enforced.
  const { svc } = switchService();
  svc.enforcementPaused = true;
  svc.setEnforcementPaused(true);
  svc.onBlockOutput(JSON.stringify({ ok: true, paused: true, verified: true }));
  assert.strictEqual(svc.enforcementPaused, true);
}

{
  // A failed pause re-reads the marker instead of guessing which way it landed.
  const { svc, probes } = switchService();
  svc.setEnforcementPaused(true);
  svc.onBlockOutput(JSON.stringify({ ok: false, error: "nft failed — enforcement left on" }));
  assert.strictEqual(svc.enforcementPaused, false);
  assert.strictEqual(probes.length, 1);
  assert.match(svc.lastBlockError, /enforcement left on/);
}

{
  // The nft rule landed, but an old socket escaped complete enforcement.
  // It must stay visible so the user can remove the live rule.
  const { svc } = switchService();
  svc.runHelper(["block-app", "firefox", "1234"]);
  svc.onBlockOutput(JSON.stringify({ ok: true, verified: false, ruleVerified: true,
    mechanism: "cgroup", warning: "an existing UDP socket may continue" }));
  assert.strictEqual(svc.model.blocked.firefox.mechanism, "cgroup");
  assert.match(svc.lastBlockError, /UDP socket/);
}

{
  // A dismissed polkit prompt produces no output: the switch stays put.
  const { svc } = switchService();
  svc.setEnforcementPaused(true);
  svc.onBlockOutput("");
  assert.strictEqual(svc.enforcementPaused, false);
}

{
  // Nothing to pause until blocking is installed and ready.
  const { svc, calls } = switchService();
  svc.blockingToolsReady = false;
  svc.setEnforcementPaused(true);
  assert.strictEqual(calls.length, 0);
}

{
  // The unprivileged status probe is what the switch reads on every panel open.
  const { svc } = switchService();
  svc.applyHelperStatus(JSON.stringify({ ok: true, blockingReady: true, paused: true, owners: {} }));
  assert.strictEqual(svc.enforcementPaused, true);
  svc.applyHelperStatus(JSON.stringify({ ok: true, blockingReady: true, owners: {} }));
  assert.strictEqual(svc.enforcementPaused, false, "an old helper without `paused` reads as enforcing");

  // nft status is unreadable as this user; a root-written marker is still
  // enough to restore the unblock control, without claiming a kernel read.
  svc.applyHelperStatus(JSON.stringify({ ok: true, blockingReady: true, table: false,
    cgroupBlocksSource: "marker", cgroupBlocksKnown: true,
    cgroupBlocks: ["firefox"], owners: {} }));
  assert.strictEqual(svc.model.blocked.firefox.mechanism, "cgroup");
}

{
  // The overview line must not call a paused block "live".
  const panel = { liveBlockCount: 2, enforcementPaused: true };
  vm.createContext(panel);
  const found = extractAll("Panel.qml").find((x) => x[1] === "enforcementPostureText");
  assert.ok(found, "missing Panel function enforcementPostureText");
  vm.runInContext(found[0], panel);
  assert.match(panel.enforcementPostureText(), /paused/);
  assert.doesNotMatch(panel.enforcementPostureText(), /recorded block/);
  panel.enforcementPaused = false;
  assert.strictEqual(panel.enforcementPostureText(), "2 apps have a recorded block on this host");
  assert.strictEqual(H.wordingForbidden("Enforcement is paused: 2 apps' blocks apply when you turn it back on"), "");
}

{
  // heroMeta maps each posture to itself and anything unknown to "Not
  // installed", so a posture Health can return but heroMeta does not list
  // renders a paused host as uninstalled. Pin the two lists together.
  const healthSrc = fs.readFileSync(path.join(__dirname, "../js/Health.js"), "utf8");
  const fn = healthSrc.match(/^function heroPosture\([\s\S]*?^\}/m)[0];
  const postures = Array.from(fn.matchAll(/return "([^"]+)"/g), (m) => m[1]);
  assert.ok(postures.includes("Paused"));
  const panelSrc = fs.readFileSync(path.join(__dirname, "../Panel.qml"), "utf8");
  const meta = panelSrc.match(/readonly property string heroMeta: \{[\s\S]*?^  \}/m)[0];
  for (const p of postures)
    assert.ok(meta.includes('return "' + p + '"'), "heroMeta does not map posture " + p);
}

// `enforcement off` over IPC let any process running as the user pause every
// block: the helper is pkexec'd from this shell, so the auth_admin_keep grant
// from the user's last click covered it with no prompt. The verb reports only,
// and the policy now makes pause ask every time (helper policy_tests).
{
  const ipc = source.match(/function enforcement\(arg: string\): string \{[\s\S]*?^    \}/m);
  assert.ok(ipc, "IpcHandler.enforcement is gone; update this pin deliberately");
  for (const mutator of ["setEnforcementPaused", "runHelper", "blockProc", "submitChange", "kub0Proc"])
    assert.strictEqual(ipc[0].indexOf(mutator), -1, "IPC enforcement reaches " + mutator);
  assert.ok(ipc[0].includes("refused"), "a mutation request must be answered, not ignored");
}

// A bare "pkexec" is whatever the user's PATH finds first.
{
  assert.ok(/property string pkexecPath: "\/usr\/bin\/pkexec"/.test(source));
  const run = functions.find((m) => m[1] === "runHelper");
  assert.ok(run && run[0].includes("[pkexecPath, canonicalHelper]"), "runHelper does not use pkexecPath");
  assert.strictEqual(source.indexOf('["pkexec"'), -1, "bare pkexec argv is back");
  const harness = fs.readFileSync(path.join(__dirname, "qml/service-harness.qml"), "utf8");
  assert.ok(harness.includes('pkexecPath: Quickshell.env("VALLUM_FAKE_PLUGIN") + "/bin/pkexec"'),
    "runtime harness no longer hands Service its refusing fake pkexec");
}

// An app whose only destinations are this machine's own gateway or nameservers
// was offered an endpoint block the helper could only refuse after the confirm.
{
  const { svc, calls } = panelAndService(1100, true);
  svc.hostCriticalIps = ["192.0.2.1"];
  svc.pendingIpsApp = "";
  svc.offerIpsFallback("fixture-app", "cgroup failed");
  assert.strictEqual(svc.pendingIpsApp, "", "offered a block of only host-critical addresses");
  svc.requestBlockIps("fixture-app");
  assert.strictEqual(calls.length, 0, "sent the helper an address it refuses");
}
{
  const { svc } = switchService();
  const status = (extra) => JSON.stringify(Object.assign({ ok: true, blockingReady: true,
    table: false, cgroupBlocksSource: "marker", cgroupBlocksKnown: true, cgroupBlocks: [],
    owners: {} }, extra));
  svc.applyHelperStatus(status({ hostCritical: ["192.168.0.254", "fe80::1"] }));
  assert.deepStrictEqual(Array.from(svc.hostCriticalIps), ["192.168.0.254", "fe80::1"]);
  svc.applyHelperStatus(status({}));
  assert.deepStrictEqual(Array.from(svc.hostCriticalIps), [], "an older helper's status keeps a stale list");
}

// A pause made outside the panel reached the bar only when the panel next
// opened, so the wall stayed up over a live pause rule until then.
{
  const watch = source.match(/Timer \{\s*id: pauseWatch\s*interval: (\d+)\s*running: root\.helperInstalled\s*repeat: true\s*onTriggered: root\.probeHelperStatus\(\)\s*\}/);
  assert.ok(watch, "no timer re-reads helper status while the helper is installed");
  assert.ok(Number(watch[1]) <= 30000, "pause re-read is slower than 30s: " + watch[1]);
}

console.log("test_service_dispatch.js ok");

// Execute actual hello/fleet ingestion: role is not inferred from account or helper.
{
  const K = require('../js/Kub0.js');
  const c = {
    Kub0: K, Health: H, ConnectionModel: CM, health: H.emptyHealth(), model: CM.emptyState(),
    kub0: K.emptyKub0(), userKub0: K.emptyKub0(), systemView: null, kub0Account: {}, kub0Revision:0, policyDaemonMode:'unknown',
    eventSource: 'user',
    captureStatus:{}, historyEntries:[], historyBusy:false, activityEntries:[], activitySinceStart:0,
    historyRequest:'', blockingReady:true, syncFromModel() {}, Qt:{callLater() {}},
    listeners:[{proto:'tcp',ip:'0.0.0.0',port:22}], listenersRevision:0, watchRules:[{id:'w-1'}], watchError:'stale', watchRevision:0,
    investigateRequest:'r1', investigateBusy:true, investigateError:'', investigateResult:null, investigateTimeout:{stop(){}},
    timelineRequest:'t1', timelineBusy:true, timelineError:'', timelineResult:{stale:true}, timelineTimeout:{stop(){}}
  };
  c.root = c;
  vm.createContext(c);
  for (const name of ['retirePolicyEvidence','publishKub0','applyDeferred','ingest']) vm.runInContext(functions.find(x => x[1] === name)[0], c);
  const hello = mode => {
    const ev = {type:'hello',account:{connected:true,github_username:'alice'}};
    if (mode !== undefined) ev.mode = mode;
    c.ingest(JSON.stringify(ev));
  };
  hello('user');
  assert.strictEqual(c.policyDaemonMode, 'user');
  // Intel frames are additive and read here, not by Health: hello clears what a
  // previous daemon sent, and each frame replaces the whole list.
  // Arrays made inside the vm realm have another Array prototype, so compare length.
  assert.strictEqual(c.listeners.length, 0, 'hello clears listeners from the previous daemon');
  assert.strictEqual(c.watchRules.length, 0);
  assert.strictEqual(c.watchError, '');
  assert.strictEqual(c.listenersRevision, 1);
  c.ingest(JSON.stringify({type:'listeners',ts:1,listeners:[{proto:'tcp',ip:'127.0.0.1',port:631,app:{id:'cups',name:'CUPS'},exe:'',uid:0,scope:'loopback'}]}));
  assert.strictEqual(c.listeners.length, 1);
  assert.strictEqual(c.listenersRevision, 2);
  c.ingest(JSON.stringify({type:'watchlist',ts:1,rules:[{id:'w-2',kind:'asn',value:'1'}],error:'nope'}));
  assert.strictEqual(c.watchRules[0].id, 'w-2');
  assert.strictEqual(c.watchError, 'nope');
  c.ingest(JSON.stringify({type:'investigate',request:'other',pivot:{connections:5},error:''}));
  assert.strictEqual(c.investigateBusy, true, 'a reply to a retired request is ignored');
  c.ingest(JSON.stringify({type:'investigate',request:'r1',pivot:{connections:5},error:''}));
  assert.strictEqual(c.investigateBusy, false);
  assert.strictEqual(c.investigateResult.connections, 5);
  assert.strictEqual(c.timelineResult, null, 'hello clears the previous daemon\'s timeline');
  c.ingest(JSON.stringify({type:'timeline',request:'t1',timeline:{buckets:24,apps:[]},error:''}));
  assert.strictEqual(c.timelineBusy, false);
  assert.strictEqual(c.timelineResult.buckets, 24);
  c.ingest(JSON.stringify({type:'listeners',ts:2,listeners:'junk'}));
  assert.strictEqual(c.listeners.length, 0, 'a malformed list degrades to empty');
  c.ingest(JSON.stringify({type:'fleet',connected:true,netpolicyRefreshOk:true,
    netpolicyEnforcement:{state:'enforcing',enforcing:true,appliedTs:1}}));
  assert.strictEqual(c.policyDaemonMode, 'user', 'fleet enforcement cannot establish system role');
  hello();
  assert.strictEqual(c.policyDaemonMode, 'unknown', 'legacy hello remains compatible without assuming role');
  assert.strictEqual(c.kub0.netpolicyEnforcement.enforcing, false, 'hello retires prior current-protection claim');
  assert.strictEqual(c.kub0.netpolicyEnforcement.appliedTs, 0);
  assert.strictEqual(c.kub0.connected, true, 'tenant connection is separate');
  assert.strictEqual(c.blockingReady, true, 'per-app helper readiness is separate');
  hello('system');
  assert.strictEqual(c.policyDaemonMode, 'system');
  hello('future');
  assert.strictEqual(c.policyDaemonMode, 'unknown');

  // Reading the system daemon's own stream (#61): its frames are the live
  // account and policies, so a `status`/`policies` read is not laid over them.
  // (It used to be: the card showed the values of the last panel open for as
  // long as the panel stayed open.) Only who the account is comes from the read.
  c.eventSource = 'system';
  hello('system');
  c.systemView = {
    status: { account: { connected: true, githubUsername: 'bob', nodeName: 'host-b', lastHeartbeatOk: true }, fleet: { selfState: 'enforcing' } },
    policies: { netpolicies: [{ id: 'old', name: 'Old', mode: 'block', rules: [] }], netpolicyRefreshOk: true,
      netpolicyEnforcement: { state: 'enforcing', enforcing: true, appliedTs: 1 } }
  };
  c.ingest(JSON.stringify({ type: 'fleet', connected: false }));
  assert.strictEqual(c.kub0.connected, false, 'the logout the stream reported is what the card shows');
  assert.strictEqual(c.kub0.netpolicies.length, 0);
  assert.strictEqual(c.kub0.netpolicyEnforcement.enforcing, false);
  assert.strictEqual(c.kub0.githubUsername, 'bob', 'who the account is: the read is the only source');
  // The stream ends: nothing read before that is evidence any more.
  c.retirePolicyEvidence();
  assert.strictEqual(c.systemView, null);
  // On its own daemon the read is laid over, as before.
  c.eventSource = 'user';
  c.systemView = { status: { account: { connected: true, githubUsername: 'bob', nodeName: 'host-b' }, fleet: {} } };
  c.publishKub0();
  assert.strictEqual(c.kub0.connected, true);
  c.retirePolicyEvidence();
  assert.notStrictEqual(c.systemView, null);
}
console.log('actual Service hello role and policy reset model checks passed');

// Execute the actual daemon exit handler during demo, including evidence reset.
{
  const K = require('../js/Kub0.js');
  const c = {Kub0:K, kub0:K.emptyKub0(), userKub0:K.emptyKub0(), systemView:null, kub0Account:{}, kub0Revision:0, policyDaemonMode:'system',
    eventSource:'user',
    shuttingDown:false, usingFallback:true, daemonStatus:'fallback', restarts:0,
    daemonErr:{text:''}, eventSock:null, socketGeneration:1,
    sockConnectDelay:{stop(){}}, sockRetry:{stop(){}}, failPendingSocketRequests(){},
    restartTimer:{restart(){throw new Error('demo must not restart live daemon');}}};
  c.root = c;
  vm.createContext(c);
  vm.runInContext(functions.find(x => x[1] === 'retirePolicyEvidence')[0], c);
  vm.runInContext(functions.find(x => x[1] === 'publishKub0')[0], c);
  c.userKub0.connected = true;
  c.userKub0.netpolicyEnforcement = {state:'enforcing',enforcing:true,appliedTs:123};
  const handler = source.match(/id: daemonProc[\s\S]*?onExited: function\(\) \{([\s\S]*?)\n    \}\n  \}/);
  assert.ok(handler, 'actual daemon exit handler missing');
  vm.runInContext('(function(){' + handler[1] + '})()', c);
  assert.strictEqual(c.policyDaemonMode, 'unknown');
  assert.strictEqual(c.kub0.netpolicyEnforcement.enforcing, false);
  assert.strictEqual(c.kub0.connected, true);
  assert.strictEqual(c.kub0Revision, 1);
  assert.strictEqual(c.daemonStatus, 'fallback');
  assert.strictEqual(c.restarts, 0);
  c.Health = H; c.health = H.emptyHealth(); c.syncHealthView = () => {};
  c.daemonAvailable = false; c.eventSock = {}; c.shuttingDown = false;
  c.usingFallback = false;
  vm.runInContext(functions.find(x => x[1] === 'currentSocket')[0], c);
  vm.runInContext(functions.find(x => x[1] === 'onEventSocketConnected')[0], c);
  c.policyDaemonMode = 'system';
  c.userKub0.netpolicyEnforcement = {state:'enforcing',enforcing:true,appliedTs:123};
  c.onEventSocketConnected(c.eventSock, 1, false);
  assert.strictEqual(c.policyDaemonMode, 'unknown');
  assert.strictEqual(c.kub0.netpolicyEnforcement.enforcing, false);
  assert.strictEqual(c.kub0Revision, 2);
}
console.log('actual daemon exit during demo and socket disconnect retirement passed');
