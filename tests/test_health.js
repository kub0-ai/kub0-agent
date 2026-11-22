"use strict";
const assert = require("assert");
const H = require("../js/Health.js");
const CM = require("../ConnectionModel.js");

function conn(id, appId, pid, extra) {
  extra = extra || {};
  return JSON.stringify(Object.assign({
    type: "connect",
    ts: 1,
    id: id,
    proto: "tcp",
    inode: 1,
    app: { id: appId || "firefox", name: "Firefox", icon: "", desktop: "", pid: pid || 4402, system: false },
    local: { ip: "10.0.0.2", port: 4 },
    remote: { ip: "1.2.3.4", port: 443 },
    state: "ESTABLISHED",
    country: "US", lat: 1, lon: 2,
    unresolved: false, newNetwork: false, networkKey: "1.2.3.0/24", hostname: ""
  }, extra));
}

function fullRow(overrides) {
  return Object.assign({
    id: "tcp:1:1.2.3.4:443",
    proto: "tcp",
    inode: 1,
    app: { id: "firefox", name: "Firefox", icon: "", desktop: "", pid: 4402, system: false },
    local: { ip: "10.0.0.2", port: 4 },
    remote: { ip: "1.2.3.4", port: 443 },
    state: "ESTABLISHED",
    country: "US",
    lat: 1,
    lon: 2,
    unresolved: false,
    newNetwork: false,
    networkKey: "1.2.3.0/24",
    hostname: ""
  }, overrides || {});
}

function snapshot(list) {
  return JSON.stringify({ type: "snapshot", ts: 1, connections: list || [] });
}

function hello() {
  return JSON.stringify({ type: "hello", version: "0.1.0", pid: 9, coverage: "tcp+connected-udp", rdns: false });
}

function tick(count) {
  return JSON.stringify({ type: "tick", ts: 1, count: count || 0 });
}

function run(health, model, line, now) {
  return H.applyIngest(health, model, line, now, CM.applyLine);
}

function testMissingDaemonNeverDemo() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, false, "kub0d is not available");
  const v = H.derive(h, 1000, { count: 0 });
  assert.strictEqual(v.monitoring, "unavailable");
  assert.strictEqual(v.demo, false);
  assert.strictEqual(v.label, "Off");
  assert.ok(H.barTooltip(v, {}).indexOf("DEMO") === -1);
}

function testDemoFixtureConnectsApplyWithoutSnapshot() {
  const fs = require("fs");
  const path = require("path");
  let h = H.enterDemo(H.emptyHealth(), 1);
  let model = CM.emptyState();
  const text = fs.readFileSync(path.join(__dirname, "fixtures/replay.ndjson"), "utf8");
  let now = 10;
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const out = run(h, model, line, now++);
    h = out.health;
    model = out.model;
  }
  assert.ok(model.count >= 1, "explicit demo must play the connect-stream fixture");
  assert.strictEqual(H.derive(h, now, { count: model.count }).monitoring, "demo");
  assert.strictEqual(H.canDispatchNewBlock(h, now), false);
}

function testDemoOnlyViaEnter() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, false, "kub0d is not available");
  let v = H.derive(h, 1, {});
  assert.notStrictEqual(v.monitoring, "demo");
  h = H.enterDemo(h, 2);
  v = H.derive(h, 2, { count: 3 });
  assert.strictEqual(v.monitoring, "demo");
  assert.strictEqual(v.label, "Demo");
  const tip = H.barTooltip(v, { count: 3, coverage: "TCP + connected UDP" });
  assert.ok(tip.indexOf("DEMO") !== -1, tip);
  assert.ok(tip.indexOf("not this machine") !== -1, tip);
  assert.strictEqual(H.canDispatchNewBlock(h, 2), false, "demo PIDs must not dispatch block-app");
}

function testSocketIsNotFreshness() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 10);
  const v = H.derive(h, 10, { count: 0 });
  assert.strictEqual(v.monitoring, "awaiting_snapshot");
  assert.strictEqual(v.snapshotReady, false);
  assert.strictEqual(v.label, "Wait");
  assert.strictEqual(H.canDispatchNewBlock(h, 10), false);
}

function testHelloDoesNotMakeSnapshotReady() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 10);
  const model = CM.emptyState();
  const out = run(h, model, hello(), 11);
  h = out.health;
  assert.strictEqual(h.snapshotReady, false);
  assert.strictEqual(h.lastFreshAt, 11, "hello is recognized protocol data");
  assert.strictEqual(H.derive(h, 11, {}).monitoring, "awaiting_snapshot");
}

function testEmptySnapshotIsHealthyIdle() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 10);
  const model = CM.emptyState();
  let out = run(h, model, hello(), 11);
  out = run(out.health, out.model, snapshot([]), 12);
  out = run(out.health, out.model, tick(0), 13);
  h = out.health;
  const v = H.derive(h, 13, { count: out.model.count });
  assert.strictEqual(v.monitoring, "current");
  assert.strictEqual(v.idle, true);
  assert.strictEqual(v.label, "Idle");
  assert.strictEqual(out.model.count, 0);
  assert.strictEqual(H.canDispatchNewBlock(h, 13), true);
  const tip = H.barTooltip(v, { count: 0, coverage: "TCP + connected UDP", blockingReady: false });
  assert.ok(tip.indexOf("Receiving updates") !== -1, tip);
  assert.ok(tip.toLowerCase().indexOf("protection active") === -1, tip);
}

function testTickKeepsCurrent() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  let out = run(h, model, snapshot([]), 2);
  out = run(out.health, out.model, tick(0), 2 + 500);
  out = run(out.health, out.model, tick(0), 2 + 1000);
  const v = H.derive(out.health, 2 + 1000, { count: 0 });
  assert.strictEqual(v.monitoring, "current");
}

function testMalformedDoesNotEstablishFreshness() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  let out = run(h, model, snapshot([]), 10);
  h = out.health;
  assert.strictEqual(h.lastFreshAt, 10);
  const rev = out.model.revision;
  out = run(h, out.model, "{not json", 11);
  assert.strictEqual(out.health.lastFreshAt, 10, "malformed line is not freshness");
  assert.ok(out.model.revision > rev, "malformed line may still bump revision");
  assert.strictEqual(out.decision.noteFresh, false);
  const v = H.derive(out.health, 11, { count: 0 });
  assert.strictEqual(v.monitoring, "current");
}

function testUnknownTypeIsNotFreshness() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  let out = run(h, model, snapshot([]), 10);
  out = run(out.health, out.model, JSON.stringify({ type: "mystery", ts: 99 }), 11);
  assert.strictEqual(out.health.lastFreshAt, 10);
  assert.strictEqual(out.decision.noteFresh, false);
}

function testInvalidSnapshotConnectionsNotFresh() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  const out = run(h, model, JSON.stringify({ type: "snapshot", connections: "nope" }), 5);
  assert.strictEqual(out.health.snapshotReady, false);
  assert.strictEqual(out.health.lastFreshAt, 0);
  assert.strictEqual(out.decision.noteFresh, false);
}

function testConnectBeforeSnapshotIsNotActionable() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  let out = run(h, model, hello(), 2);
  out = run(out.health, out.model, conn("tcp:1:1.2.3.4:443", "firefox", 4402), 3);
  assert.strictEqual(out.model.count, 0, "connect before snapshot must not populate actionable rows");
  assert.strictEqual(out.health.snapshotReady, false);
  assert.strictEqual(out.health.lastFreshAt, 3, "recognized connect still proves the feed is arriving");
  assert.strictEqual(H.canDispatchNewBlock(out.health, 3), false);
}

function testStaleAfterThreshold() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  let out = run(h, model, snapshot([fullRow()]), 100);
  h = out.health;
  let v = H.derive(h, 100, { count: out.model.count });
  assert.strictEqual(v.monitoring, "current");
  v = H.derive(h, 100 + H.STALE_MS + 1, { count: out.model.count });
  assert.strictEqual(v.monitoring, "stale");
  assert.strictEqual(v.label, "Stale");
  assert.strictEqual(H.canDispatchNewBlock(h, 100 + H.STALE_MS + 1), false);
  assert.ok(!H.overviewSummaryAllowed(v));
  const tip = H.barTooltip(v, { count: out.model.count, blockingReady: true });
  assert.ok(tip.indexOf("not live") !== -1, tip);
  assert.ok(tip.indexOf("Receiving updates") === -1, tip);
}

function testReconnectNeedsFreshSnapshot() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  let out = run(h, model, snapshot([fullRow()]), 50);
  assert.strictEqual(out.model.count, 1);
  CM.setBlocked(out.model, "firefox", "cgroup");
  h = H.markSocketDown(out.health, "reconnecting to kub0d");
  let v = H.derive(h, 60, { count: out.model.count });
  assert.strictEqual(v.monitoring, "connecting");
  assert.strictEqual(h.snapshotReady, false);
  assert.strictEqual(out.model.count, 1, "last-known rows remain");
  assert.ok(out.model.blocked.firefox, "block map survives socket loss");
  assert.strictEqual(H.canDispatchNewBlock(h, 60), false);
  assert.strictEqual(H.canDispatchUnblock(out.model.blocked, "firefox", true), true);

  h = H.markSocketUp(h, 70);
  v = H.derive(h, 70, { count: out.model.count });
  assert.strictEqual(v.monitoring, "awaiting_snapshot");
  out = run(h, out.model, conn("tcp:9:9.9.9.9:443", "curl", 99), 71);
  assert.ok(!out.model.apps.curl, "incremental connect before snapshot is dropped");
  assert.strictEqual(H.canDispatchNewBlock(out.health, 71), false);

  out = run(out.health, out.model, snapshot([fullRow({
    id: "tcp:2:8.8.8.8:443",
    inode: 2,
    app: { id: "firefox", name: "Firefox", icon: "", desktop: "", pid: 8800, system: false },
    remote: { ip: "8.8.8.8", port: 443 },
    networkKey: "8.8.8.0/24"
  })]), 80);
  h = out.health;
  v = H.derive(h, 80, { count: out.model.count });
  assert.strictEqual(v.monitoring, "current");
  assert.strictEqual(H.canDispatchNewBlock(h, 80), true);
  assert.ok(out.model.blocked.firefox, "snapshot rebuild must not drop session blocks");
  assert.strictEqual(out.model.apps.firefox.pids.indexOf(8800) !== -1, true);
  assert.strictEqual(out.model.apps.firefox.pids.indexOf(4402), -1, "old PIDs must not survive the new snapshot");
}

function testUnblockIndependentOfLiveRow() {
  const blocked = { slack: { mechanism: "cgroup" } };
  assert.strictEqual(H.canDispatchUnblock(blocked, "slack", true), true);
  assert.strictEqual(H.canDispatchUnblock(blocked, "slack", false), false, "still needs helper capability");
  assert.strictEqual(H.canDispatchUnblock({}, "slack", true), false);
  assert.strictEqual(H.canDispatchUnblock(blocked, "firefox", true), false);
  const ids = H.sessionKnownIds(blocked);
  assert.deepStrictEqual(ids, ["slack"]);
}

function testResetObservationsKeepsBlocks() {
  let state = CM.emptyState();
  state = CM.applyLine(state, snapshot([{
    id: "tcp:1:1.2.3.4:443", proto: "tcp",
    app: { id: "firefox", name: "Firefox", pid: 1 },
    remote: { ip: "1.2.3.4", port: 443 }, state: "ESTABLISHED"
  }]), 1);
  CM.setBlocked(state, "firefox", "endpoints");
  CM.resetNetworkObservations(state, 2);
  assert.strictEqual(state.count, 0);
  assert.ok(!state.apps.firefox);
  assert.ok(state.blocked.firefox);
  assert.strictEqual(state.blocked.firefox.mechanism, "endpoints");
  assert.ok(CM.anyBlocked(state));
}

function testReceiveTimeNotEventTs() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  const line = JSON.stringify({ type: "tick", ts: 9999999999999, count: 0 });
  const out = run(h, model, snapshot([]), 40);
  const out2 = run(out.health, out.model, line, 41);
  assert.strictEqual(out2.health.lastFreshAt, 41, "freshness is local receipt time, not event.ts");
}

function testTooltipDoesNotClaimCoverageFromHeartbeat() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketUp(h, 1);
  const model = CM.emptyState();
  const out = run(h, model, snapshot([]), 5);
  const v = H.derive(out.health, 5, { count: 0 });
  const tip = H.barTooltip(v, {
    count: 0,
    coverage: "TCP + connected UDP",
    blockingReady: true,
    anyBlocked: true
  });
  assert.strictEqual(H.wordingForbidden(tip), "", tip);
  assert.ok(tip.indexOf("capability") !== -1, tip);
  assert.ok(tip.indexOf("not a kernel inventory") !== -1, tip);
  assert.ok(tip.indexOf("automatic protection") !== -1, tip);
  assert.ok(H.activityEmptyText(0, "").indexOf("durable incident") !== -1);
}

function testConnectingVsUnavailable() {
  let h = H.emptyHealth();
  h = H.markDaemonAvailable(h, true);
  h = H.markSocketDown(h, "connecting to kub0d");
  assert.strictEqual(H.derive(h, 1, {}).monitoring, "connecting");
  h = H.markDaemonAvailable(h, false, "kub0d not built");
  assert.strictEqual(H.derive(h, 1, {}).monitoring, "unavailable");
  assert.strictEqual(H.derive(h, 1, {}).label, "Off");
}

function testStatusIpcShapeHelpers() {
  const v = H.derive(H.emptyHealth(), 0, {});
  assert.ok(["unavailable", "connecting", "awaiting_snapshot", "current", "stale", "demo"].indexOf(v.monitoring) !== -1);
  assert.strictEqual(typeof v.snapshotReady, "boolean");
  assert.strictEqual(typeof v.ageMs, "number");
  const payload = H.statusPayload(v, {
    count: 4,
    history: 0,
    daemon: "connected",
    blocking: false,
    coverage: "TCP + connected UDP",
    fallback: false,
    helper: true,
    polkit: true,
    needsHelper: false,
    bindOfferNeeded: true,
    bindOfferNote: "Set Super+Alt+S",
    anyBlocked: true,
    sessionKnownBlocks: ["firefox"]
  });
  assert.strictEqual(payload.count, 4, "legacy count preserved");
  assert.strictEqual(payload.daemon, "connected", "legacy daemon preserved");
  assert.strictEqual(payload.blocking, false, "legacy blocking is capability, not anyBlocked");
  assert.strictEqual(payload.anyBlocked, true);
  assert.strictEqual(payload.fallback, false);
  assert.strictEqual(payload.monitoring, "unavailable");
  assert.strictEqual(payload.blockingReady, false);
  assert.deepStrictEqual(payload.sessionKnownBlocks, ["firefox"]);
}

testMissingDaemonNeverDemo();
testDemoOnlyViaEnter();
testDemoFixtureConnectsApplyWithoutSnapshot();
testSocketIsNotFreshness();
testHelloDoesNotMakeSnapshotReady();
testEmptySnapshotIsHealthyIdle();
testTickKeepsCurrent();
testMalformedDoesNotEstablishFreshness();
testUnknownTypeIsNotFreshness();
testInvalidSnapshotConnectionsNotFresh();
testConnectBeforeSnapshotIsNotActionable();
testStaleAfterThreshold();
testReconnectNeedsFreshSnapshot();
testUnblockIndependentOfLiveRow();
testResetObservationsKeepsBlocks();
testReceiveTimeNotEventTs();
testTooltipDoesNotClaimCoverageFromHeartbeat();
testConnectingVsUnavailable();
testStatusIpcShapeHelpers();

function populated() {
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

function testInvalidEventsDoNotRefreshOrErase() {
  const cases = [
    ["missing snapshot payload", { type: "snapshot", ts: 5000 }],
    ["null snapshot payload", { type: "snapshot", ts: 5000, connections: null }],
    ["null snapshot row", { type: "snapshot", ts: 5000, connections: [null] }],
    ["invalid heartbeat count", { type: "tick", ts: 5000, count: "not-a-number" }],
    ["object prototype event name", { type: "toString" }],
    ["incomplete snapshot row", { type: "snapshot", ts: 5000, connections: [{ id: "incomplete" }] }],
    ["invalid heartbeat timestamp", { type: "tick", ts: "not-a-number", count: 1 }],
    ["missing hello payload", { type: "hello" }],
    ["missing status payload", { type: "status" }],
    ["invalid connection identity", { type: "connect", id: [], app: null }]
  ];
  for (const [name, event] of cases) {
    const before = populated();
    const out = H.applyIngest(before.health, before.model, JSON.stringify(event), 5000, CM.applyLine);
    assert.strictEqual(out.health.lastFreshAt, 1000, name + " refreshed health");
    assert.strictEqual(out.model.count, 1, name + " changed last-known observations");
    assert.strictEqual(out.decision.noteFresh, false, name + " noted freshness");
  }
}

function testOwnKeyTypeMembership() {
  assert.strictEqual(H.isKnownType("toString"), false);
  assert.strictEqual(H.isKnownType("snapshot"), true);
  assert.strictEqual(H.isKnownType("tick"), true);
  const kind = H.classifyLine(JSON.stringify({ type: "toString" }));
  assert.strictEqual(kind.ok, false);
  assert.strictEqual(kind.unknown, true);
}

function testReplayFixtureIsValidTraffic() {
  const fs = require("fs");
  const path = require("path");
  const text = fs.readFileSync(path.join(__dirname, "fixtures/replay.ndjson"), "utf8");
  for (const line of text.split("\n")) {
    if (!line.trim() || line.trim().charAt(0) === "#") continue;
    const kind = H.classifyLine(line);
    assert.strictEqual(kind.ok, true, "replay line rejected: " + line);
  }
}

function testValidEmptySnapshotAndIdleTick() {
  let h = H.markSocketUp(H.markDaemonAvailable(H.emptyHealth(), true), 1);
  let model = CM.emptyState();
  let out = run(h, model, snapshot([]), 2);
  out = run(out.health, out.model, tick(0), 3);
  assert.strictEqual(out.health.snapshotReady, true);
  assert.strictEqual(out.health.lastFreshAt, 3);
  assert.strictEqual(out.model.count, 0);
  assert.strictEqual(H.derive(out.health, 3, { count: 0 }).monitoring, "current");
}

function testReconnectHelloDoesNotRejuvenateObservationAge() {
  const before = populated();
  assert.strictEqual(before.health.lastSnapshotAt, 1000);
  let h = H.markSocketDown(before.health, "reconnecting to kub0d");
  h = H.markSocketUp(h, 4000);
  const out = run(h, before.model, hello(), 5000);
  assert.strictEqual(out.health.lastFreshAt, 5000, "hello is feed receipt");
  assert.strictEqual(out.health.lastSnapshotAt, 1000, "hello must not move snapshot age");
  assert.strictEqual(out.model.count, 1, "retained row still present");
  const v = H.derive(out.health, 5000, { count: 1 });
  assert.strictEqual(v.monitoring, "awaiting_snapshot");
  assert.strictEqual(v.observationAgeMs, 4000);
  assert.notStrictEqual(H.formatAge(v.observationAgeMs), "just now");
  const tip = H.barTooltip(v, { count: 1, coverage: "TCP + connected UDP" });
  assert.ok(tip.indexOf("just now") === -1, tip);
  assert.ok(tip.indexOf(H.formatAge(4000)) !== -1, tip);
}

function testDemoIsolatesObservationsAndKeepsSessionBlocks() {
  let h = H.markSocketUp(H.markDaemonAvailable(H.emptyHealth(), true), 1);
  let model = populated().model;
  CM.setBlocked(model, "fixture-app", "cgroup");
  assert.strictEqual(model.count, 1);
  h = H.enterDemo(h, 10);
  CM.resetNetworkObservations(model, 10);
  assert.strictEqual(model.count, 0);
  assert.ok(!model.apps["fixture-app"]);
  assert.ok(model.blocked["fixture-app"]);
  const demoSnap = JSON.stringify({
    type: "snapshot", ts: 11, connections: [{
      id: "demo-flow", proto: "tcp", inode: 1,
      app: { id: "manager-demo", name: "Demo", icon: "", desktop: "", pid: 9, system: false },
      local: { ip: "192.0.2.254", port: 1 },
      remote: { ip: "192.0.2.1", port: 443 },
      state: "ESTABLISHED", country: "", lat: 0, lon: 0,
      unresolved: false, newNetwork: false, networkKey: "192.0.2.0/24", hostname: ""
    }]
  });
  let out = run(h, model, demoSnap, 11);
  assert.ok(out.model.apps["manager-demo"]);
  h = H.exitDemo(out.health);
  CM.resetNetworkObservations(out.model, 12);
  assert.strictEqual(out.model.count, 0);
  assert.ok(!out.model.apps["manager-demo"]);
  assert.ok(out.model.blocked["fixture-app"]);
  assert.strictEqual(h.demo, false);
  assert.strictEqual(h.lastSnapshotAt, 0);
}

function testBlockShortcutScope() {
  assert.strictEqual(H.blockShortcutAllowed("apps", "fixture-2", ["fixture-2"], []), true);
  assert.strictEqual(H.blockShortcutAllowed("apps", "fixture-2", ["fixture-0"], []), false);
  assert.strictEqual(H.blockShortcutAllowed("protection", "fixture-2", ["fixture-2"], []), false);
  assert.strictEqual(H.blockShortcutAllowed("protection", "gone", ["fixture-2"], ["gone"]), true);
  assert.strictEqual(H.blockShortcutAllowed("overview", "fixture-2", ["fixture-2"], []), false);
  assert.strictEqual(H.blockShortcutAllowed("apps", "", ["fixture-2"], []), false);
}

function testPanelDropsFalseNegativeBlockCopy() {
  const fs = require("fs");
  const path = require("path");
  const panel = fs.readFileSync(path.join(__dirname, "../Panel.qml"), "utf8");
  assert.strictEqual(
    (panel.match(/Not blocked — Block app targets this running process tree/g) || []).length,
    0
  );
  assert.ok(panel.indexOf("No block remembered this session") !== -1);
}

testInvalidEventsDoNotRefreshOrErase();
testOwnKeyTypeMembership();
testReplayFixtureIsValidTraffic();
testValidEmptySnapshotAndIdleTick();
testReconnectHelloDoesNotRejuvenateObservationAge();
testDemoIsolatesObservationsAndKeepsSessionBlocks();
testBlockShortcutScope();
testPanelDropsFalseNegativeBlockCopy();

function clone(v) {
  return JSON.parse(JSON.stringify(v));
}

function deletePath(obj, path) {
  const parts = path.split(".");
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    cur = cur[parts[i]];
    if (!cur)
      return obj;
  }
  delete cur[parts[parts.length - 1]];
  return obj;
}

function testRequiredFieldDeletionsAreRejected() {
  const required = [
    "id", "proto", "inode", "app", "local", "remote", "state",
    "app.id", "app.name", "app.icon", "app.desktop", "app.pid",
    "local.ip", "local.port", "remote.ip", "remote.port"
  ];
  const before = populated();
  for (const path of required) {
    const row = deletePath(clone(fullRow()), path);
    const out = H.applyIngest(
      before.health, before.model,
      JSON.stringify({ type: "snapshot", ts: 2000, connections: [row] }),
      2000, CM.applyLine
    );
    assert.strictEqual(out.decision.noteFresh, false, path + " noted freshness");
    assert.strictEqual(out.decision.applyModel, false, path + " applied");
    assert.strictEqual(out.health.lastFreshAt, 1000, path + " refreshed");
    assert.strictEqual(out.model.count, 1, path + " changed observations");
    assert.ok(out.model.apps["fixture-app"], path + " replaced apps");
  }
}

function testWrongTypesAndBoundsAreRejected() {
  const cases = [
    ["port 65536", fullRow({ remote: { ip: "192.0.2.2", port: 65536 } })],
    ["port -1", fullRow({ remote: { ip: "192.0.2.2", port: -1 } })],
    ["port 1.5", fullRow({ remote: { ip: "192.0.2.2", port: 1.5 } })],
    ["local port 65536", fullRow({ local: { ip: "10.0.0.2", port: 65536 } })],
    ["pid 4294967296", fullRow({ app: { id: "firefox", name: "Firefox", icon: "", desktop: "", pid: 4294967296, system: false } })],
    ["pid -1", fullRow({ app: { id: "firefox", name: "Firefox", icon: "", desktop: "", pid: -1, system: false } })],
    ["inode -1", fullRow({ inode: -1 })],
    ["inode 1.2", fullRow({ inode: 1.2 })],
    ["lat string", fullRow({ lat: "1" })],
    ["system string", fullRow({ app: { id: "firefox", name: "Firefox", icon: "", desktop: "", pid: 1, system: "no" } })],
    ["app id number", fullRow({ app: { id: 1, name: "Firefox", icon: "", desktop: "", pid: 1, system: false } })],
    ["local null", fullRow({ local: null })],
    ["remote missing port", (function () { const r = fullRow(); delete r.remote.port; return r; })()]
  ];
  const before = populated();
  for (const [name, row] of cases) {
    const out = H.applyIngest(
      before.health, before.model,
      JSON.stringify({ type: "snapshot", ts: 2000, connections: [row] }),
      2000, CM.applyLine
    );
    assert.strictEqual(out.decision.applyModel, false, name + " applied");
    assert.strictEqual(out.health.lastFreshAt, 1000, name + " refreshed");
    assert.strictEqual(out.model.count, 1, name + " changed observations");
    assert.strictEqual(H.derive(out.health, 2000, {}).monitoring, "current", name + " monitoring");
  }
}

function testValidBoundsAndExtrasAreAccepted() {
  const extras = fullRow({
    remote: { ip: "192.0.2.2", port: 65535 },
    local: { ip: "10.0.0.2", port: 0 },
    inode: 0,
    extraField: "allowed",
    app: { id: "firefox", name: "Firefox", icon: "", desktop: "", pid: 0, system: false, extra: true }
  });
  delete extras.country;
  delete extras.hostname;
  const before = populated();
  const out = H.applyIngest(
    before.health, before.model,
    JSON.stringify({ type: "snapshot", ts: 2000, connections: [extras], unused: 1 }),
    2000, CM.applyLine
  );
  assert.strictEqual(out.decision.applyModel, true);
  assert.strictEqual(out.decision.noteFresh, true);
  assert.strictEqual(out.health.lastFreshAt, 2000);
  assert.strictEqual(out.model.connections[extras.id].remote.port, 65535);
}

function testEventRequiredFields() {
  const before = populated();
  const events = [
    { type: "hello", version: "1", coverage: "tcp+connected-udp", rdns: false },
    { type: "hello", version: "1", pid: 1, rdns: false },
    { type: "tick", ts: 1 },
    { type: "tick", count: 0 },
    { type: "disconnect", id: "x" },
    { type: "disconnect", ts: 1 },
    { type: "digest", ts: 1, newNetworks: 1 },
    { type: "digest", ts: 1, keys: [] },
    { type: "status" },
    { type: "snapshot", connections: [] },
    { type: "connect", ts: 1, id: "tcp:1:1.2.3.4:443", proto: "tcp" }
  ];
  for (const ev of events) {
    const out = H.applyIngest(before.health, before.model, JSON.stringify(ev), 5000, CM.applyLine);
    assert.strictEqual(out.decision.noteFresh, false, JSON.stringify(ev) + " noted freshness");
    assert.strictEqual(out.model.count, 1, JSON.stringify(ev) + " changed model");
  }
}

function testMalformedDoesNotErasePopulated() {
  const before = populated();
  const rev = before.model.revision;
  const out = H.applyIngest(before.health, before.model, "{nope", 5000, CM.applyLine);
  assert.strictEqual(out.health.lastFreshAt, 1000);
  assert.strictEqual(out.model.count, 1);
  assert.ok(out.model.revision > rev);
  assert.strictEqual(out.model.lastError, "bad json");
}

function testPrototypeAppIdsIngestAtomically() {
  const before = populated();
  const prior = JSON.stringify(before.model.apps);
  for (const id of ["toString", "constructor", "__proto__", "hasOwnProperty", "valueOf"]) {
    const row = fullRow({
      id: "flow-" + id,
      app: { id: id, name: id, icon: "", desktop: "", pid: 9, system: false }
    });
    const out = H.applyIngest(
      before.health, before.model,
      JSON.stringify({ type: "snapshot", ts: 2000, connections: [row] }),
      2000, CM.applyLine
    );
    assert.strictEqual(out.decision.applyModel, true, id + " rejected");
    assert.strictEqual(out.decision.noteFresh, true, id + " not fresh");
    assert.ok(out.model.apps[id], id + " missing from apps");
    assert.strictEqual(out.model.apps[id].id, id);
    assert.ok(Array.isArray(out.model.apps[id].connections));
    assert.strictEqual(out.model.apps[id].connections.length, 1);
    assert.ok(!out.model.apps["fixture-app"], id + " left prior apps");
    assert.strictEqual(out.model.count, 1);
  }
  assert.strictEqual(JSON.stringify(before.model.apps), prior, "source model mutated");
}

function testMixedInvalidSnapshotDoesNotApply() {
  const before = populated();
  const out = H.applyIngest(
    before.health, before.model,
    JSON.stringify({
      type: "snapshot",
      ts: 2000,
      connections: [fullRow(), { id: "malformed", proto: "tcp", app: {} }]
    }),
    2000, CM.applyLine
  );
  assert.strictEqual(out.decision.applyModel, false);
  assert.strictEqual(out.model.count, 1);
  assert.ok(out.model.apps["fixture-app"]);
  assert.strictEqual(out.health.lastFreshAt, 1000);
}

function testRetainSelectedIdNeverRetargets() {
  assert.strictEqual(H.retainSelectedId("fixture-3", ["fixture-4", "fixture-5"]), "fixture-3");
  assert.strictEqual(H.retainSelectedId("fixture-3", ["fixture-3"]), "fixture-3");
  assert.strictEqual(H.retainSelectedId("", ["fixture-0"]), "fixture-0");
  assert.strictEqual(H.retainSelectedId("", []), "");
  assert.strictEqual(H.retainSelectedId("gone", []), "gone");
}

function testAcceptSearchSelection() {
  assert.strictEqual(H.acceptSearchSelection("fixture-1", ["fixture-0", "fixture-1"]), "fixture-1");
  assert.strictEqual(H.acceptSearchSelection("fixture-2", ["fixture-0"]), "fixture-0");
  assert.strictEqual(H.acceptSearchSelection("fixture-2", []), "fixture-2");
  assert.strictEqual(H.acceptSearchSelection("", ["fixture-0"]), "fixture-0");
  assert.strictEqual(H.acceptSearchSelection("", []), "");
  assert.strictEqual(H.acceptSearchSelection("gone", []), "gone");
}

function testBarLabelsCoverMonitoringStates() {
  const labels = H.barStateLabels();
  assert.deepStrictEqual(labels, ["Off", "…", "Wait", "Idle", "On", "Stale", "Demo", "Paused"]);
  const states = [
    ["unavailable", false],
    ["connecting", false],
    ["awaiting_snapshot", false],
    ["current", true],
    ["current", false],
    ["stale", false],
    ["demo", false]
  ];
  for (const [monitoring, idle] of states) {
    const label = H.barLabel({ monitoring: monitoring, idle: idle });
    assert.ok(labels.indexOf(label) !== -1, monitoring + " -> " + label);
  }
}

// The bar used to render the state as a WORD, and reserved the width of the widest
// one ("Stale"/"Demo") on every draw — which is what left dead space to the right of
// a short state like "On". It is a single glyph now. The invariant that mattered
// survives in translated form: every state the service can emit must still have a
// distinct visual, so none of them can render as a blank or a duplicate.
// The bar's label came from monitoring alone, so with a pause rule live it read
// "On" beside the wall glyph ("fully protecting") while every block was skipped.
function testBarSaysPausedOverAPauseRule() {
  const fs = require("fs");
  const path = require("path");
  assert.strictEqual(H.barPostureLabel("On", true), "Paused");
  assert.strictEqual(H.barPostureLabel("Idle", true), "Paused");
  assert.strictEqual(H.barPostureLabel("On", false), "On");
  assert.strictEqual(H.barPostureLabel("Idle", undefined), "Idle");
  // Degraded monitoring already avoids the wall; its own label says more.
  for (const l of ["Off", "…", "Wait", "Stale", "Demo"])
    assert.strictEqual(H.barPostureLabel(l, true), l);
  const bar = fs.readFileSync(path.join(__dirname, "../BarWidget.qml"), "utf8");
  assert.ok(/Health\.barPostureLabel\(.*, *enforcementPaused\)/.test(bar),
    "bar stateLabel does not read enforcementPaused");
  // The call can be right while the property behind it is misspelled:
  // `vallum.enforcementPause` is undefined, `=== true` is then always false,
  // and the bar goes back to painting the wall over a pause rule.
  const read = bar.match(/property bool enforcementPaused: *vallum \? *vallum\.(\w+) === true/);
  assert.ok(read, "bar no longer derives enforcementPaused from the service");
  const svc = fs.readFileSync(path.join(__dirname, "../Service.qml"), "utf8");
  assert.ok(new RegExp("property bool " + read[1] + "\\b").test(svc),
    "bar reads vallum." + read[1] + ", which Service.qml does not declare");
}

function testBarGlyphCoversEveryState() {
  const fs = require("fs");
  const path = require("path");
  const bar = fs.readFileSync(path.join(__dirname, "../BarWidget.qml"), "utf8");

  // Codepoints, not pasted glyphs — a mojibaked source file must fail loudly here
  // rather than silently matching nothing.
  //
  // ⚠️ This pins IDENTITY, not MEANING. It can only prove the constant still says
  // what this table says; it cannot tell you the codepoint draws the right picture,
  // because node has no access to the font's cmap. glyphShieldOff was U+F099D here
  // for exactly that reason — present in the face, asserted by this test, and
  // resolving to md-shield_LOCK (a padlock) on a bar reporting that protection is
  // OFF. When you change a row, resolve the new value against the face itself:
  //   python3 -c "from fontTools.ttLib import TTFont; \
  //     print(TTFont('/usr/share/fonts/TTF/JetBrainsMonoNerdFont-Regular.ttf') \
  //       .getBestCmap()[0xF099E])"   # -> md-shield_off
  const glyphs = {
    glyphWall: 0xF07FE,        // md-wall
    glyphShield: 0xF0498,      // md-shield
    glyphShieldPaused: 0xF0499, // md-shield_outline
    glyphShieldOff: 0xF099E,   // md-shield_off  (NOT F099D = md-shield_lock)
    glyphShieldAlert: 0xF0ECC  // md-shield_alert
  };
  const seen = new Set();
  for (const [name, cp] of Object.entries(glyphs)) {
    const ch = String.fromCodePoint(cp);
    assert.ok(bar.indexOf(name + ": \"" + ch + "\"") !== -1,
      name + " missing or not U+" + cp.toString(16).toUpperCase());
    assert.ok(!seen.has(ch), "two states share glyph U+" + cp.toString(16).toUpperCase());
    seen.add(ch);
    // Declared but never branched to would be a dead state.
    assert.ok(bar.split(name).length - 1 >= 2, name + " declared but never returned");
  }

  // Every monitoring state the health layer can produce must be reachable in the
  // glyph binding — either by name, or via the stateLabel it maps to.
  for (const token of ["off", "stale", "unavailable", "demo", "on", "paused"])
    assert.ok(bar.indexOf('"' + token + '"') !== -1, "glyph binding never tests " + token);

  // The wall says "fully protecting", so exactly one path may reach it: a
  // stateLabel of On. barPostureLabel is what keeps a paused host off that path.
  assert.strictEqual(bar.split("return glyphWall").length - 1, 1, "a second path reaches the wall glyph");
  assert.ok(/if \(s === "on"\)\s*return glyphWall/.test(bar), "the wall is not gated on On");
  // Paused and Idle drew the same filled shield, so a pause was invisible
  // until you hovered for the tooltip.
  assert.ok(/if \(s === "paused"\)\s*return glyphShieldPaused/.test(bar), "Paused has no glyph of its own");
  for (const l of H.barStateLabels())
    assert.notStrictEqual(H.barPostureLabel(l, true), "On", l + " reads On while paused");

  // Pins the fix: reintroducing a reserved label width brings the right-side gap back.
  assert.strictEqual(bar.indexOf("reservedLabelWidth"), -1, "reserved label width is back");
  assert.strictEqual(bar.indexOf("TextMetrics"), -1, "TextMetrics is back");
}

function testPanelHasNoFilteredRetarget() {
  const fs = require("fs");
  const path = require("path");
  const panel = fs.readFileSync(path.join(__dirname, "../Panel.qml"), "utf8");
  const n = (panel.match(/else if .*selectedAppId.*idInApps.*searchQuery/g) || []).length;
  assert.strictEqual(n, 0);
}

function testRuntimeFixtureIsBundled() {
  const fs = require("fs");
  const path = require("path");
  const runner = fs.readFileSync(path.join(__dirname, "qml/run-runtime.sh"), "utf8");
  assert.strictEqual(/\/home\/[A-Za-z0-9_]/.test(runner), false, "the runner names no home directory");
  assert.ok(runner.indexOf("tests/qml/fake-plugin") !== -1);
  assert.ok(fs.existsSync(path.join(__dirname, "qml/fake-plugin/bin/kub0d")));
  assert.ok(fs.existsSync(path.join(__dirname, "qml/fake-plugin/bin/pkexec")));
  assert.ok(fs.existsSync(path.join(__dirname, "qml/fake-plugin/bin/hyprctl")));
}

testRequiredFieldDeletionsAreRejected();
testWrongTypesAndBoundsAreRejected();
testValidBoundsAndExtrasAreAccepted();
testEventRequiredFields();
testMalformedDoesNotErasePopulated();
testPrototypeAppIdsIngestAtomically();
testMixedInvalidSnapshotDoesNotApply();
testRetainSelectedIdNeverRetargets();
testAcceptSearchSelection();
testBarLabelsCoverMonitoringStates();
testBarSaysPausedOverAPauseRule();
testBarGlyphCoversEveryState();
testPanelHasNoFilteredRetarget();
testRuntimeFixtureIsBundled();
console.log("test_health.js ok");
