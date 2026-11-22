"use strict";
const assert = require("assert");
const path = require("path");
const fs = require("fs");
const CM = require("../ConnectionModel.js");

function applyFixture() {
  const text = fs.readFileSync(path.join(__dirname, "fixtures/replay.ndjson"), "utf8");
  let state = CM.emptyState();
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    state = CM.applyLine(state, line, 5000);
  }
  return state;
}

function testGrouping() {
  const state = applyFixture();
  assert.ok(state.apps.firefox, "firefox grouped");
  assert.ok(state.apps.spotify, "spotify grouped");
  // slack's flows disconnect at the end of the fixture; grouping is still
  // visible mid-stream (covered by drawable/filter tests using earlier lines).
  // 40 chrome-style: two firefox pids still one app
  const pids = state.apps.firefox.pids;
  assert.ok(pids.indexOf(4402) !== -1);
  assert.ok(pids.indexOf(4403) !== -1);
  assert.strictEqual(state.apps.firefox.id, "firefox");
}

function testUnresolvedNeverDrawable() {
  const state = applyFixture();
  const arcs = CM.drawableArcs(state.connections, { lat: 0, lon: 0 }, 40);
  for (const a of arcs) {
    assert.strictEqual(a.unresolved, false);
    assert.ok(a.country, "drawable arc has country");
  }
  const unresolved = Object.values(state.connections).filter((c) => c.unresolved);
  assert.ok(unresolved.length >= 1, "fixture has unresolved UDP");
}

function testNetworkKey() {
  assert.strictEqual(CM.networkKey("142.250.190.14"), "142.250.190.0/24");
  assert.strictEqual(CM.networkKey("142.250.190.99"), "142.250.190.0/24");
  assert.strictEqual(CM.networkKey("8.8.8.8"), "8.8.8.0/24");
  const k = CM.networkKey("2001:db8:abcd:12::1");
  assert.ok(k.endsWith("/48"), k);
  assert.strictEqual(CM.networkKey("2001:db8:abcd:99::ffff"), k);
}

function testDisconnect() {
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect",
    id: "tcp:1:1.2.3.4:443",
    proto: "tcp",
    app: { id: "curl", name: "curl", icon: "curl", desktop: "", pid: 9, system: false },
    local: { ip: "10.0.0.2", port: 4 },
    remote: { ip: "1.2.3.4", port: 443 },
    country: "US", lat: 1, lon: 2, unresolved: false, newNetwork: true, networkKey: "1.2.3.0/24"
  }), 1);
  assert.strictEqual(state.count, 1);
  assert.strictEqual(state.pulse, true);
  state = CM.applyLine(state, JSON.stringify({ type: "disconnect", id: "tcp:1:1.2.3.4:443" }), 2);
  assert.strictEqual(state.count, 0);
  assert.ok(!state.apps.curl);
}

function testPort53NoPulseRequirement() {
  // Pulse is driven by newNetwork from the daemon; daemon sets it false for :53.
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect",
    id: "udp:1:8.8.8.8:53",
    proto: "udp",
    app: { id: "firefox", name: "Firefox", pid: 1 },
    remote: { ip: "8.8.8.8", port: 53 },
    country: "US", lat: 37, lon: -95, unresolved: false, newNetwork: false, networkKey: "8.8.8.0/24"
  }), 1);
  assert.strictEqual(state.pulse, false);
}

function testDigest() {
  const state = applyFixture();
  assert.ok(state.digestText.indexOf("new network") !== -1, state.digestText);
}

function testFilter() {
  const state = applyFixture();
  const se = CM.filterApps(state.ordered, "sweden");
  // country is US/SE codes, not names — search "SE" or spotify
  const sp = CM.filterApps(state.ordered, "spot");
  assert.strictEqual(sp.length, 1);
  assert.strictEqual(sp[0].id, "spotify");
  const us = CM.filterApps(state.ordered, "SE");
  assert.ok(us.some((a) => a.id === "spotify"));
}

function testBlockBadge() {
  let state = applyFixture();
  CM.setBlocked(state, "firefox", "cgroup");
  assert.strictEqual(state.apps.firefox.blocked, true);
  assert.strictEqual(state.apps.firefox.mechanism, "cgroup");
  assert.ok(CM.anyBlocked(state));
  CM.setBlocked(state, "firefox", "");
  assert.strictEqual(state.apps.firefox.blocked, false);
}

function testTimeWaitNotInFixtureLiveSet() {
  // TIME_WAIT is a parser concern; the model only sees what the daemon emits.
  const state = applyFixture();
  for (const c of Object.values(state.connections)) {
    assert.notStrictEqual(c.state, "TIME_WAIT");
  }
}

testGrouping();
testUnresolvedNeverDrawable();
testNetworkKey();
testDisconnect();
testPort53NoPulseRequirement();
testDigest();
testFilter();
function testIsBlockable() {
  assert.strictEqual(CM.isBlockable({ id: "firefox", system: false }), true);
  assert.strictEqual(CM.isBlockable({ id: "system", system: true }), false);
  assert.strictEqual(CM.isBlockable({ id: "system" }), false);
  assert.strictEqual(CM.isBlockable({ id: "unknown" }), false);
  assert.strictEqual(CM.isBlockable({ id: "Unknown", system: false }), false);
  assert.strictEqual(CM.isBlockable(null), false);
}

// --- Live / History split (SCHEMA 2.4) ------------------------------------

function testIsLiveAcrossSourceVocabularies() {
  // procfs, the DEFAULT source, emits raw /proc/net/tcp names. Anything the
  // kernel still lists is a socket the app still holds, teardown included.
  for (const s of ["ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
                   "FIN_WAIT2", "CLOSE_WAIT", "LAST_ACK", "CLOSING"])
    assert.strictEqual(CM.isLive({ state: s }), true, "procfs " + s + " is live");

  // CLOSE is LIVE, and this assertion is a regression pin, not a detail.
  // sample() is TCP-only (daemon/src/main.rs:680), so TCP CLOSE never reaches
  // the panel — but an unconnected UDP socket has no remote endpoint and parses
  // as CLOSE (daemon/src/procfs.rs:259) while being a perfectly live listener.
  // Putting CLOSE in the deny-list hid live sockets from the pill.
  assert.strictEqual(CM.isLive({ state: "CLOSE" }), true,
    "CLOSE is live unconnected UDP, not a finished conversation");

  // opensnitch emits exactly three values; Flow::to_legacy projects FlowState
  // down to them. Every backfilled row is CLOSED.
  assert.strictEqual(CM.isLive({ state: "OBSERVED" }), true);
  assert.strictEqual(CM.isLive({ state: "CLOSED" }), false);

  // The direction of the default is the decision, so pin it. This is a
  // deny-list: a state no source has emitted yet renders as live, which is
  // visible-and-wrong. Flipping this to an allow-list makes unknown states
  // vanish silently, which is the defect the split exists to fix.
  assert.strictEqual(CM.isLive({ state: "" }), true, "absent state is live");
  assert.strictEqual(CM.isLive({}), true, "missing field is live");
  assert.strictEqual(CM.isLive({ state: "SOME_FUTURE_EBPF_STATE" }), true);
  assert.strictEqual(CM.isLive({ state: "closed" }), false, "matched case-insensitively");
  assert.strictEqual(CM.isLive(null), false);
}

function testBackfillNeverInflatesThePill() {
  // The defect: the OpenSnitch driver broadcasts an Event::Connect per
  // backfilled row and never an Event::Disconnect, so a day of finished history
  // was counted under a pill whose tooltip reads "live connections"
  // (daemon/src/main.rs run_opensnitch, docs/SCHEMA.md 5.1).
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect", id: "tcp:9:93.184.216.34:443", proto: "tcp",
    app: { id: "curl", name: "curl", pid: 77 },
    remote: { ip: "93.184.216.34", port: 443 },
    state: "CLOSED", country: "US", lat: 38, lon: -97,
    unresolved: false, newNetwork: false, networkKey: "93.184.216.0/24"
  }), 10);

  assert.strictEqual(state.count, 0, "a backfilled row must not count as live");
  assert.strictEqual(state.historyCount, 1);
  assert.strictEqual(state.ordered.length, 0, "and must not sit on the Live tab");
  assert.strictEqual(state.historyOrdered.length, 1);
  assert.strictEqual(state.historyOrdered[0].id, "curl");
  assert.ok(state.connections["tcp:9:93.184.216.34:443"], "the row is filed, not dropped");

  // The map makes the same claim as the pill, so it gets the same rule.
  const origin = { lat: 0, lon: 0 };
  assert.strictEqual(CM.drawableArcs(state.connections, origin, 40).length, 0);
  assert.strictEqual(CM.drawableArcs(state.connections, origin, 40, true).length, 1);
}

function testTeardownStaysOnTheLiveTab() {
  // The default source must not lose rows to the split. CLOSE_WAIT is a socket
  // the app still holds with data still readable — ending, not ended.
  let state = CM.emptyState();
  ["ESTABLISHED", "CLOSE_WAIT", "SYN_SENT"].forEach((s, i) => {
    state = CM.applyLine(state, JSON.stringify({
      type: "connect", id: "tcp:" + i + ":1.2.3.4:443", proto: "tcp",
      app: { id: "firefox", name: "Firefox", pid: 1 },
      remote: { ip: "1.2.3.4", port: 443 }, state: s,
      country: "US", lat: 1, lon: 2,
      unresolved: false, newNetwork: false, networkKey: "1.2.3.0/24"
    }), 20);
  });
  assert.strictEqual(state.count, 3, "no live TCP state is lost to History");
  assert.strictEqual(state.historyCount, 0);
}

function testProcfsContributesNothingToHistory() {
  // procfs never reports a finished conversation. LISTEN, TIME_WAIT and TCP
  // CLOSE are dropped before a Connection is built, and a TCP conversation that
  // ends arrives as `disconnect`, which deletes the row. The replay fixture is
  // a procfs capture, so History must be empty — including its one CLOSE row,
  // which is firefox's live 0.0.0.0:5353 mDNS listener.
  const state = applyFixture();
  assert.strictEqual(state.historyCount, 0, "a procfs capture has no history");
  assert.ok(Object.values(state.connections).some((c) => c.state === "CLOSE"),
    "fixture still exercises the unconnected-UDP CLOSE path");
  assert.strictEqual(state.count + state.historyCount,
    Object.keys(state.connections).length, "every row lands on exactly one tab");
  for (const a of state.ordered)
    for (const c of a.connections)
      assert.ok(CM.isLive(c), "Live tab holds only live rows");
  for (const a of state.historyOrdered)
    for (const c of a.connections)
      assert.ok(!CM.isLive(c), "History holds only finished rows");
}

function testUnconnectedUdpStaysOnLive() {
  // The refutation this pins: an mDNS listener is a live kernel socket that
  // procfs reports as CLOSE because it has no remote endpoint. It is unresolved
  // and never drawn as an arc, but it is counted, and the split must not have
  // quietly changed that.
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect", id: "udp:7:0.0.0.0:0", proto: "udp",
    app: { id: "firefox", name: "Firefox", pid: 4402 },
    local: { ip: "0.0.0.0", port: 5353 }, remote: { ip: "0.0.0.0", port: 0 },
    state: "CLOSE", country: "", lat: 0, lon: 0,
    unresolved: true, newNetwork: false, networkKey: ""
  }), 50);
  assert.strictEqual(state.count, 1, "a live UDP listener counts toward the pill");
  assert.strictEqual(state.historyCount, 0);
}

function testBackfillNeverPulsesTheBar() {
  // The amber pulse means "a network prefix never seen before", present tense,
  // and enrich() marks historical rows new_network from the same seen-set as
  // live ones. The away digest may count them; the pulse may not.
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect", id: "tcp:3:203.0.113.9:443", proto: "tcp",
    app: { id: "curl", name: "curl", pid: 8 },
    remote: { ip: "203.0.113.9", port: 443 }, state: "CLOSED",
    country: "US", lat: 1, lon: 2,
    unresolved: false, newNetwork: true, networkKey: "203.0.113.0/24"
  }), 60);
  assert.strictEqual(state.pulse, false, "a finished row must not pulse the bar");
  assert.ok(state.digestText.indexOf("new network") !== -1,
    "but it does count toward the away digest, which is a question about the past");
}

function testTickNeverOverwritesTheLiveCount() {
  // A tick carries the daemon's tally of every row it tracks, in any state.
  // Letting it write state.count puts history back under the "live connections"
  // label through a heartbeat — the same defect, a different writer.
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "connect", id: "tcp:1:1.2.3.4:443", proto: "tcp",
    app: { id: "curl", name: "curl", pid: 5 },
    remote: { ip: "1.2.3.4", port: 443 }, state: "CLOSED",
    country: "US", lat: 1, lon: 2,
    unresolved: false, newNetwork: false, networkKey: "1.2.3.0/24"
  }), 40);
  assert.strictEqual(state.count, 0);

  state = CM.applyLine(state, JSON.stringify({ type: "tick", count: 1 }), 41);
  assert.strictEqual(state.count, 0, "a tick must not resurrect a history row");
  assert.strictEqual(state.historyCount, 1);
  assert.strictEqual(state.sourceCount, 1, "the daemon's tally is kept, separately");
}

function testBlockBadgeReachesBothTabs() {
  // An app can hold a live socket and own finished rows at the same time.
  // Blocking is a statement about the app, so the badge belongs on both.
  let state = CM.emptyState();
  ["ESTABLISHED", "CLOSED"].forEach((s, i) => {
    state = CM.applyLine(state, JSON.stringify({
      type: "connect", id: "tcp:" + i + ":5.6.7.8:443", proto: "tcp",
      app: { id: "slack", name: "Slack", pid: 3 },
      remote: { ip: "5.6.7.8", port: 443 }, state: s,
      country: "US", lat: 1, lon: 2,
      unresolved: false, newNetwork: false, networkKey: "5.6.7.0/24"
    }), 30);
  });
  assert.strictEqual(state.count, 1);
  assert.strictEqual(state.historyCount, 1);

  CM.setBlocked(state, "slack", "cgroup");
  assert.strictEqual(state.apps.slack.blocked, true);
  assert.strictEqual(state.historyApps.slack.blocked, true, "badge reaches History");
  CM.setBlocked(state, "slack", "");
  assert.strictEqual(state.apps.slack.blocked, false);
  assert.strictEqual(state.historyApps.slack.blocked, false);
}

testBlockBadge();
testIsBlockable();
testTimeWaitNotInFixtureLiveSet();
testIsLiveAcrossSourceVocabularies();
testBackfillNeverInflatesThePill();
testTeardownStaysOnTheLiveTab();
testProcfsContributesNothingToHistory();
testUnconnectedUdpStaysOnLive();
testBackfillNeverPulsesTheBar();
testTickNeverOverwritesTheLiveCount();
testBlockBadgeReachesBothTabs();

function testResetNetworkObservationsKeepsSessionBlocks() {
  let state = applyFixture();
  CM.setBlocked(state, "firefox", "cgroup");
  const rev = state.revision;
  CM.resetNetworkObservations(state, 99);
  assert.strictEqual(state.count, 0);
  assert.strictEqual(Object.keys(state.connections).length, 0);
  assert.ok(state.blocked.firefox);
  assert.strictEqual(state.blocked.firefox.mechanism, "cgroup");
  assert.ok(state.revision > rev);
}

function testMalformedLineBumpsRevision() {
  let state = CM.emptyState();
  const rev = state.revision;
  state = CM.applyLine(state, "{nope", 1);
  assert.ok(state.revision > rev);
  assert.strictEqual(state.lastError, "bad json");
}

testResetNetworkObservationsKeepsSessionBlocks();
testMalformedLineBumpsRevision();

function testNullSnapshotRowDoesNotThrow() {
  let state = applyFixture();
  const count = state.count;
  assert.doesNotThrow(() => {
    CM.applyLine(state, JSON.stringify({ type: "snapshot", ts: 1, connections: [null] }), 2);
  });
  assert.strictEqual(state.count, count);
}

function testInvalidSnapshotArrayDoesNotWipe() {
  let state = applyFixture();
  const count = state.count;
  CM.applyLine(state, JSON.stringify({ type: "snapshot", ts: 1 }), 2);
  assert.strictEqual(state.count, count);
  CM.applyLine(state, JSON.stringify({ type: "snapshot", ts: 1, connections: null }), 3);
  assert.strictEqual(state.count, count);
}

testNullSnapshotRowDoesNotThrow();
testInvalidSnapshotArrayDoesNotWipe();

function testPrototypeSafeIdentifierMaps() {
  for (const id of ["toString", "constructor", "__proto__", "hasOwnProperty", "valueOf"]) {
    let state = CM.emptyState();
    state = CM.applyLine(state, JSON.stringify({
      type: "snapshot", ts: 1, connections: [{
        id: "flow-" + id, proto: "tcp", inode: 3,
        app: { id: id, name: id, icon: "", desktop: "", pid: 8, system: false },
        local: { ip: "10.0.0.2", port: 9 }, remote: { ip: "1.2.3.4", port: 443 },
        state: "ESTABLISHED", country: "", lat: 0, lon: 0,
        unresolved: false, newNetwork: false, networkKey: "1.2.3.0/24", hostname: ""
      }]
    }), 1);
    assert.ok(state.apps[id], id + " missing");
    assert.strictEqual(state.apps[id].id, id);
    assert.strictEqual(state.apps[id].connections.length, 1);
    assert.strictEqual(typeof state.apps[id].connections.push, "function");
    CM.setBlocked(state, id, "cgroup");
    assert.strictEqual(state.apps[id].blocked, true);
    assert.ok(state.blocked[id]);
    assert.strictEqual(state.blocked[id].mechanism, "cgroup");
  }
}

function testApplyLineLeavesCallerStateOnRejectedSnapshot() {
  let state = applyFixture();
  const count = state.count;
  const apps = Object.keys(state.apps).sort();
  CM.applyLine(state, JSON.stringify({ type: "snapshot", ts: 1, connections: [null] }), 2);
  assert.strictEqual(state.count, count);
  assert.deepStrictEqual(Object.keys(state.apps).sort(), apps);
}

function testSnapshotReplaceIsAssignedNotPartial() {
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "snapshot", ts: 1, connections: [{
      id: "old", proto: "tcp", inode: 1,
      app: { id: "old-app", name: "Old", icon: "", desktop: "", pid: 1, system: false },
      local: { ip: "10.0.0.2", port: 1 }, remote: { ip: "1.2.3.4", port: 443 },
      state: "ESTABLISHED"
    }]
  }), 1);
  assert.ok(state.apps["old-app"]);
  const prior = state;
  const next = CM.applyLine(state, JSON.stringify({
    type: "snapshot", ts: 2, connections: [{
      id: "new", proto: "tcp", inode: 2,
      app: { id: "new-app", name: "New", icon: "", desktop: "", pid: 2, system: false },
      local: { ip: "10.0.0.2", port: 2 }, remote: { ip: "1.2.3.4", port: 443 },
      state: "ESTABLISHED"
    }]
  }), 2);
  assert.ok(prior.apps["old-app"], "caller state lost old app");
  assert.ok(!prior.apps["new-app"], "caller state gained new app");
  assert.ok(next.apps["new-app"]);
  assert.ok(!next.apps["old-app"]);
}

testPrototypeSafeIdentifierMaps();
testApplyLineLeavesCallerStateOnRejectedSnapshot();
testSnapshotReplaceIsAssignedNotPartial();

function liveConns(n) {
  const cs = [];
  for (let i = 0; i < n; i++)
    cs.push({ state: "ESTABLISHED", country: "US", remote: { ip: "1.2.3." + i, port: 443 } });
  return cs;
}

function sortFixture() {
  return [
    { id: "alpha-b", name: "Alpha", lastActivity: 100, connections: liveConns(2), blocked: false },
    { id: "alpha-a", name: "Alpha", lastActivity: 100, connections: liveConns(1), blocked: true },
    { id: "mike", name: "Mike", lastActivity: 300, connections: [], blocked: true },
    { id: "zed", name: "Zed", lastActivity: 50, connections: liveConns(3), blocked: false },
    { id: "unknown", name: "Unknown", lastActivity: 200, connections: liveConns(1), blocked: false }
  ];
}

function idsOf(rows) {
  return rows.map((a) => a.id);
}

function sortKeyValue(a, key) {
  if (key === "activity")
    return a.lastActivity || 0;
  if (key === "connections")
    return (a.connections || []).filter((c) => CM.isLive(c)).length;
  if (key === "blocked")
    return a.blocked === true ? 0 : 1;
  return String(a.name || a.id) + "\0" + String(a.id);
}

function testOrderRowsEachKey() {
  const rows = sortFixture();
  assert.deepStrictEqual(
    idsOf(CM.orderRows(rows, "name")),
    ["alpha-a", "alpha-b", "mike", "unknown", "zed"],
    "name: Alpha/a, Alpha/b, Mike, Unknown, Zed"
  );
  assert.deepStrictEqual(
    idsOf(CM.orderRows(rows)),
    ["alpha-a", "alpha-b", "mike", "unknown", "zed"],
    "omitted sortKey is name"
  );
  assert.deepStrictEqual(
    idsOf(CM.orderRows(rows, "activity")),
    ["mike", "unknown", "alpha-a", "alpha-b", "zed"],
    "activity desc, name→id ties"
  );
  assert.deepStrictEqual(
    idsOf(CM.orderRows(rows, "connections")),
    ["zed", "alpha-b", "alpha-a", "unknown", "mike"],
    "connections desc, name→id ties"
  );
  assert.deepStrictEqual(
    idsOf(CM.orderRows(rows, "blocked")),
    ["alpha-a", "mike", "alpha-b", "unknown", "zed"],
    "blocked first, then name→id"
  );
  const ranked = CM.orderRows(rows, "connections");
  const byRank = ranked.slice().sort((x, y) => x.activityRank - y.activityRank);
  assert.strictEqual(byRank[0].id, "mike", "activityRank 0 is busiest regardless of sort key");
}

function testFilterAppsKeysAndCompose() {
  const rows = CM.orderRows(sortFixture(), "name");
  assert.strictEqual(CM.filterApps(rows, "", "all").length, 5);
  assert.deepStrictEqual(idsOf(CM.filterApps(rows, "", "live")), ["alpha-a", "alpha-b", "unknown", "zed"]);
  assert.deepStrictEqual(idsOf(CM.filterApps(rows, "", "blocked")), ["alpha-a", "mike"]);
  assert.deepStrictEqual(idsOf(CM.filterApps(rows, "", "unknown")), ["unknown"]);
  assert.deepStrictEqual(
    idsOf(CM.filterApps(rows, "alpha", "blocked")),
    ["alpha-a"],
    "filter+query compose"
  );
  assert.deepStrictEqual(idsOf(CM.filterApps(rows, "zed", "live")), ["zed"]);
  assert.deepStrictEqual(idsOf(CM.filterApps(rows, "mike", "live")), []);
  assert.strictEqual(CM.filterApps(rows, "", "all"), rows, "all+empty query returns same list");
  const spot = CM.filterApps(applyFixture().ordered, "spot");
  assert.strictEqual(spot.length, 1);
  assert.strictEqual(spot[0].id, "spotify");
}

function assertStableAmongUnchanged(before, after, key) {
  const beforeIds = idsOf(before);
  const afterIds = idsOf(after);
  assert.deepStrictEqual(
    afterIds.slice().sort(),
    beforeIds.slice().sort(),
    key + ": ids are a permutation"
  );
  const beforeMap = {};
  const afterMap = {};
  for (const a of before) beforeMap[a.id] = a;
  for (const a of after) afterMap[a.id] = a;
  for (let i = 0; i < afterIds.length; i++) {
    for (let j = i + 1; j < afterIds.length; j++) {
      const idI = afterIds[i];
      const idJ = afterIds[j];
      if (sortKeyValue(beforeMap[idI], key) === sortKeyValue(afterMap[idI], key)
          && sortKeyValue(beforeMap[idJ], key) === sortKeyValue(afterMap[idJ], key)) {
        assert.ok(
          beforeIds.indexOf(idI) < beforeIds.indexOf(idJ),
          key + ": " + idI + " stayed before " + idJ
        );
      }
    }
  }
}

function testActivityBurstDoesNotReorderUnchangedKeys() {
  const keys = ["name", "activity", "connections", "blocked"];
  for (const key of keys) {
    let current = sortFixture();
    let ordered = CM.orderRows(current, key);
    for (let s = 0; s < 10; s++) {
      const before = ordered.map((a) => Object.assign({}, a, {
        connections: (a.connections || []).slice()
      }));
      current = current.map((a) => Object.assign({}, a, {
        lastActivity: a.id === "zed" ? a.lastActivity + 1000 : a.lastActivity,
        connections: (a.connections || []).slice()
      }));
      ordered = CM.orderRows(current, key);
      assertStableAmongUnchanged(before, ordered, key);
    }
  }
}

testOrderRowsEachKey();
testFilterAppsKeysAndCompose();
testActivityBurstDoesNotReorderUnchangedKeys();

// ---------------------------------------------------------------------------
// Row ordering and the blocked-app trapdoor.
// ---------------------------------------------------------------------------

function connectLine(id, appId, appName, ip, at) {
  return JSON.stringify({
    type: "connect",
    id: id,
    proto: "tcp",
    app: { id: appId, name: appName, icon: appId, desktop: "", pid: 100, system: false },
    local: { ip: "10.0.0.2", port: 4000 },
    remote: { ip: ip, port: 443 },
    state: "ESTABLISHED",
    country: "US", lat: 1, lon: 2,
    unresolved: false, newNetwork: false, networkKey: "0.0.0.0/24",
    seenAt: at
  });
}

// The regression this file exists to catch: rows used to be sorted by
// lastActivity, and rebuild() runs every 500ms, so the list reordered under the
// pointer twice a second while the user aimed at a block toggle.
function testOrderDoesNotFollowActivity() {
  let state = CM.emptyState();
  state = CM.applyLine(state, connectLine("t:1", "zulip", "Zulip", "1.1.1.1"), 1000);
  state = CM.applyLine(state, connectLine("t:2", "aria", "Aria", "2.2.2.2"), 1000);
  const first = state.ordered.map((a) => a.id);
  assert.deepStrictEqual(first, ["aria", "zulip"], "ordered by name, not arrival");

  // Make zulip overwhelmingly the most recently active app and rebuild.
  state = CM.applyLine(state, connectLine("t:3", "zulip", "Zulip", "3.3.3.3"), 99000);
  assert.deepStrictEqual(
    state.ordered.map((a) => a.id), first,
    "a burst of activity must not move a row"
  );
  // Activity is still reported, just not as position.
  const zulip = state.ordered.filter((a) => a.id === "zulip")[0];
  assert.strictEqual(zulip.activityRank, 0, "busiest app is still rank 0");
}

// Blocking used to delete the only way to unblock: rows come from live
// connections, a successful block kills them, the row and its toggle vanish and
// the nftables rule stays up forever.
function testBlockedAppKeepsARowWithNoConnections() {
  let state = CM.emptyState();
  state = CM.applyLine(state, connectLine("t:1", "slack", "Slack", "1.1.1.1"), 1000);
  assert.ok(state.apps.slack, "precondition: slack has a row");

  CM.setBlocked(state, "slack", "cgroup");
  // The block works: every slack conversation ends.
  state = CM.applyLine(state, JSON.stringify({ type: "disconnect", id: "t:1" }), 2000);

  const row = state.apps.slack;
  assert.ok(row, "blocked app still has a row after its traffic stops");
  assert.strictEqual(row.dormant, true, "row is marked dormant");
  assert.strictEqual(row.blocked, true, "row still reads as blocked");
  assert.strictEqual(row.name, "Slack", "dormant row keeps the app's name, not its id");
  assert.strictEqual(row.connections.length, 0);
  assert.ok(state.ordered.some((a) => a.id === "slack"), "dormant row is in the rendered list");

  // A dormant row is not traffic and must never reach the bar pill.
  assert.strictEqual(state.count, 0, "dormant row does not inflate the live count");

  // Unblocking removes it again.
  CM.setBlocked(state, "slack", "");
  assert.ok(!state.apps.slack, "lifting the block drops the dormant row");
}

function testDormantRowNeverOutranksRealActivity() {
  let state = CM.emptyState();
  state = CM.applyLine(state, connectLine("t:1", "aria", "Aria", "1.1.1.1"), 1000);
  CM.setBlocked(state, "ghost", "endpoints");
  CM.rebuild(state, 50000);
  const ghost = state.ordered.filter((a) => a.id === "ghost")[0];
  assert.ok(ghost, "injected");
  assert.strictEqual(ghost.lastActivity, 0, "a dormant row is never stamped with now()");
  const aria = state.ordered.filter((a) => a.id === "aria")[0];
  assert.ok(aria.activityRank < ghost.activityRank, "real traffic ranks above a dormant row");
}

// Endpoint blocks live in nftables and outlive the shell; state.blocked does
// not. Without rehydration the UI came back up claiming nothing was blocked
// while the kernel was still enforcing.
function testRehydrateBlockedFromHelperOwners() {
  let state = CM.emptyState();
  const changed = CM.rehydrateBlocked(state, { slack: ["1.2.3.4"], zoom: ["5.6.7.8"] });
  assert.strictEqual(changed, true, "reports that it changed something");
  assert.strictEqual(state.blocked.slack.mechanism, "endpoints");
  assert.strictEqual(state.blocked.zoom.mechanism, "endpoints");

  // A cgroup block leaves no owners entry. Reconciling endpoints must not
  // silently drop it — that would hide a live block.
  CM.setBlocked(state, "firefox", "cgroup");
  CM.rehydrateBlocked(state, { slack: ["1.2.3.4"], zoom: ["5.6.7.8"] });
  assert.strictEqual(state.blocked.firefox.mechanism, "cgroup", "cgroup block survives reconcile");

  // An endpoint block lifted out of band disappears from owners and must clear.
  CM.rehydrateBlocked(state, { slack: ["1.2.3.4"] });
  assert.ok(!state.blocked.zoom, "endpoint block removed out of band is cleared");
  assert.ok(state.blocked.slack, "still-owned endpoint block is kept");
  assert.strictEqual(state.blocked.firefox.mechanism, "cgroup", "cgroup still untouched");

  assert.strictEqual(
    CM.rehydrateBlocked(state, { slack: ["1.2.3.4"] }), false,
    "a no-op reconcile reports no change, so it cannot spin a rebuild loop"
  );
}

// applyLine must never modify the state it is given: Health.applyIngest drops
// a line that throws by keeping the previous state, which only works if that
// state is untouched. This used to be guaranteed by a JSON round trip of the
// whole state per event; it is now copy-on-write, so every event type that
// writes anything is checked here, in a sequence where each builds on the last.
function testApplyLineNeverMutatesItsInput() {
  const conn = (id, app, ip, extra) => Object.assign({
    type: "connect", ts: 1, id: id, proto: "tcp", inode: 1,
    app: { id: app, name: app, icon: "", desktop: "", pid: 7, system: false },
    local: { ip: "10.0.0.2", port: 5000 }, remote: { ip: ip, port: 443 },
    state: "ESTABLISHED", country: "US", lat: 1, lon: 1, newNetwork: true,
    networkKey: ip.replace(/\.\d+$/, ".0/24")
  }, extra || {});
  const lines = [
    { type: "hello", ts: 1, coverage: "tcp+connected-udp" },
    { type: "snapshot", ts: 1, connections: [conn("a", "aria", "1.1.1.1"), conn("b", "zulip", "2.2.2.2")] },
    conn("c", "aria", "3.3.3.3"),
    { type: "tick", ts: 1, count: 3 },
    { type: "tick", ts: 1, count: 3 },
    { type: "disconnect", ts: 1, id: "b" },
    { type: "digest", ts: 1, keys: ["9.9.9.0/24"], newNetworks: 1 },
    { type: "status", ts: 1, message: "degraded" },
    "{not json",
  ].map((l) => typeof l === "string" ? l : JSON.stringify(l));

  let state = CM.emptyState();
  CM.setBlocked(state, "ghost", "cgroup");
  for (const line of lines) {
    const before = JSON.stringify(state);
    const next = CM.applyLine(state, line, 5000);
    assert.notStrictEqual(next, state, "a new state for " + line.slice(0, 30));
    assert.strictEqual(JSON.stringify(state), before, "input mutated by " + line.slice(0, 30));
    state = next;
  }

  // And the copy-on-write did not lose anything along the way.
  assert.strictEqual(state.count, 2, "aria's two connections are live");
  assert.ok(state.apps.ghost && state.apps.ghost.dormant, "blocked row survived");
  assert.strictEqual(state.digestText, "1 new network while you were away");
  assert.strictEqual(state.lastError, "bad json");
}

// The panel renders `ordered`, so a tick has to reach it. The spark used to be
// sampled into `apps` only, and on screen it moved only when some connect or
// disconnect happened to rebuild `ordered`.
function testTickSparklinesReachTheRenderedRows() {
  let state = CM.emptyState();
  state = CM.applyLine(state, JSON.stringify({
    type: "snapshot", ts: 1, connections: [{
      id: "a", proto: "tcp", app: { id: "aria", name: "aria" },
      local: { ip: "10.0.0.2", port: 1 }, remote: { ip: "1.1.1.1", port: 443 }, state: "ESTABLISHED"
    }]
  }), 1000);
  for (let i = 0; i < 3; i++)
    state = CM.applyLine(state, JSON.stringify({ type: "tick", ts: 1, count: 1 }), 1000);
  assert.deepStrictEqual(state.apps.aria.spark, [1, 1, 1]);
  assert.strictEqual(state.ordered[0], state.apps.aria, "ordered holds the sampled row");
}

// An endpoint block is host-wide. An app's connected UDP to the local stub
// resolver is a real connection the daemon reports, and blocking it takes DNS
// down for every app on the machine.
function testRemotesOfNeverOffersMachineCriticalAddresses() {
  const c = (ip, port) => ({ remote: { ip: ip, port: port } });
  const app = { connections: [
    c("127.0.0.53", 53), c("192.168.1.1", 53), c("9.9.9.9", 853), c("::1", 631),
    c("169.254.169.254", 80), c("fe80::1", 547), c("224.0.0.251", 5353), c("ff02::fb", 5353),
    c("::ffff:127.0.0.1", 8080), c("0.0.0.0", 0),
    c("100.64.0.1", 443), c("100.127.255.254", 41641), c("::ffff:100.100.100.100", 443),
    c("93.184.216.34", 443), c("2001:db8::1", 443), c("192.168.1.20", 8443), c("93.184.216.34", 80),
    c("100.128.0.1", 443),
    c("fd7a:115c:a1e0::1", 443), c("FD7A:115C:A1E0:AB12::7", 443), c("fd00::1", 443),
  ] };
  assert.deepStrictEqual(CM.remotesOf(app),
    ["93.184.216.34", "2001:db8::1", "192.168.1.20", "100.128.0.1", "fd00::1"]);
}

// The helper refuses this machine's own gateways and nameservers by lookup, and
// reports them in status. A router's web UI on :80 is a real destination the
// panel used to offer, only for the helper to refuse it after the confirm.
function testRemotesOfSkipsTheHelpersHostCriticalList() {
  const c = (ip, port) => ({ remote: { ip: ip, port: port } });
  const app = { connections: [
    c("192.168.0.254", 80), c("::ffff:192.168.0.254", 443), c("1.1.1.1", 443),
    c("2001:DB8::53", 443), c("93.184.216.34", 443),
  ] };
  const critical = ["192.168.0.254", "1.1.1.1", "2001:db8::53", "::ffff:10.0.0.1"];
  assert.deepStrictEqual(CM.remotesOf(app, critical), ["93.184.216.34"]);
  assert.deepStrictEqual(CM.remotesOf({ connections: [c("10.0.0.1", 80)] }, critical), []);
  // An older helper reports no list; the offer falls back to the range rules.
  assert.strictEqual(CM.remotesOf(app).length, 5);
  assert.strictEqual(CM.remotesOf(app, undefined).length, 5);
}

// The daemon keeps a .desktop file's case; the helper stores ids lowercased.
// Reconciling them raw turned a blocked com.discordapp.Discord into a
// "com.discordapp.discord" ghost row on every panel open.
function testRehydrateMatchesIdsTheWayTheHelperStoresThem() {
  assert.strictEqual(CM.helperId("com.discordapp.Discord"), "com.discordapp.discord");
  assert.strictEqual(CM.helperId("My App!"), "my-app");
  let state = CM.emptyState();
  state.appMeta["com.discordapp.Discord"] = { name: "Discord" };
  state.blocked["com.discordapp.Discord"] = { mechanism: "endpoints" };
  const changed = CM.rehydrateBlocked(state, { "com.discordapp.discord": ["1.2.3.4"] });
  assert.strictEqual(changed, false, "the same block, spelled the helper's way, is no change");
  assert.deepStrictEqual(Object.keys(state.blocked), ["com.discordapp.Discord"], "no ghost row");

  // After a restart state.blocked is empty; the session's id is still preferred.
  state = CM.emptyState();
  state.appMeta["com.discordapp.Discord"] = { name: "Discord" };
  CM.rehydrateBlocked(state, { "com.discordapp.discord": ["1.2.3.4"] });
  assert.deepStrictEqual(Object.keys(state.blocked), ["com.discordapp.Discord"]);

  // And lifting it out of band still clears it.
  CM.rehydrateBlocked(state, {});
  assert.deepStrictEqual(Object.keys(state.blocked), []);

  // Status can beat the daemon's first snapshot. Once metadata arrives, the
  // helper spelling must migrate to the visible id instead of making a twin.
  state = CM.emptyState();
  CM.rehydrateBlocked(state, { "com.discordapp.discord": ["1.2.3.4"] });
  assert.deepStrictEqual(Object.keys(state.blocked), ["com.discordapp.discord"]);
  state.appMeta["com.discordapp.Discord"] = { name: "Discord" };
  assert.strictEqual(CM.rehydrateBlocked(state, { "com.discordapp.discord": ["1.2.3.4"] }), true);
  assert.deepStrictEqual(Object.keys(state.blocked), ["com.discordapp.Discord"]);
  assert.strictEqual(CM.rehydrateBlocked(state, { "com.discordapp.discord": ["1.2.3.4"] }), false);
}

// App blocks live in nftables too, and the panel used to forget every one of
// them on a shell restart, since only endpoint blocks were reconciled.
function testRehydrateRestoresCgroupBlocks() {
  let state = CM.emptyState();
  state.appMeta["com.discordapp.Discord"] = { name: "Discord" };
  assert.strictEqual(CM.rehydrateBlocked(state, {}, ["com.discordapp.discord", "firefox"]), true);
  assert.strictEqual(state.blocked["com.discordapp.Discord"].mechanism, "cgroup");
  assert.strictEqual(state.blocked.firefox.mechanism, "cgroup");

  // Unknown listing: cgroup entries are left alone, endpoints still reconcile.
  CM.setBlocked(state, "slack", "endpoints");
  CM.rehydrateBlocked(state, {}, undefined);
  assert.ok(state.blocked.firefox, "unknown cgroup listing touches nothing");
  assert.ok(!state.blocked.slack, "endpoint entry with no owner still clears");

  // A rule removed out of band clears; an endpoint block survives a cgroup list.
  CM.setBlocked(state, "zoom", "endpoints");
  CM.rehydrateBlocked(state, { zoom: ["1.2.3.4"] }, ["firefox"]);
  assert.ok(!state.blocked["com.discordapp.Discord"], "lifted cgroup block clears");
  assert.strictEqual(state.blocked.zoom.mechanism, "endpoints");
  assert.strictEqual(state.blocked.firefox.mechanism, "cgroup");

  // Both at once: the cgroup block is the one shown.
  CM.rehydrateBlocked(state, { firefox: ["5.6.7.8"], zoom: ["1.2.3.4"] }, ["firefox"]);
  assert.strictEqual(state.blocked.firefox.mechanism, "cgroup");
  assert.strictEqual(CM.rehydrateBlocked(state, { firefox: ["5.6.7.8"], zoom: ["1.2.3.4"] }, ["firefox"]), false,
    "a no-op reconcile reports no change");

  // The cgroup rule is lifted but the app still owns addresses: it stays
  // blocked, as an endpoint block, in the same reconcile.
  CM.rehydrateBlocked(state, { firefox: ["5.6.7.8"] }, []);
  assert.strictEqual(state.blocked.firefox.mechanism, "endpoints");
}

// Deferring the rebuild must change when the work happens, never the result.
function testDeferredRebuildSettlesToTheSameState() {
  const c = (id, app, ip) => JSON.stringify({ type: "connect", ts: 1, id: id, proto: "tcp",
    app: { id: app, name: app }, local: { ip: "10.0.0.2", port: 1 }, remote: { ip: ip, port: 443 },
    state: "ESTABLISHED", country: "US", lat: 1, lon: 1 });
  const lines = [
    JSON.stringify({ type: "snapshot", ts: 1, connections: [] }),
    c("a", "aria", "1.1.1.1"), c("b", "zulip", "2.2.2.2"), c("c", "aria", "3.3.3.3"),
    JSON.stringify({ type: "disconnect", ts: 1, id: "b" }),
    JSON.stringify({ type: "tick", ts: 1, count: 2 }),
    c("d", "mako", "4.4.4.4"),
  ];
  let eager = CM.emptyState(), lazy = CM.emptyState();
  for (const l of lines) {
    eager = CM.applyLine(eager, l, 5000);
    lazy = CM.applyLine(lazy, l, 5000, { deferRebuild: true });
  }
  assert.strictEqual(lazy.needsRebuild, true, "the last connect is pending");
  assert.strictEqual(CM.settle(lazy, 5000), true);
  assert.strictEqual(CM.settle(lazy, 5000), false, "settling twice does nothing");
  const view = (st) => JSON.stringify({ count: st.count,
    ordered: st.ordered.map((a) => [a.id, a.connections.length, a.spark]) });
  assert.strictEqual(view(lazy), view(eager));
  assert.deepStrictEqual(lazy.apps.aria.spark, [2], "the tick sampled settled rows, not stale ones");
}

// The daemon renames a process of ours that would land on "system" or
// "unknown" (identity.rs is_reserved_id), because isBlockable refuses those
// rows. The two lists must stay the same, or an app can make itself
// unblockable again.
function testTheDaemonNeverHandsOutAnIdThePanelRefuses() {
  const src = require("fs").readFileSync(require("path").join(__dirname, "../daemon/src/identity.rs"), "utf8");
  const m = src.match(/fn is_reserved_id[\s\S]*?matches!\(id\.to_ascii_lowercase\(\)\.as_str\(\),([^)]*)\)/);
  assert.ok(m, "is_reserved_id not found in daemon/src/identity.rs");
  const reserved = [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  assert.deepStrictEqual(reserved.sort(), ["system", "unknown"]);
  for (const id of reserved) {
    assert.strictEqual(CM.isBlockable({ id, system: false }), false, id);
    assert.strictEqual(CM.isBlockable({ id: id.toUpperCase(), system: false }), false, id);
    assert.strictEqual(CM.isBlockable({ id: id + "-app", system: false }), true, id + "-app");
  }
}


// A process that joins another app's row (exe name, comm or a .desktop file)
// keeps its own executable. The block confirmation lists every executable a
// row holds, so the join shows before the block does anything.
function testTheBlockConfirmationNamesEveryProgramInTheRow() {
  const line = (inode, pid, exe) => JSON.stringify({
    type: "connect", ts: 1000 + inode, id: "tcp:" + inode + ":93.184.216.34:443", proto: "tcp", inode,
    app: Object.assign({ id: "firefox", name: "Firefox", icon: "firefox", desktop: "firefox.desktop", pid, system: false },
      exe === undefined ? {} : { exe }),
    local: { ip: "192.168.1.10", port: 40000 + inode }, remote: { ip: "93.184.216.34", port: 443 },
    state: "ESTABLISHED", country: "US", lat: 0, lon: 0, unresolved: false, newNetwork: false, networkKey: "93.184.216.0/24",
  });
  let state = CM.emptyState();
  state = CM.applyLine(state, line(1, 10, "/usr/lib/firefox/firefox"), 5000);
  state = CM.applyLine(state, line(2, 11, "/usr/lib/firefox/firefox"), 5000);
  assert.deepStrictEqual(state.apps.firefox.exes, ["/usr/lib/firefox/firefox"]);
  assert.strictEqual(CM.blockProgramsLine(state.apps.firefox), "Program: /usr/lib/firefox/firefox");

  state = CM.applyLine(state, line(3, 66, "/tmp/.x/firefox"), 5000);
  assert.deepStrictEqual(state.apps.firefox.pids.sort(), [10, 11, 66]);
  assert.strictEqual(CM.blockProgramsLine(state.apps.firefox),
    "2 different programs are under this name: /tmp/.x/firefox, /usr/lib/firefox/firefox");

  // An older daemon sends no exe: no line, rather than an empty "Program:".
  let old = CM.applyLine(CM.emptyState(), line(4, 12), 5000);
  assert.strictEqual(CM.blockProgramsLine(old.apps.firefox), "");
  assert.strictEqual(CM.blockProgramsLine(null), "");

  const many = { exes: ["/a", "/b", "/c", "/d", "/e", "/f"] };
  assert.strictEqual(CM.blockProgramsLine(many),
    "6 different programs are under this name: /a, /b, /c, /d, and 2 more");

  const panel = fs.readFileSync(path.join(__dirname, "../Panel.qml"), "utf8");
  assert.ok(/message: "Block " \+ root\.blockConfirmName\(\) \+ "\?\\n\\n" \+ root\.blockConfirmPrograms\(\) \+/.test(panel),
    "the block confirmation no longer shows blockConfirmPrograms()");
  assert.ok(panel.includes("ConnectionModel.blockProgramsLine(a)"), "blockConfirmPrograms no longer reads blockProgramsLine");
}

testOrderDoesNotFollowActivity();
testBlockedAppKeepsARowWithNoConnections();
testDormantRowNeverOutranksRealActivity();
testRehydrateBlockedFromHelperOwners();
testApplyLineNeverMutatesItsInput();
testTickSparklinesReachTheRenderedRows();
testRemotesOfNeverOffersMachineCriticalAddresses();
testRemotesOfSkipsTheHelpersHostCriticalList();
testRehydrateMatchesIdsTheWayTheHelperStoresThem();
testRehydrateRestoresCgroupBlocks();
testDeferredRebuildSettlesToTheSameState();
testTheDaemonNeverHandsOutAnIdThePanelRefuses();
testTheBlockConfirmationNamesEveryProgramInTheRow();
// The whole host (#61): one app id can hold two accounts' processes; a block
// names only the pids that run as the asking account.
{
  const row = (id, uid, pid, owner) => ({
    id, proto: "tcp", inode: pid, uid,
    app: { id: "shared", name: "Shared", icon: "", desktop: "", pid, system: false, owner },
    local: { ip: "192.0.2.254", port: 40000 + pid }, remote: { ip: "192.0.2.1", port: 443 }, state: "ESTABLISHED",
    country: "", lat: 0, lon: 0, unresolved: false, newNetwork: false, networkKey: "192.0.2.0/24", hostname: ""
  });
  const rows = [row("a", 1000, 11, { uid: 1000, name: "me" }), row("b", 1000, 11, { uid: 1000, name: "me" }),
    row("c", 1001, 22, { uid: 1001, name: "them" }), row("d", null, 33, { uid: 1000, name: "me" }), row("e", null, 44, null)];
  const st = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: rows }), 1);
  assert.deepStrictEqual(Array.from(CM.pidsOwnedBy(st, "shared", 1000)).sort(), [11, 33], "by the row's uid, else its app's owner");
  assert.deepStrictEqual(Array.from(CM.pidsOwnedBy(st, "shared", 1001)), [22]);
  assert.deepStrictEqual(Array.from(CM.pidsOwnedBy(st, "shared", 1002)), []);
  assert.deepStrictEqual(Array.from(CM.pidsOwnedBy(st, "other", 1000)), []);
  assert.deepStrictEqual(Array.from(CM.pidsOwnedBy(null, "shared", 1000)), []);
}
console.log("test_connection_model.js ok");
