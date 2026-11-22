"use strict";
const assert = require("assert");
const A = require("../js/Activity.js");

function e(ts, kind, app, detail) {
  return {
    ts: ts,
    kind: kind,
    app: app || null,
    detail: detail || {}
  };
}

function testIngestNewestFirstAndCap() {
  const hello = [
    e(1, "daemon_start"),
    e(2, "app_first_seen", { id: "a", name: "A" }),
    e(3, "new_network", null, { network: "1.2.3.0/24", country: "US" })
  ];
  let store = A.ingest([], hello, 1000);
  assert.strictEqual(store.length, 3);
  assert.strictEqual(store[0].ts, 3, "hello replay is ascending; ingest puts newest first");
  assert.strictEqual(store[2].ts, 1);
  store = A.ingest(store, [e(4, "block", { id: "a", name: "A" }, { mechanism: "cgroup" })], 1000);
  assert.strictEqual(store[0].ts, 4);
  assert.strictEqual(store[1].ts, 3);
  const many = [];
  for (let i = 0; i < 1200; i++)
    many.push(e(100 + i, "app_first_seen", { id: "x" + i, name: "X" }));
  const capped = A.ingest([], many, 1000);
  assert.strictEqual(capped.length, 1000);
  assert.strictEqual(capped[0].ts, 100 + 1199);
  assert.strictEqual(capped[999].ts, 100 + 200);
}

function testGroupByHour() {
  const now = new Date(2026, 8, 18, 16, 30, 0).getTime();
  const today14 = new Date(2026, 8, 18, 14, 5, 1).getTime();
  const today14b = new Date(2026, 8, 18, 14, 55, 0).getTime();
  const yest23 = new Date(2026, 8, 17, 23, 10, 0).getTime();
  const entries = [
    e(today14b, "block", { id: "f", name: "Firefox" }, { mechanism: "cgroup" }),
    e(today14, "app_first_seen", { id: "f", name: "Firefox" }),
    e(yest23, "new_network", null, { network: "9.9.9.0/24", country: "US" })
  ];
  const groups = A.groupByHour(entries, now);
  assert.strictEqual(groups.length, 2);
  assert.strictEqual(groups[0].label, "Today 14:00");
  assert.strictEqual(groups[0].entries.length, 2);
  assert.strictEqual(groups[1].label, "Yesterday 23:00");
  assert.strictEqual(groups[1].entries.length, 1);
}

function testFilterEntries() {
  const rows = [
    e(1, "app_first_seen", { id: "firefox", name: "Firefox" }),
    e(2, "new_network", null, { network: "1.2.3.0/24", country: "DE" }),
    e(3, "block", { id: "firefox", name: "Firefox" }, { mechanism: "cgroup" }),
    e(4, "unblock", { id: "slack", name: "Slack" }, { mechanism: "endpoints" }),
    e(5, "block_failed", { id: "x", name: "X" }, { mechanism: "cgroup", error: "nope" }),
    e(6, "unknown_owner", null, { uid: 1000, reason: "no-owner" }),
    e(7, "kub0_connected"),
    e(8, "heartbeat_ok", null, { ok: true }),
    e(9, "heartbeat_failed", null, { ok: false }),
    e(10, "daemon_start"),
    e(11, "source_changed", null, { source: "procfs" })
  ];
  assert.strictEqual(A.filterEntries(rows, "all", "").length, 11);
  assert.strictEqual(A.filterEntries(rows, "apps", "").length, 1);
  assert.strictEqual(A.filterEntries(rows, "networks", "").length, 1);
  assert.strictEqual(A.filterEntries(rows, "blocks", "").length, 3);
  assert.strictEqual(A.filterEntries(rows, "unknown", "").length, 1);
  assert.strictEqual(A.filterEntries(rows, "kub0", "").length, 3);
  assert.strictEqual(A.filterEntries(rows, "system", "").length, 2);
  const q = A.filterEntries(rows, "all", "firefox");
  assert.strictEqual(q.length, 2);
  const det = A.filterEntries(rows, "all", "no-owner");
  assert.strictEqual(det.length, 1);
  const hb = A.filterEntries(rows, "kub0", "failed");
  assert.strictEqual(hb.length, 1);
  assert.strictEqual(hb[0].kind, "heartbeat_failed");
}

function testDigestEntriesFiltersThenCaps() {
  const rows = [
    e(50, "app_first_seen", { id: "slack", name: "Slack" }),
    e(40, "block", { id: "firefox", name: "Firefox" }, { mechanism: "cgroup" }),
    e(30, "new_network", null, { network: "1.2.3.0/24", country: "DE" }),
    e(20, "app_first_seen", { id: "firefox", name: "Firefox" }),
    e(10, "daemon_start")
  ];
  const all = A.digestEntries(rows, "", 4);
  assert.strictEqual(all.length, 4, "unfiltered digest stays capped");
  assert.strictEqual(all[0].appId, "slack");
  assert.ok(all[0].line.indexOf("Slack") >= 0);
  const q = A.digestEntries(rows, "firefox", 4);
  assert.strictEqual(q.length, 2);
  assert.strictEqual(q[0].appId, "firefox");
  assert.strictEqual(q[1].appId, "firefox");
  const none = A.digestEntries(rows, "no-such-app", 4);
  assert.strictEqual(none.length, 0);
  const noApp = A.digestEntries(rows, "daemon_start", 4);
  assert.strictEqual(noApp.length, 1);
  assert.strictEqual(noApp[0].appId, "");
}

testIngestNewestFirstAndCap();
testGroupByHour();
testFilterEntries();
testDigestEntriesFiltersThenCaps();
console.log("test_activity.js ok");

// The exec gate: its activity kind files under blocks, its detail line names
// the decision, and only a block (or a deny that failed open) earns a
// notification, with the two helper actions and the digest after --with.
function testExecGateDenyKindAndDetail() {
  assert.ok(A.KIND_GROUPS.blocks.indexOf("exec_gate_deny") >= 0, "a refused exec is a block");
  assert.strictEqual(A.kindLabel("exec_gate_deny"), "exec gate");
  const blocked = e(5, "exec_gate_deny", { id: "exec:ab", name: "sample" },
    { decision: "blocked", exe: "/home/u/Downloads/sample", reason: "detonated: ransomware", sha256: "a".repeat(64) });
  assert.strictEqual(A.detailLine(blocked), "blocked · /home/u/Downloads/sample · detonated: ransomware");
  const once = e(6, "exec_gate_deny", null, { decision: "allowed_once", exe: "/x" });
  assert.strictEqual(A.detailLine(once), "allowed once · /x");
  const rows = A.filterEntries([blocked, e(1, "app_first_seen", { id: "a", name: "A" })], "blocks", "");
  assert.strictEqual(rows.length, 1);
  assert.strictEqual(A.filterEntries([blocked], "all", "ransomware").length, 1, "the reason is searchable");
}

function testExecGateNotificationTextAndActions() {
  const sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  const blocked = e(5, "exec_gate_deny", { id: "exec:" + sha, name: "sample" },
    { decision: "blocked", comm: "sample", exe: "/home/u/sample", sha256: sha,
      reason: "ransomware dropper", promotedBy: "vigiles-auto", createdAt: "2026-10-20T01:02:03Z" });
  const n = A.notification(blocked);
  assert.ok(n, "a block notifies");
  assert.strictEqual(n.headline, "kub0 blocked sample");
  assert.strictEqual(n.body, "this file matches a sample kub0 detonated on 2026-10-20 (ransomware dropper).");
  assert.strictEqual(n.urgency, "critical");
  assert.strictEqual(n.sha256, sha);
  assert.deepStrictEqual(n.actions.map((a) => a.label), ["Allow once", "Trust on this machine"]);
  // Both lower protection: `pkexec /usr/bin/kub0 <verb> <sha256>` through the
  // system daemon, never the helper (#61 step 1b).
  assert.deepStrictEqual(n.actions[0].argv, ["/usr/bin/pkexec", "/usr/bin/kub0", "allow-once"]);
  assert.deepStrictEqual(n.actions[1].argv, ["/usr/bin/pkexec", "/usr/bin/kub0", "trust"]);
  assert.deepStrictEqual(n.withArgs, [sha], "the digest rides after --with, never inside an action");
  for (const a of n.actions)
    assert.strictEqual(a.argv.indexOf(sha), -1);

  const noDate = A.notification(e(5, "exec_gate_deny", null, { decision: "blocked", comm: "s", sha256: sha }));
  assert.strictEqual(noDate.body, "this file matches a sample kub0 detonated.");

  const failopen = A.notification(e(5, "exec_gate_deny", null,
    { decision: "allowed_failopen", comm: "s", sha256: sha, createdAt: "2026-10-20T01:02:03Z" }));
  assert.strictEqual(failopen.headline, "kub0 could not block s");
  assert.ok(failopen.body.indexOf("so it ran") >= 0, failopen.body);
  assert.deepStrictEqual(failopen.actions.map((a) => a.label), ["Trust on this machine"], "nothing to allow once: it already ran");

  assert.strictEqual(A.notification(e(5, "exec_gate_deny", null, { decision: "allowed_once", sha256: sha })), null, "the owner asked for that");
  assert.strictEqual(A.notification(e(5, "exec_gate_deny", null, { decision: "allowed_local_trust", sha256: sha })), null);
  assert.strictEqual(A.notification(e(5, "exec_gate_deny", null, { decision: "blocked", sha256: "not-a-digest" })), null,
    "a digest that is not 64 hex never reaches an argv");
  assert.strictEqual(A.notification(e(5, "exec_gate_deny", null, { decision: "blocked", sha256: sha.toUpperCase() })), null);
}

function testExecGateNotifyRateLimit() {
  const sha = "a".repeat(64);
  const other = "b".repeat(64);
  let r = A.execGateNotifyAllowed({}, sha, 1000);
  assert.strictEqual(r.allowed, true);
  r = A.execGateNotifyAllowed(r.seen, sha, 1000 + 60 * 1000);
  assert.strictEqual(r.allowed, false, "same digest inside ten minutes stays quiet");
  r = A.execGateNotifyAllowed(r.seen, other, 1000 + 60 * 1000);
  assert.strictEqual(r.allowed, true, "another digest is its own window");
  r = A.execGateNotifyAllowed(r.seen, sha, 1000 + A.EXEC_GATE_NOTIFY_WINDOW_MS);
  assert.strictEqual(r.allowed, true, "the window has passed");
  assert.strictEqual(Object.keys(r.seen).length, 2, "expired entries are dropped, live ones kept");
  assert.strictEqual(A.execGateNotifyAllowed(null, "", 5).allowed, false);
  assert.strictEqual(A.execGateNotifyAllowed("junk", sha, 5).allowed, true);
}

// Binds.notifyArgvWithActions is QML-only (.pragma library, no exports), so
// evaluate the function text the way test_service_dispatch.js evaluates
// Service.qml: the argv order is what `omarchy notification send` parses.
function testNotifyArgvWithActionsOrder() {
  const fs = require("fs");
  const path = require("path");
  const vm = require("vm");
  const src = fs.readFileSync(path.join(__dirname, "../js/Binds.js"), "utf8");
  const m = src.match(/^function notifyArgvWithActions\([^\n]*\) \{[\s\S]*?^\}/m);
  assert.ok(m, "Binds.js has notifyArgvWithActions");
  const ctx = { PLUGIN_ID: "ai.kub0.agent" };
  vm.createContext(ctx);
  vm.runInContext(m[0], ctx);
  const sha = "c".repeat(64);
  const argv = ctx.notifyArgvWithActions("kub0", "X", "kub0 blocked s", "body", "critical",
    [{ label: "Allow once", argv: ["/usr/bin/pkexec", "/usr/lib/vallum/vallum-block", "execgate-allow-once"] },
     { label: "Trust on this machine", argv: ["/usr/bin/pkexec", "/usr/lib/vallum/vallum-block", "execgate-trust"] }],
    [sha]);
  // Array.from: the vm realm's Array is not this realm's, and deepStrictEqual
  // compares prototypes.
  assert.deepStrictEqual(Array.from(argv), [
    "omarchy", "notification", "send", "--app-name", "kub0", "-g", "X", "-u", "critical",
    "kub0 blocked s", "body",
    "--action", "Allow once", "/usr/bin/pkexec", "/usr/lib/vallum/vallum-block", "execgate-allow-once",
    "--action", "Trust on this machine", "/usr/bin/pkexec", "/usr/lib/vallum/vallum-block", "execgate-trust",
    "--with", sha
  ]);
  // No actions: no --with either, and a bogus urgency is dropped.
  assert.deepStrictEqual(Array.from(ctx.notifyArgvWithActions("kub0", "X", "h", "b", "loud", [], [sha])),
    ["omarchy", "notification", "send", "--app-name", "kub0", "-g", "X", "h", "b"]);
}

testExecGateDenyKindAndDetail();
testExecGateNotificationTextAndActions();
testExecGateNotifyRateLimit();
testNotifyArgvWithActionsOrder();
console.log("exec gate activity tests ok");
