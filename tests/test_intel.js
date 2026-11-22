"use strict";
// The Intel view's pure half. Rows here are the shapes the daemon sends
// (daemon/src/intel.rs, event.rs) after ConnectionModel.normalizeConn.
const assert = require("assert");
const I = require("../js/Intel.js");
const CM = require("../ConnectionModel.js");

let passed = 0;
function test(name, fn) { fn(); passed += 1; console.log("  ok  " + name); }

function conn(id, extra) {
  return Object.assign({
    id: id, proto: "tcp", inode: 1, state: "ESTABLISHED", seenAt: 1000,
    app: { id: "firefox", name: "Firefox", pid: 7 },
    remote: { ip: "203.0.113.7", port: 443 }, local: { ip: "10.0.0.2", port: 1 },
    country: "DE", hostname: "", networkKey: "203.0.113.0/24", asn: 24940, org: "Hetzner Online GmbH",
    indicators: []
  }, extra || {});
}

test("normalizeConn keeps asn, org and indicators and degrades odd shapes", () => {
  const raw = {
    id: "a", proto: "tcp", app: { id: "x", name: "X" }, remote: { ip: "1.2.3.4", port: 443 }, local: { ip: "", port: 0 },
    asn: 13335, org: "Cloudflare, Inc.",
    indicators: [
      { id: "beacon-cadence", severity: "notice", attack: { id: "T1071", name: "Application Layer Protocol" }, basis: "every 60s" },
      { id: "hosting", severity: "info", basis: "landlord" },
      { severity: "warning" },
      "junk", null
    ]
  };
  const m = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: [raw] }), 1);
  const c = m.connections.a;
  assert.strictEqual(c.asn, 13335);
  assert.strictEqual(c.org, "Cloudflare, Inc.");
  assert.deepStrictEqual(c.indicators.map(i => i.id), ["beacon-cadence", "hosting"]);
  assert.deepStrictEqual(c.indicators[0].attack, { id: "T1071", name: "Application Layer Protocol" });
  assert.strictEqual(c.indicators[1].attack, null);
  const bare = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: [{ id: "b", proto: "tcp", app: { id: "x" }, remote: { ip: "1.1.1.1", port: 1 }, local: { ip: "", port: 0 }, asn: "13335", org: 7 }] }), 1).connections.b;
  assert.strictEqual(bare.asn, null, "a string ASN is not a number");
  assert.strictEqual(bare.org, "");
  assert.deepStrictEqual(bare.indicators, []);
});

test("indicator rows sort by severity then recency and carry the row's context", () => {
  const a = conn("a", { seenAt: 10, indicators: [{ id: "hosting", severity: "info", basis: "h" }] });
  const b = conn("b", { seenAt: 20, hostname: "c2.example.net", indicators: [
    { id: "beacon-cadence", severity: "notice", attack: { id: "T1071", name: "ALP" }, basis: "every 60s" },
    { id: "exe-deleted", severity: "warning", basis: "gone" }
  ] });
  const c = conn("c", { seenAt: 30, indicators: [{ id: "new-asn", severity: "notice", basis: "first" }] });
  const d = conn("d", { seenAt: 40, indicators: [{ id: "future-thing", severity: "critical", basis: "?" }] });
  const rows = I.indicatorRows({ a, b, c, d });
  assert.deepStrictEqual(rows.map(r => r.indicator), ["exe-deleted", "new-asn", "beacon-cadence", "hosting", "future-thing"],
    "warning, then notices newest first, then info; an unknown severity sorts last");
  assert.strictEqual(rows[0].title, "Executable deleted");
  assert.strictEqual(rows[0].peer, "c2.example.net:443");
  assert.strictEqual(rows[0].network, "AS24940 Hetzner Online GmbH");
  assert.strictEqual(rows[0].appName, "Firefox");
  assert.strictEqual(rows[4].title, "future-thing", "an unknown id keeps its own name");
  assert.deepStrictEqual(I.summarize(rows), { warning: 1, notice: 2, info: 1, total: 5 });
  assert.strictEqual(I.summaryLine(rows), "1 warning · 2 notices · 1 info");
  assert.strictEqual(I.summaryLine([]), "Nothing to flag on the current rows.");
  assert.deepStrictEqual(I.indicatorRows([conn("e")]), [], "a row with no indicators produces nothing");
  assert.deepStrictEqual(I.filterRows(rows, "notice", "").map(r => r.indicator), ["new-asn", "beacon-cadence"]);
  assert.deepStrictEqual(I.filterRows(rows, "", "t1071").map(r => r.indicator), ["beacon-cadence"], "ATT&CK ids are searchable");
  assert.deepStrictEqual(I.filterRows(rows, "", "hetzner").length, 5, "the network label is searchable");
  assert.deepStrictEqual(I.filterRows(rows, "warning", "nothing-matches"), []);
});

test("Intel liveness agrees with ConnectionModel.isLive for every state", () => {
  for (const state of ["ESTABLISHED", "CLOSED", "closed", "Closed", "SYN_SENT", "connect-attempt", "", "OBSERVED"]) {
    const c = conn("s", { state: state });
    assert.strictEqual(I.isLive(c), CM.isLive(c), "state " + JSON.stringify(state));
  }
});

test("peer and network labels read the hostname first and bracket IPv6", () => {
  assert.strictEqual(I.peerLabel(conn("a", { hostname: "h.example", remote: { ip: "1.2.3.4", port: 80 } })), "h.example:80");
  assert.strictEqual(I.peerLabel(conn("a", { remote: { ip: "2001:db8::1", port: 443 } })), "[2001:db8::1]:443");
  assert.strictEqual(I.networkLabel({ asn: 1 }), "AS1");
  assert.strictEqual(I.networkLabel({ org: "X" }), "X");
  assert.strictEqual(I.networkLabel({}), "");
});

test("listeners sort exposed first and summarize exposure honestly", () => {
  const rows = I.listenerRows([
    { proto: "tcp", ip: "127.0.0.1", port: 631, app: { id: "cups", name: "CUPS" }, exe: "/usr/bin/cupsd", uid: 0, scope: "loopback" },
    { proto: "tcp", ip: "0.0.0.0", port: 22, app: { id: "system", name: "system", system: true }, exe: "", uid: 0, scope: "all" },
    { proto: "udp", ip: "192.168.1.5", port: 5353, app: { id: "avahi", name: "Avahi" }, exe: "", uid: 972, scope: "address" },
    null, "junk"
  ]);
  assert.deepStrictEqual(rows.map(r => r.port), [22, 5353, 631]);
  assert.strictEqual(rows[0].scopeLabel, "All interfaces");
  assert.strictEqual(rows[1].scopeLabel, "One address");
  assert.strictEqual(rows[2].scopeLabel, "Loopback only");
  assert.strictEqual(rows[2].exposed, false);
  assert.strictEqual(I.exposureLine(rows), "2 of 3 sockets are reachable from the network.");
  assert.strictEqual(I.exposureLine([rows[2]]), "1 socket listens, all on loopback only.");
  assert.strictEqual(I.exposureLine([]), "No listening sockets observed.");
  assert.strictEqual(I.listenerRows("nope").length, 0);
});

test("watch validation refuses the obviously wrong and lets the daemon decide the rest", () => {
  assert.strictEqual(I.validateWatch("asn", "AS13335"), "");
  assert.strictEqual(I.validateWatch("asn", "cloudflare"), "An ASN is a number, like AS13335");
  assert.strictEqual(I.validateWatch("country", "kp"), "");
  assert.strictEqual(I.validateWatch("country", "PRK"), "A country is a two-letter code");
  assert.strictEqual(I.validateWatch("port", "4444"), "");
  assert.strictEqual(I.validateWatch("port", "70000"), "A port is 0..65535");
  assert.strictEqual(I.validateWatch("host", "localhost"), "A hostname needs a dot and no spaces");
  assert.strictEqual(I.validateWatch("host", "example.com"), "");
  assert.strictEqual(I.validateWatch("cidr", "203.0.113.0/24"), "");
  assert.strictEqual(I.validateWatch("cidr", "not an ip"), "An address or CIDR range, like 203.0.113.0/24");
  assert.strictEqual(I.validateWatch("app", ""), "Enter a value");
  assert.strictEqual(I.validateWatch("app", "x".repeat(300)), "Too long");
  assert.strictEqual(I.WATCH_KINDS.map(k => k.value).join(","), "asn,country,cidr,host,port,app");
});

test("watch rows are titled, detailed, and ordered by last hit", () => {
  const now = 1_000_000;
  const rows = I.watchRows([
    { id: "w-1", kind: "port", value: "4444", note: "reverse shells", ts: 10, hits: 0, last_hit: 0 },
    { id: "w-2", kind: "asn", value: "13335", note: "", ts: 5, hits: 3, last_hit: now - 120_000 },
    { bogus: true }
  ], now);
  assert.deepStrictEqual(rows.map(r => r.id), ["w-2", "w-1"]);
  assert.strictEqual(rows[0].title, "ASN AS13335");
  assert.strictEqual(rows[0].detail, "3 hits, last 2m ago");
  assert.strictEqual(rows[1].title, "Remote port 4444");
  assert.strictEqual(rows[1].detail, "reverse shells · no hits yet");
});

test("pivot subjects come from the row and facts read the daemon's pivot", () => {
  const c = conn("a", { hostname: "edge.cdn.example.net" });
  assert.strictEqual(I.subjectFor(c, "ip"), "ip:203.0.113.7");
  assert.strictEqual(I.subjectFor(c, "host"), "host:example.net");
  assert.strictEqual(I.subjectFor(c, "asn"), "asn:24940");
  assert.strictEqual(I.subjectFor(c, "app"), "app:firefox");
  assert.strictEqual(I.subjectFor(conn("b", { asn: null }), "asn"), "");
  assert.deepStrictEqual(I.pivotOptions(c).map(o => o.label), ["203.0.113.7", "*.example.net", "AS24940", "app firefox", "DE"]);
  const now = 10_000_000;
  const facts = I.pivotFacts({
    subject: { kind: "ip", value: "203.0.113.7" }, since: 0, until: now, connections: 12, live: 2, tx: 2048, rx: 4 * 1024 * 1024,
    first: now - 3_600_000, last: now - 30_000, cadenceMs: 60_000,
    apps: [{ id: "firefox", name: "Firefox", connections: 10 }, { id: "curl", name: "", connections: 2 }],
    destinations: [{ ip: "203.0.113.7", port: 443, hostname: "", connections: 12 }],
    asns: [{ key: "24940", label: "AS24940 Hetzner Online GmbH", connections: 12 }],
    countries: [{ key: "DE", label: "DE", connections: 12 }], ports: [{ key: "443", label: "443", connections: 12 }],
    indicators: [{ id: "beacon-cadence", severity: "notice", connections: 12, example: "x" }],
    timeline: [0, 3, 6, 3], timelineBucketMs: 3_600_000, truncated: true
  }, now);
  const get = l => facts.find(r => r.label === l).value;
  assert.strictEqual(get("Matched"), "12 connections (2 live) · history capped, a floor");
  assert.strictEqual(get("Seen"), "first 1h ago, last 30s ago");
  assert.strictEqual(get("Sampled transfer"), "↑ 2 KiB ↓ 4.0 MiB");
  assert.strictEqual(get("Cadence"), "about every 60s");
  assert.strictEqual(get("Apps"), "Firefox ×10, curl ×2");
  assert.strictEqual(get("Indicators"), "Notice · Regular cadence ×12");
  assert.deepStrictEqual(I.timelineBars({ timeline: [0, 3, 6, 3] }), [0, 0.5, 1, 0.5]);
  assert.deepStrictEqual(I.timelineBars({ timeline: [0, 0] }), []);
  assert.deepStrictEqual(I.pivotFacts({ connections: 0 }, now), [{ label: "Matched", value: "no retained observations in this window" }]);
  assert.deepStrictEqual(I.pivotFacts(null, now)[0].label, "Matched", "a malformed pivot still renders");
});

console.log("test_intel.js ok (" + passed + " tests)");

// Round two: lineage and package reach the drawer; notifications are chosen
// by Activity.notification, not in QML.
const E = require("../js/Evidence.js");
const A = require("../js/Activity.js");
test("lineage and package survive normalizeConn and render in the evidence drawer", () => {
  const raw = {
    id: "l", proto: "tcp", app: { id: "curl", name: "curl", pid: 9 }, remote: { ip: "1.2.3.4", port: 443 }, local: { ip: "", port: 0 },
    evidence: { source: "procfs", recordedAt: 5, ownerMethod: "m", hash: "sha256:abc", container: null, package: "none",
      lineage: { ancestors: [{ pid: 8, comm: "bash", exe: "/usr/bin/bash" }, { pid: 1, comm: "systemd" }, { bogus: true }], cmdline: "curl -s x", cwd: "/tmp", truncated: true } }
  };
  const c = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: [raw] }), 1).connections.l;
  assert.strictEqual(c.evidence.package, "none");
  assert.deepStrictEqual(c.evidence.lineage.ancestors, [{ pid: 8, comm: "bash", exe: "/usr/bin/bash" }, { pid: 1, comm: "systemd", exe: "" }]);
  assert.strictEqual(c.evidence.lineage.truncated, true);
  const rows = E.describe(c);
  const get = l => rows.find(r => r.label === l).value;
  assert.strictEqual(get("Package"), "No installed package owns this executable");
  assert.strictEqual(get("Process lineage"), "bash (8) /usr/bin/bash\n← systemd (1)\n← … chain cut short");
  assert.strictEqual(get("Command line"), "curl -s x");
  assert.strictEqual(get("Working directory"), "/tmp");
  const none = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: [Object.assign({}, raw, { id: "n", evidence: { source: "procfs" } })] }), 1).connections.n;
  assert.strictEqual(none.evidence.lineage, null);
  assert.strictEqual(none.evidence.package, "");
  assert.ok(!E.describe(none).some(r => r.label === "Process lineage" || r.label === "Package"));
  assert.strictEqual(I.indicatorLabel("exe-unpackaged"), "Unpackaged executable");
  assert.strictEqual(I.indicatorLabel("exe-build-dir"), "Go build directory");
});

test("the hostname's source survives and is explained in the drawer", () => {
  const raw = { id: "h", proto: "tcp", app: { id: "x", name: "X" }, remote: { ip: "1.2.3.4", port: 443 }, local: { ip: "", port: 0 }, hostname: "cdn.example.net", hostnameSource: "dns" };
  const c = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: [raw] }), 1).connections.h;
  assert.strictEqual(c.hostnameSource, "dns");
  const row = E.describe(c).find(r => r.label === "Hostname observation").value;
  assert.ok(row.startsWith("cdn.example.net\n") && row.includes("asked DNS for"), row);
  const ptr = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: [Object.assign({}, raw, { id: "p", hostnameSource: "ptr" })] }), 1).connections.p;
  assert.ok(E.describe(ptr).find(r => r.label === "Hostname observation").value.includes("Reverse DNS"));
  const none = CM.applyLine(CM.emptyState(), JSON.stringify({ type: "snapshot", ts: 1, connections: [Object.assign({}, raw, { id: "n", hostnameSource: 7 })] }), 1).connections.n;
  assert.strictEqual(none.hostnameSource, "");
  assert.strictEqual(E.describe(none).find(r => r.label === "Hostname observation").value, "cdn.example.net");
});

test("only watch hits and warnings earn a notification", () => {
  const hit = A.notification({ ts: 1, kind: "watch_hit", app: { id: "nc", name: "" }, detail: { rule: "w-1", match: "port 4444 (shells)", remote: "1.2.3.4", port: 4444 } });
  assert.deepStrictEqual(hit, { headline: "Watch rule matched", body: "nc reached 1.2.3.4:4444 · port 4444 (shells)" });
  const warn = A.notification({ ts: 1, kind: "indicator", app: { id: "x", name: "X" }, detail: { indicator: "exe-deleted", severity: "warning", basis: "gone", hostname: "h.example", port: 443 } });
  assert.deepStrictEqual(warn, { headline: "kub0 warning: exe-deleted", body: "X → h.example:443\ngone" });
  assert.strictEqual(A.notification({ ts: 1, kind: "indicator", detail: { indicator: "new-asn", severity: "notice" } }), null, "a notice never interrupts");
  assert.strictEqual(A.notification({ ts: 1, kind: "new_network", detail: {} }), null);
  assert.strictEqual(A.notification(null), null);
});
test("timeline rows shade by sqrt of the busiest cell and fold the long tail", () => {
  const h = 3600000;
  const since = Date.UTC(2026, 9, 11, 0, 0, 0);
  const raw = { since, until: since + 24 * h, bucketMs: h, buckets: 24, max: 16,
    apps: [{ id: "firefox", name: "Firefox", counts: Array.from({ length: 24 }, (_, i) => i === 3 ? 16 : i === 4 ? 4 : 0), total: 20 },
           { id: "curl", name: "", counts: [1], total: 1 }, { bogus: 1 }],
    other: Array.from({ length: 24 }, (_, i) => i === 0 ? 2 : 0), otherApps: 3,
    total: Array.from({ length: 24 }, (_, i) => i === 3 ? 16 : i === 4 ? 4 : i === 0 ? 3 : 0), truncated: true };
  const rows = I.timelineRows(raw);
  assert.deepStrictEqual(rows.map(r => r.label), ["Firefox", "curl", "+3 other apps"]);
  assert.strictEqual(rows[0].cells.length, 24);
  assert.strictEqual(rows[0].cells[3].shade, 1);
  assert.strictEqual(rows[0].cells[4].shade, 0.5, "4 of 16 shades at sqrt(0.25)");
  assert.strictEqual(rows[0].cells[0].shade, 0);
  assert.strictEqual(rows[1].cells.length, 24, "a short counts array is padded");
  assert.strictEqual(rows[2].total, 2);
  assert.deepStrictEqual(I.timelineLabels(raw).map(l => l.index), [0, 6, 12, 18]);
  assert.strictEqual(I.timelineLabels(Object.assign({}, raw, { bucketMs: 6 * h, buckets: 28 })).length, 7, "a week labels each day");
  assert.deepStrictEqual(I.timelineCellAt(rows, 24, 0, 0, 240, 90), { row: 0, col: 0 });
  assert.deepStrictEqual(I.timelineCellAt(rows, 24, 35, 89, 240, 90), { row: 2, col: 3 });
  assert.strictEqual(I.timelineCellAt(rows, 24, 240, 10, 240, 90), null, "off the right edge");
  assert.strictEqual(I.timelineCellAt([], 24, 1, 1, 240, 90), null);
  const hover = I.timelineHoverText(raw, rows, { row: 0, col: 3 });
  assert.ok(/^Firefox · \d\d\/\d\d \d\d:\d\d–\d\d:\d\d · 16 connections$/.test(hover), hover);
  // The daemon aligns buckets to the hour, so labels print the real minute
  // of the boundary rather than assuming :00 (a half-hour zone shows :30).
  assert.ok(I.timelineLabels(raw).every(l => /^\d\d:\d\d$/.test(l.label)), "hour labels carry minutes");
  assert.ok(I.timelineSummary(raw).startsWith("5 apps over 24 hourly buckets"));
  assert.ok(I.timelineSummary(raw).endsWith("counts are a floor."));
  assert.strictEqual(I.timelineSummary(null), "No timeline yet.");
  assert.strictEqual(I.timelineSummary({ buckets: 3, total: [0, 0, 0] }), "No observations in retained history for this window.");
  assert.deepStrictEqual(I.timelineRows("junk"), []);
});

test("a timed block is offered only when every gate the helper enforces is open", () => {
  const app = { id: "curl", name: "curl", pids: [7], system: false, blocked: false };
  const base = { app, ip: "203.0.113.7", port: 443, blockingReady: true, helperBusy: false, current: true, enforcementPaused: false,
    rules: [], helperId: CM.helperId, isBlockable: CM.isBlockable, hostWideUnsafe: () => false, now: 1 };
  assert.deepStrictEqual(I.destinationBlockState(base), { canBlock: true, reason: "", existingRule: null, appId: "curl" });
  const why = (patch) => I.destinationBlockState(Object.assign({}, base, patch)).reason;
  assert.strictEqual(why({ app: null }), "App is not in the current list");
  assert.strictEqual(why({ app: Object.assign({}, app, { id: "system", system: true }) }), "System and unknown rows cannot be blocked");
  assert.strictEqual(why({ app: Object.assign({}, app, { blocked: true }) }), "The whole app is blocked already");
  assert.strictEqual(why({ app: Object.assign({}, app, { pids: [] }) }), "No running process to scope the rule to");
  assert.strictEqual(why({ blockingReady: false }), "Blocking needs the installed helper");
  assert.strictEqual(why({ enforcementPaused: true }), "Enforcement is paused; the rule would wait for resume");
  assert.strictEqual(why({ helperBusy: true }), "The helper is busy");
  assert.strictEqual(why({ current: false }), "Monitoring is not current");
  assert.strictEqual(why({ hostWideUnsafe: () => true }), "This address is one the host cannot afford to lose");
  const ruled = I.destinationBlockState(Object.assign({}, base, { rules: [{ app: "curl", ip: "203.0.113.7", expiresAt: 9 }] }));
  assert.strictEqual(ruled.reason, "Already blocked by a timed rule");
  assert.strictEqual(ruled.existingRule.ip, "203.0.113.7");
  assert.strictEqual(I.destinationBlockState(Object.assign({}, base, { rules: [{ app: "curl", ip: "198.51.100.1" }] })).reason, "One timed rule per app; 198.51.100.1 is already ruled");
  assert.strictEqual(I.destinationBlockState(Object.assign({}, base, { app: Object.assign({}, app, { id: "My App" }), rules: [{ app: "my-app", ip: "1.1.1.1" }] })).existingRule.ip, "1.1.1.1", "rules are keyed by helper id");
  assert.strictEqual(I.destinationBlockState({ ip: "" }).canBlock, false);
  assert.deepStrictEqual(I.BLOCK_DURATIONS.map(d => d.seconds), [300, 900, 3600], "the helper accepts exactly these");
});

console.log("test_intel.js round two ok");
