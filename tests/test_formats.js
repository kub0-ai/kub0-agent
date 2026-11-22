"use strict";
// The timeStyle and byteUnits preferences: the formatters in js/Ux.js, and
// every function in js/ that prints a timestamp or a byte count taking the
// panel's `ux` object as an optional last argument.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const U = require("../js/Ux.js");
const P = require("../js/Prefs.js");
const Traffic = require("../js/Traffic.js");
const Intel = require("../js/Intel.js");
const History = require("../js/History.js");
const Endpoints = require("../js/Endpoints.js");
const Evidence = require("../js/Evidence.js");
const Activity = require("../js/Activity.js");
const Kub0 = require("../js/Kub0.js");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log("  ok  " + name);
}

const KIT = { caption: 10, bodySmall: 11, body: 12, subtitle: 13, display: 24 };
function ux(timeStyle, byteUnits) {
  return U.metrics(KIT, "normal", "normal", timeStyle, byteUnits);
}
const DEFAULT = ux("mixed", "binary");
const RELATIVE = ux("relative", "decimal");
const CLOCK = ux("clock", "decimal");

// Local time, so the expectations hold in any time zone.
const NOW = new Date(2026, 10, 15, 9, 40, 0).getTime();          // 15 Nov 2026 09:40:00
const TODAY = new Date(2026, 10, 15, 9, 38, 23).getTime();        // 97 s before
const YESTERDAY = new Date(2026, 10, 14, 21, 5, 9).getTime();
const LAST_YEAR = new Date(2025, 2, 4, 7, 8, 9).getTime();

// ------------------------------------------------------------ the choices

test("the store and the tables offer the same choices", () => {
  assert.deepStrictEqual(U.values(U.TIME_STYLES), P.TIME_STYLES);
  assert.deepStrictEqual(U.values(U.BYTE_UNITS), P.BYTE_UNITS);
  for (const row of U.TIME_STYLES.concat(U.BYTE_UNITS)) assert.ok(row.label.length > 0);
});

test("the defaults are what the panel always printed, and a hand edit is clamped", () => {
  const d = P.defaults();
  assert.strictEqual(d.timeStyle, "mixed");
  assert.strictEqual(d.byteUnits, "binary");
  assert.strictEqual(P.sanitize({ timeStyle: "iso" }).timeStyle, "mixed");
  assert.strictEqual(P.sanitize({ timeStyle: "clock" }).timeStyle, "clock");
  assert.strictEqual(P.sanitize({ byteUnits: "bits" }).byteUnits, "binary");
  assert.strictEqual(P.sanitize({ byteUnits: "decimal" }).byteUnits, "decimal");
});

test("the defaults carry no formatter, so every caller prints its own", () => {
  assert.strictEqual(DEFAULT.time, null);
  assert.strictEqual(DEFAULT.bytes, null);
  assert.strictEqual(ux(undefined, undefined).time, null);
  assert.strictEqual(ux("sideways", "nibbles").bytes, null);
  assert.strictEqual(typeof RELATIVE.time, "function");
  assert.strictEqual(typeof CLOCK.time, "function");
  assert.strictEqual(typeof CLOCK.bytes, "function");
});

// --------------------------------------------------------- the formatters

test("how long ago: one spelling, both directions", () => {
  assert.strictEqual(U.relativeTime(NOW, NOW), "just now");
  assert.strictEqual(U.relativeTime(NOW - 5000, NOW), "5s ago");
  assert.strictEqual(U.relativeTime(TODAY, NOW), "2m ago");
  assert.strictEqual(U.relativeTime(NOW - 3 * 3600000, NOW), "3h ago");
  assert.strictEqual(U.relativeTime(NOW - 4 * 86400000, NOW), "4d ago");
  assert.strictEqual(U.relativeTime(NOW + 25 * 60000, NOW), "in 25m", "a time still to come");
  assert.strictEqual(U.relativeTime(0, NOW), "unknown");
  assert.strictEqual(U.relativeTime(NaN, NOW), "unknown");
  assert.strictEqual(U.relativeTime("yesterday", NOW), "unknown");
});

test("clock time: as short as stays unambiguous", () => {
  assert.strictEqual(U.clockTime(TODAY, NOW), "09:38:23", "today: the time, to the second");
  assert.strictEqual(U.clockTime(YESTERDAY, NOW), "Nov 14 21:05", "this year: the day and the minute");
  assert.strictEqual(U.clockTime(LAST_YEAR, NOW), "2025-03-04 07:08", "older: the full date");
  assert.strictEqual(U.clockTime(0, NOW), "unknown");
  assert.strictEqual(U.clockTime(undefined, NOW), "unknown");
});

test("decimal bytes count in thousands", () => {
  assert.strictEqual(U.decimalBytes(0), "0 B");
  assert.strictEqual(U.decimalBytes(999), "999 B");
  assert.strictEqual(U.decimalBytes(1000), "1.0 kB");
  assert.strictEqual(U.decimalBytes(1500000), "1.5 MB");
  assert.strictEqual(U.decimalBytes(2.5e9), "2.5 GB");
  assert.strictEqual(U.decimalBytes(-1), "unknown");
  assert.strictEqual(U.decimalBytes(null), "unknown");
});

// ---------------------------------------- each caller: default is untouched

const APP = { traffic: { measured: 2, txRate: 1024, rxRate: 32768, txBytes: 65536, rxBytes: 4194304 } };
const PIVOT = { connections: 3, live: 1, first: NOW - 3 * 3600000, last: TODAY, tx: 1500000, rx: 64000, apps: [], destinations: [] };
const RULE = { kind: "cidr", value: "192.0.2.0/24", note: "probe", hits: 2, lastHit: TODAY };
const ACCOUNT = { connected: true, endpointsUpdatedAt: NOW - 5000, endpointsRefreshOk: true };
const CONN = { exe: "/usr/bin/probe", app: { pid: 7 }, uid: 1000, remote: { ip: "192.0.2.1", port: 443 },
  local: { ip: "10.0.0.2", port: 50000 }, proto: "tcp", state: "established",
  evidence: { ownerMethod: "procfs", source: "sock_diag", recordedAt: TODAY } };
const DENY = { ts: TODAY, comm: "probe", exe: "/usr/bin/probe", sha256: "a".repeat(64), decision: "deny" };
const POLICY = { effectiveAction: "monitor", kind: "country", size: 3, hits: 0, blocked: 0, wouldBlock: 0, shared: 0,
  suppressed: 0, serverWithheld: 0, snoozedUntil: NOW + 25 * 60000 };
const ENTRIES = [{ ts: TODAY, kind: "blocked", app: { name: "Probe", id: "probe" } }];

function each(fn) {
  return { none: fn(undefined), def: fn(DEFAULT), rel: fn(RELATIVE), clock: fn(CLOCK) };
}

test("with the defaults every caller prints exactly what it does with no ux at all", () => {
  const calls = [
    (f) => Traffic.bytes(1500000, f),
    (f) => Traffic.summary(APP, true, f),
    (f) => Intel.bytes(1500000, f),
    (f) => Intel.ago(TODAY, NOW, f),
    (f) => Intel.ruleDetail(RULE, NOW, f),
    (f) => JSON.stringify(Intel.pivotFacts(PIVOT, NOW, f)),
    (f) => History.time(TODAY, f, NOW),
    (f) => Endpoints.time(new Date(TODAY).toISOString(), f, NOW),
    (f) => Endpoints.inventoryStatus(ACCOUNT, [], NOW, f),
    (f) => JSON.stringify(Evidence.describe(CONN, f, NOW)),
    (f) => Activity.formatTime(TODAY, f, NOW),
    (f) => JSON.stringify(Activity.digestEntries(ENTRIES, "", 4, f, NOW)),
    (f) => Kub0.execDenyLine(DENY, f, NOW),
    (f) => Kub0.policyRuleDetail(POLICY, f, NOW)
  ];
  calls.forEach((fn, i) => {
    const r = each(fn);
    assert.strictEqual(r.def, r.none, "call " + i + " changes nothing at the defaults");
    // A caller whose own default is already "how long ago" reads the same in
    // that style; the clock style is then the one that has to differ.
    assert.ok(r.rel !== r.none || r.clock !== r.none, "call " + i + " follows the preference: " + r.rel + " / " + r.clock);
  });
});

// ------------------------------------------------ each caller: the choices

test("sizes and speeds follow the units", () => {
  assert.strictEqual(Traffic.bytes(1500000), "1.4 MiB");
  assert.strictEqual(Traffic.bytes(1500000, CLOCK), "1.5 MB");
  assert.strictEqual(Traffic.bytes(-1, CLOCK), "unknown");
  assert.strictEqual(Traffic.summary(APP, true, CLOCK),
    "↑ 1.0 kB/s  ↓ 32.8 kB/s · sampled session ↑ 65.5 kB ↓ 4.2 MB");
  assert.strictEqual(Intel.bytes(1500000, RELATIVE), "1.5 MB");
});

test("the Intel drawer and a watch rule say when in the chosen way", () => {
  const seen = (f) => Intel.pivotFacts(PIVOT, NOW, f).filter((r) => r.label === "Seen")[0].value;
  const moved = (f) => Intel.pivotFacts(PIVOT, NOW, f).filter((r) => r.label === "Sampled transfer")[0].value;
  assert.strictEqual(seen(CLOCK), "first 06:40:00, last 09:38:23");
  assert.strictEqual(seen(RELATIVE), "first 3h ago, last 2m ago");
  assert.strictEqual(moved(CLOCK), "↑ 1.5 MB ↓ 64.0 kB");
  assert.strictEqual(Intel.ruleDetail(RULE, NOW, CLOCK), "probe · 2 hits, last 09:38:23");
  assert.strictEqual(Intel.ago(0, NOW, CLOCK), "never", "nothing to show is still never");
});

test("History, Endpoints and evidence drop the long date for the chosen reading", () => {
  assert.strictEqual(History.time(TODAY, CLOCK, NOW), "09:38:23");
  assert.strictEqual(History.time(YESTERDAY, RELATIVE, NOW), "13h ago");
  assert.strictEqual(Endpoints.time(new Date(YESTERDAY).toISOString(), CLOCK, NOW), "Nov 14 21:05");
  assert.strictEqual(Endpoints.time("not a date", CLOCK, NOW), "Not reported");
  assert.strictEqual(Endpoints.inventoryStatus(ACCOUNT, [], NOW, RELATIVE).indexOf("Last successful inventory: 5s ago.") >= 0, true);
  assert.strictEqual(Endpoints.inventoryStatus(ACCOUNT, [], NOW, CLOCK).indexOf("Last successful inventory: 09:39:55.") >= 0, true);
  const stamp = (f) => Evidence.describe(CONN, f, NOW).filter((r) => r.label === "Source timestamp")[0].value;
  assert.strictEqual(stamp(CLOCK), "09:38:23");
  assert.strictEqual(stamp(RELATIVE), "2m ago");
  const none = { evidence: {} };
  assert.strictEqual(Evidence.describe(none, CLOCK, NOW).filter((r) => r.label === "Source timestamp")[0].value, "Unknown");
});

test("activity lines, gate matches and a snooze follow it too", () => {
  assert.strictEqual(Activity.formatTime(TODAY, RELATIVE, NOW), "2m ago");
  assert.strictEqual(Activity.formatTime(TODAY, CLOCK, NOW), "09:38:23");
  assert.ok(JSON.stringify(Activity.digestEntries(ENTRIES, "", 4, RELATIVE, NOW)).indexOf("2m ago  ") >= 0,
    "the digest line opens with the chosen reading");
  assert.ok(Kub0.execDenyLine(DENY, RELATIVE, NOW).indexOf("2m ago") === 0);
  assert.ok(Kub0.policyRuleDetail(POLICY, RELATIVE, NOW).indexOf("snoozed until in 25m") >= 0);
  assert.ok(Kub0.policyRuleDetail(POLICY, CLOCK, NOW).indexOf("snoozed until 10:05:00") >= 0);
});

// --------------------------------------------- the views pass the choice on

test("every view hands its ux to the formatter it calls", () => {
  // A call without it prints the default whatever Settings says.
  const root = path.join(__dirname, "..");
  const call = /\b(Traffic\.(bytes|summary)|Intel\.(pivotFacts|ruleDetail|ago|bytes)|History\.time|Endpoints\.(time|inventoryStatus)|Evidence\.describe|Kub0\.(execDenyLine|policyRuleDetail|clock)|Activity\.(digestEntries|formatTime))\(/;
  let seen = 0;
  for (const f of fs.readdirSync(root).filter((n) => n.endsWith(".qml"))) {
    fs.readFileSync(path.join(root, f), "utf8").split("\n").forEach((l, i) => {
      if (!call.test(l)) return;
      seen += 1;
      assert.ok(/root\.ux\b/.test(l), f + ":" + (i + 1) + ": pass root.ux to " + call.exec(l)[1]);
    });
  }
  assert.ok(seen >= 9, "the calls are there to check (" + seen + ")");
});

test("no view formats a timestamp by itself", () => {
  const root = path.join(__dirname, "..");
  for (const f of fs.readdirSync(root).filter((n) => n.endsWith(".qml"))) {
    fs.readFileSync(path.join(root, f), "utf8").split("\n").forEach((l, i) => {
      if (/toLocale(String|TimeString|DateString)\(/.test(l))
        assert.ok(/root\.ux\.time \?/.test(l), f + ":" + (i + 1) + ": a locale date with no way to follow the Times setting");
    });
  }
});

console.log(passed + " format tests passed");
