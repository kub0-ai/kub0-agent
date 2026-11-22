"use strict";
// The panel half of the exec-gate wire contract (daemon/tests/wire_contract.rs).
//
// tests/fixtures/execgate-contract.json is generated from the daemon's
// ExecGateFrame with every field populated, plus the fleet event that carries
// it. Kub0.applyFleet is an ALLOW-LIST: before this test the whole `execGate`
// object was dropped there, so the panel could not show a single deny. Every
// leaf the daemon sends must come out of applyFleet unchanged, or be named in
// NOT_KEPT with a reason.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const K = require("../js/Kub0.js");

const fixture = JSON.parse(fs.readFileSync(
  path.join(__dirname, "fixtures/execgate-contract.json"), "utf8"));
const wire = fixture.execGate;

// Sent by the daemon, deliberately not kept. Each needs a reason, and a stale
// entry (one the panel now keeps, or the daemon no longer sends) fails too.
const NOT_KEPT = {};

function leaves(v, prefix, out) {
  if (v !== null && typeof v === "object") {
    if (Array.isArray(v))
      v.forEach(function (x, i) { leaves(x, prefix + "[" + i + "]", out); });
    else
      Object.keys(v).forEach(function (k) { leaves(v[k], prefix ? prefix + "." + k : k, out); });
  } else {
    out.push([prefix, v]);
  }
  return out;
}

function at(obj, p) {
  const parts = p.replace(/\[(\d+)\]/g, ".$1").split(".");
  let cur = obj;
  for (const part of parts) {
    if (cur === null || typeof cur !== "object" || !Object.prototype.hasOwnProperty.call(cur, part))
      return { found: false };
    cur = cur[part];
  }
  return { found: true, value: cur };
}

function shape(p) {
  return p.replace(/\[\d+\]/g, "");
}

function checkEveryFieldSurvives(label, k) {
  const kept = k.execGate;
  assert.ok(kept && typeof kept === "object", label + ": execGate did not reach the model");
  const dropped = [];
  const exempted = {};
  for (const [p, value] of leaves(wire, "", [])) {
    const got = at(kept, p);
    const reason = NOT_KEPT[shape(p)];
    if (reason !== undefined) {
      exempted[shape(p)] = true;
      assert.ok(!got.found, label + ": NOT_KEPT lists " + p + " but the panel now keeps it; delete the entry");
      continue;
    }
    if (!got.found || got.value !== value)
      dropped.push(p + " (sent " + JSON.stringify(value) + ", kept " +
        (got.found ? JSON.stringify(got.value) : "nothing") + ")");
  }
  assert.deepStrictEqual(dropped, [],
    label + ": Kub0.applyFleet drops execGate fields the daemon sends. Name them in " +
    "normalizeExecGate, or add them to NOT_KEPT with a reason:\n  " + dropped.join("\n  "));
  for (const k2 of Object.keys(NOT_KEPT))
    assert.ok(exempted[k2], "NOT_KEPT lists " + k2 + ", which the daemon no longer sends; delete the entry");
}

function testTheFixtureIsTheDaemonsShape() {
  for (const k of ["enabled", "armed", "keys", "source", "observedAt", "counters", "denies", "trusted", "oncePending"])
    assert.ok(Object.prototype.hasOwnProperty.call(wire, k), "fixture has no " + k);
  assert.strictEqual(fixture.events.fleet.type, "fleet");
  assert.deepStrictEqual(fixture.events.fleet.execGate, wire, "the fleet event carries the frame verbatim");
  assert.strictEqual(fixture.events.fleet.denylistLive, true);
}

function testEveryFieldSurvivesApplyFleetAndCopy() {
  // The fixture's fleet event is a default snapshot (not connected) carrying
  // the frame; the stream flag is only meaningful with an account.
  const k = K.applyFleet(K.emptyKub0(), Object.assign({}, fixture.events.fleet, { connected: true }));
  checkEveryFieldSurvives("applyFleet", k);
  checkEveryFieldSurvives("copyKub0", K.copyKub0(k));
  // The gate is this machine's: a disconnected frame still carries it.
  const off = K.applyFleet(K.emptyKub0(), Object.assign({}, fixture.events.fleet, { connected: false }));
  checkEveryFieldSurvives("disconnected", off);
  assert.strictEqual(off.denylistLive, null, "no account, no stream");
  assert.strictEqual(k.denylistLive, true);
  // A frame without the field (older daemon) keeps the last-good gate.
  const older = K.applyFleet(k, { type: "fleet", connected: true });
  checkEveryFieldSurvives("older daemon", older);
}

function testTheSettingsCopyReadsTheFixture() {
  const k = K.applyFleet(K.emptyKub0(), fixture.events.fleet);
  // The fixture sets every field, so its gate is on the list saved before the
  // daemon started. The heading and a row say so: those keys are that old.
  assert.strictEqual(K.execGateHeading(k), "Exec gate: armed, 3 keys from the saved org list (no sync since the daemon started)");
  const facts = K.execGateFacts(k);
  const byLabel = {};
  for (const f of facts) byLabel[f.label] = f;
  assert.strictEqual(byLabel["Org list"].value, "saved copy, no sync since the daemon started");
  assert.strictEqual(byLabel["Org list"].tone, "warn");
  // Once a sync has replaced it, neither is there.
  const synced = K.applyFleet(K.emptyKub0(), { type: "fleet", execGate: Object.assign({}, wire, { listRestored: false }) });
  assert.strictEqual(K.execGateHeading(synced), "Exec gate: armed, 3 keys");
  assert.ok(!K.execGateFacts(synced).some(function (f) { return f.label === "Org list"; }));
  assert.strictEqual(byLabel.State.value, "armed");
  assert.strictEqual(byLabel.Blocked.value, "1");
  assert.strictEqual(byLabel.Blocked.tone, "warn");
  assert.strictEqual(byLabel["Allowed once"].value, "2");
  assert.ok(byLabel["Trusted here"].value.startsWith("1 digest"));
  assert.strictEqual(byLabel["Fail-open"].value, String(4 + 10 + 11 + 9), "failopen + deadline + overflow + error");
  assert.strictEqual(byLabel["Pending allows"].value, "1 one-shot allow");
  const line = K.execDenyLine(k.execGate.denies[0]);
  assert.ok(line.indexOf("fixture-sample") >= 0, line);
  assert.ok(line.indexOf("not blocked (fail-open)") >= 0, line);
  assert.ok(line.indexOf("fixture reason") >= 0, line);
  assert.ok(K.trustedLine(k.execGate.trusted[0]).startsWith("fixture-trusted · 2222222222222222…"));
  // Source states the heading has to be honest about.
  const mirror = K.applyFleet(K.emptyKub0(), { type: "fleet", execGate: Object.assign({}, wire, { source: "mirror", armed: false }) });
  assert.strictEqual(K.execGateHeading(mirror), "Exec gate: loaded, idle until the first deny-list sync");
  const stale = K.applyFleet(K.emptyKub0(), { type: "fleet", execGate: Object.assign({}, wire, { source: "stale" }) });
  assert.ok(K.execGateHeading(stale).indexOf("stale") >= 0);
  assert.ok(K.execGateHeading(K.emptyKub0()).indexOf("not reported") >= 0);
  const off = K.applyFleet(K.emptyKub0(), { type: "fleet", execGate: { source: "live", enabled: false } });
  assert.strictEqual(K.execGateHeading(off), "Exec gate: off");
  // Junk never becomes a row.
  const junk = K.normalizeExecGate({ source: "bogus", keys: -5, denies: [null, {}, { sha256: "" }, { sha256: "abc", decision: "nuke" }], trusted: ["x", { sha256: "d" }] });
  assert.strictEqual(junk.source, "none");
  assert.strictEqual(junk.keys, 0);
  assert.strictEqual(junk.denies.length, 1);
  assert.strictEqual(junk.denies[0].decision, "blocked", "an unknown decision reads as the safe one");
  assert.strictEqual(junk.trusted.length, 1);
}

testTheFixtureIsTheDaemonsShape();
testEveryFieldSurvivesApplyFleetAndCopy();
testTheSettingsCopyReadsTheFixture();
console.log("test_execgate_contract.js ok");
