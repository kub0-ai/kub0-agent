"use strict";
// The panel half of daemon/tests/wire_contract.rs.
//
// tests/fixtures/connection-contract.json is generated from the daemon's serde
// structs, with every field populated. This drives it through the same ingest
// path Service.qml uses (Health.applyIngest -> ConnectionModel.applyLine with
// deferRebuild) and requires every field the daemon sends to come out the
// other side unchanged, unless NOT_KEPT below says why it does not.
//
// normalizeConn is an ALLOW-LIST. A field it does not name is invisible to the
// whole UI, and every one of these misses shipped green because the test on
// each side of the seam used its own hand-written shape: clue and tag (PR #8),
// a fleet policy name, and hostname: the daemon sent the PTR name for every
// row it resolved and the Live tab never once showed it.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const CM = require("../ConnectionModel.js");
const H = require("../js/Health.js");
const P = require("../js/Peers.js");

const fixture = JSON.parse(fs.readFileSync(
  path.join(__dirname, "fixtures/connection-contract.json"), "utf8"));
const wire = fixture.connection;

// Sent by the daemon, deliberately not kept by the panel. Every entry needs a
// reason, must still be sent, and must still be dropped: a stale entry fails
// too, so this cannot rot into a blanket exemption.
const NOT_KEPT = {
  "tag.network_key": "the row's own networkKey; the daemon only attaches a tag to rows of the network it names",
  "tag.ptr_suffix": "fleet-scoring input the daemon has already applied; nothing in the panel reads it",
  "tag.ts": "tag-store bookkeeping; the panel says who named a network (source), not when"
};

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

// The exemption key for a leaf path: array indexes dropped.
function shape(p) {
  return p.replace(/\[\d+\]/g, "");
}

// Service.qml: Health.applyIngest(health, model, line, now, applyDeferred).
function applyDeferred(m, line, now) {
  return CM.applyLine(m, line, now, { deferRebuild: true });
}

function ingest(lines) {
  let health = H.markSocketUp(H.markDaemonAvailable(H.emptyHealth(), true), 1000);
  let model = CM.emptyState();
  let now = 2000;
  for (const line of lines) {
    const out = H.applyIngest(health, model, line, now, applyDeferred);
    assert.strictEqual(out.decision.applyModel, true,
      "the panel refused a line the daemon generated: " + line.slice(0, 120));
    health = out.health;
    model = out.model;
    now += 1;
  }
  CM.settle(model, now);
  return model;
}

function checkEveryFieldSurvives(label, model) {
  const kept = model.connections[wire.id];
  assert.ok(kept, label + ": the connection did not reach the model");
  const dropped = [];
  const exempted = {};
  for (const [p, value] of leaves(wire, "", [])) {
    const got = at(kept, p);
    const reason = NOT_KEPT[shape(p)];
    if (reason !== undefined) {
      exempted[shape(p)] = true;
      assert.ok(!got.found,
        label + ": NOT_KEPT lists " + p + " but the panel now keeps it; delete the entry");
      continue;
    }
    if (!got.found || got.value !== value)
      dropped.push(p + " (sent " + JSON.stringify(value) + ", kept " +
        (got.found ? JSON.stringify(got.value) : "nothing") + ")");
  }
  assert.deepStrictEqual(dropped, [],
    label + ": normalizeConn drops fields the daemon sends. Name them in normalizeConn, " +
    "or add them to NOT_KEPT with a reason:\n  " + dropped.join("\n  "));
  for (const k of Object.keys(NOT_KEPT))
    assert.ok(exempted[k], "NOT_KEPT lists " + k + ", which the daemon no longer sends; delete the entry");
}

function testEveryDaemonFieldSurvivesBothCarriers() {
  // snapshot (greeting, retag) and connect (every new row, and a late PTR
  // name) carry the same record; both reach putConnection.
  checkEveryFieldSurvives("snapshot",
    ingest([JSON.stringify(fixture.events.snapshot)]));
  const empty = Object.assign({}, fixture.events.snapshot, { connections: [] });
  checkEveryFieldSurvives("connect",
    ingest([JSON.stringify(empty), JSON.stringify(fixture.events.connect)]));
}

function testTheFixtureIsTheDaemonsShape() {
  // Guard the guard: a fixture that lost its fields would pass the check above.
  for (const k of ["hostname", "clue", "tag", "evidence", "policy", "uid", "reason", "exe", "bytes"])
    assert.ok(Object.prototype.hasOwnProperty.call(wire, k), "fixture has no " + k);
  assert.strictEqual(fixture.events.connect.type, "connect");
  assert.strictEqual(fixture.events.connect.id, wire.id, "connect flattens the record");
  assert.deepStrictEqual(fixture.events.snapshot.connections[0], wire);
}

function testTheLiveTabNamesAPeerByItsHostname() {
  // What the Live tab row actually prints (Panel.qml: Peers.summary over
  // appData.connections). With no human name and no strong clue, the PTR name
  // is the answer, not the bare address.
  const bare = JSON.parse(JSON.stringify(fixture.events.snapshot));
  delete bare.connections[0].tag;
  delete bare.connections[0].clue;
  const model = ingest([JSON.stringify(bare)]);
  const app = model.apps[wire.app.id];
  assert.ok(app, "the fixture app has no row");
  assert.strictEqual(P.peerName(app.connections[0]), wire.hostname);
  assert.strictEqual(P.summary(app), wire.hostname);
  assert.strictEqual(P.peers(app)[0].hostname, wire.hostname);
}

function testARowWithNoHostnameIsNotGivenOne() {
  // The other direction, so the fix cannot be "invent something".
  const none = JSON.parse(JSON.stringify(fixture.events.snapshot));
  delete none.connections[0].tag;
  delete none.connections[0].clue;
  delete none.connections[0].hostname;
  const model = ingest([JSON.stringify(none)]);
  const kept = model.connections[wire.id];
  assert.strictEqual(kept.hostname, "");
  assert.strictEqual(P.peerName(kept), wire.remote.ip + ":" + wire.remote.port);
}

function testALateNameUpdatesTheRowInPlace() {
  // The daemon re-sends `connect` for a known id when its PTR lands. That must
  // replace the row, not add a second one, and must not pulse "new network".
  const before = JSON.parse(JSON.stringify(fixture.events.connect));
  delete before.hostname;
  delete before.tag;
  delete before.clue;
  const empty = Object.assign({}, fixture.events.snapshot, { connections: [] });
  let model = ingest([JSON.stringify(empty), JSON.stringify(before)]);
  assert.strictEqual(model.connections[wire.id].hostname, "");
  model.pulse = false;
  const after = Object.assign({}, before, { hostname: wire.hostname });
  model = CM.applyLine(model, JSON.stringify(after), 5000);
  assert.strictEqual(Object.keys(model.connections).length, 1);
  assert.strictEqual(model.connections[wire.id].hostname, wire.hostname);
  assert.strictEqual(model.pulse, false, "a late name pulsed as a new network");
}

testTheFixtureIsTheDaemonsShape();
testEveryDaemonFieldSurvivesBothCarriers();
testTheLiveTabNamesAPeerByItsHostname();
testARowWithNoHostnameIsNotGivenOne();
testALateNameUpdatesTheRowInPlace();
console.log("test_wire_contract.js ok");
