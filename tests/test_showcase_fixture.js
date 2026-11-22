"use strict";
// tests/qml/Fixture.js "showcase": the model preview.png is rendered from
// (tests/qml/make-preview.sh). The picture is public, so what goes into it is
// checked here: no address that could be anyone's, no host name that
// resolves, and a model the panel can draw.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const c = {};
vm.createContext(c);
vm.runInContext(fs.readFileSync(path.join(__dirname, "qml/Fixture.js"), "utf8"), c);
const m = c.models.showcase;
assert.ok(m, "Fixture.models.showcase");

// RFC 5737 (TEST-NET-1/2/3) and RFC 3849 (2001:db8::/32): set aside for
// documentation, routed nowhere.
const documentation = (ip) => /^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}$/.test(ip) || /^2001:db8:/i.test(ip);

const ids = Object.keys(m.connections);
assert.ok(ids.length >= 10, "enough to look like a machine in use: " + ids.length);
assert.strictEqual(m.count, ids.length, "the count is the connections");
let fromApps = 0;
for (const app of m.ordered) {
  assert.strictEqual(m.apps[app.id], app);
  assert.ok(app.name && app.connections.length > 0, app.id);
  for (const conn of app.connections) {
    fromApps += 1;
    assert.strictEqual(m.connections[conn.id], conn, conn.id + " is listed once, under its id");
    assert.ok(documentation(conn.remote.ip), conn.id + ": " + conn.remote.ip + " is not a documentation address");
    assert.ok(documentation(conn.local.ip), conn.id + ": local " + conn.local.ip);
    assert.ok(/\.example$/.test(conn.hostname), conn.id + ": " + conn.hostname + " is not under .example");
    assert.ok(/^[A-Z]{2}$/.test(conn.country), conn.id + ": country");
    assert.ok(Math.abs(conn.lat) <= 90 && Math.abs(conn.lon) <= 180 && !(conn.lat === 0 && conn.lon === 0), conn.id + ": somewhere to draw to");
    assert.strictEqual(conn.app.id, app.id);
  }
  // A blocked app is in the model's block record, and nothing else is.
  assert.strictEqual(Boolean(m.blocked[app.id]), app.blocked === true, app.id + ": blocked on the row and in the record");
}
assert.strictEqual(fromApps, ids.length, "no connection is listed under two apps, or under none");
assert.ok(Object.keys(m.blocked).length >= 1, "the picture shows a block");
// Every connection has an arc, and the other scenarios still have none.
assert.strictEqual(c.arcs(m).length, ids.length);
// The checks' own scenarios are what they were.
assert.strictEqual(c.models.populated.count, 8);
assert.strictEqual(c.models.many.count, 20);
assert.strictEqual(c.models.empty.count, 0);

// The harness draws arcs only for this scenario, and a shot can name it.
const harness = fs.readFileSync(path.join(__dirname, "qml/panel-harness.qml"), "utf8");
assert.ok(harness.includes('function drawableArcs() { return Quickshell.env("VALLUM_SCENARIO") === "showcase" ? Fixture.arcs(model) : [] }'));
const runner = fs.readFileSync(path.join(__dirname, "qml/run-runtime.sh"), "utf8");
assert.ok(/for key in HOME PATH TZ [^\n]*\bVALLUM_SCENARIO\b[^\n]*\bVALLUM_BLOCK_READY\b/.test(runner), "the scenario reaches the panel");
assert.ok(runner.includes('export VALLUM_SCENARIO="${shot_scenario:-populated}"'), "a shot without a scenario is the one the checks use");

console.log("showcase fixture ok");
