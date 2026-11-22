"use strict";
const assert = require("assert");
const E = require("../js/Endpoints.js");
const now = Date.parse("2026-10-04T01:00:00Z");
const rows = [
  {nodeName:"laptop", state:"enforcing", lastSeen:"2026-10-04T00:59:00Z", agentVer:"0.2.0", arch:"x86_64"},
  {nodeName:"old-laptop", state:"monitoring", lastSeen:"2026-10-04T00:50:00Z"},
  {nodeName:"offline", state:"down", lastSeen:"2026-10-04T00:59:00Z"},
  {nodeName:"unknown", state:"unknown", lastSeen:""}
];
assert.strictEqual(E.filtered(rows, "", "", now).length, 4);
assert.deepStrictEqual(E.filtered(rows, "", "online", now).map(x=>x.nodeName), ["laptop"]);
assert.deepStrictEqual(E.filtered(rows, "", "offline", now).map(x=>x.nodeName), ["old-laptop", "offline"]);
assert.strictEqual(E.filtered(rows, "x86_64", "enforcing", now).length, 1);
assert.strictEqual(E.filtered(rows, "offline", "online", now).length, 0);
assert.strictEqual(E.state(rows[1], now - 1), "monitoring");
assert.strictEqual(E.state(rows[1], now), "down");
assert.strictEqual(E.time("invalid"), "Not reported");
assert.strictEqual(E.toggle("monitoring", "monitoring"), "");
assert.strictEqual(E.toggle("monitoring", "offline"), "offline");
console.log("test_endpoints.js ok");
for (const state of ['enforcing', 'monitoring']) {
  const row = {state, lastSeen:new Date(now + 60000).toISOString()};
  assert.strictEqual(E.state(row, now), state);
  row.lastSeen = new Date(now + 60001).toISOString();
  assert.strictEqual(E.state(row, now), 'unknown');
  for (const seen of ['', null, undefined, 'invalid']) {
    assert.strictEqual(E.state({state, lastSeen:seen}, now), 'unknown');
  }
  for (const clock of [NaN, Infinity, null, undefined, '123', 0, -1])
    assert.strictEqual(E.state({state, lastSeen:rows[0].lastSeen}, clock), 'unknown');
}
assert.strictEqual(E.age(now + 60000, now), 0);
assert.strictEqual(E.age(now + 60001, now), null);
for (const state of ['enforced', 'online', '', undefined])
  assert.strictEqual(E.state({state, lastSeen:rows[1].lastSeen}, now), 'unknown');
assert.strictEqual(E.label({state:'down', lastSeen:''}, NaN), 'Offline');
assert.strictEqual(E.ownerApps(1), '1 app with endpoint-owner IP entries reported');
assert.strictEqual(E.ownerApps(2), '2 apps with endpoint-owner IP entries reported');
assert.strictEqual(E.ownerApps(0), '0 apps with endpoint-owner IP entries reported');
for (const count of [null, undefined, -1, 1.5, '0'])
  assert.strictEqual(E.ownerApps(count), 'Apps with endpoint-owner IP entries not reported');
const account = {connected:true, endpointsUpdatedAt:now - 60000, endpointsRefreshOk:false};
assert(E.inventoryStatus(account, rows, now).includes(new Date(now - 60000).toLocaleString()));
assert(E.inventoryStatus(account, rows, now).includes('60 seconds ago'));
for (const timestamp of [0, undefined, NaN, now + 60001, '123', 1e20])
  assert(E.inventoryStatus({...account, endpointsUpdatedAt:timestamp}, rows, now).includes('date unavailable'));
assert(E.inventoryStatus({...account, endpointsRefreshOk:true}, [], now).startsWith('0 kub0 endpoints.'));
for (const query of ['laptop', '0.2.0', 'x86_64', 'linux']) {
  const searchable = [{...rows[0], kernelVersion:'Linux 6.12'}];
  assert.strictEqual(E.filtered(searchable, query, 'online', now).length, 1);
}

// Deadline scheduling shares exactly the model's skew and expiry boundaries.
const live = (seen, state = 'enforcing') => ({state, lastSeen:new Date(seen).toISOString()});
for (const state of ['enforcing', 'monitoring']) {
  const expiring = live(now - 599999, state);
  assert.strictEqual(E.nextTransitionDelay([expiring], now), 1);
  assert.strictEqual(E.state(expiring, now), state);
  assert.strictEqual(E.state(expiring, now + 1), 'down');
  assert.strictEqual(E.nextTransitionDelay([expiring], now + 1), 10000);
  const future = live(now + 60001, state);
  assert.strictEqual(E.nextTransitionDelay([future], now), 1);
  assert.strictEqual(E.state(future, now), 'unknown');
  assert.strictEqual(E.state(future, now + 1), state);
  assert.strictEqual(E.nextTransitionDelay([future], now + 1), 10000);
  assert.strictEqual(E.nextTransitionDelay([future], now + 660000), 1);
  assert.strictEqual(E.state(future, now + 660001), 'down');
}
assert.strictEqual(E.nextTransitionDelay([live(now - 598000), live(now - 599500)], now), 500);
assert.strictEqual(E.nextTransitionDelay([live(now + 65000)], now), 5000);
assert.strictEqual(E.nextTransitionDelay([live(now - 590000)], now), 10000);
for (const clock of [NaN, Infinity, null, undefined, '123', 0, -1, 1e20])
  assert.strictEqual(E.nextTransitionDelay([live(now - 599999)], clock), 10000);
for (const row of [null, {}, live(now - 599999, 'down'), live(now - 599999, 'online'),
  live(now - 600000), {state:'enforcing', lastSeen:''}, {state:'monitoring', lastSeen:'invalid'},
  {state:'enforcing', lastSeen:1e20}, {state:'enforcing', lastSeen:'+999999-01-01'},
  live(8640000000000000)])
  assert.strictEqual(E.nextTransitionDelay([row], now), 10000);
assert.strictEqual(E.nextTransitionDelay([], now), 10000);
assert.strictEqual(E.nextTransitionDelay(null, now), 10000);
console.log('endpoint deadline cases ok');
