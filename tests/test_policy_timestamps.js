"use strict";
const assert = require("assert");
const K = require("../js/Kub0.js");

function rule(ts) {
  return {kind: "ip", hits: 0, snoozedUntil: ts};
}
function plan(ts) {
  return {state: "enforcing", enforcing: true, entries: 1, appliedTs: ts};
}
function normalizedRule(ts) {
  return K.normalizeNetPolicy({id: "p", rules: [rule(ts)]}).rules[0];
}

// Invalid evidence must neither invent an expiry nor crash ISO formatting.
for (const ts of [8640000000000001, Number.MAX_VALUE, NaN, Infinity, -Infinity,
                  -1, -8640000000000000, -8640000000000001, 0,
                  undefined, null, "1700000000000", "2024-01-01"]) {
  assert.strictEqual(K.validPolicyTimestamp(ts), false, String(ts));
  for (const r of [rule(ts), normalizedRule(ts)]) {
    assert.strictEqual(K.policyRuleDetail(r), "no matches yet", String(ts));
  }
  for (const e of [plan(ts), K.normalizeEnforcement(plan(ts))]) {
    assert.strictEqual(K.policyEnforcementText(e), "Known applied plan: 1 range.", String(ts));
  }
}

// The exact Date limit is valid; its adjacent overflow above is not.
// Compare local HH:MM so this test also works outside UTC.
for (const ts of [1, 1700000000000, 8640000000000000]) {
  assert.strictEqual(K.validPolicyTimestamp(ts), true, String(ts));
  const d = new Date(ts);
  assert.ok(Number.isFinite(d.getTime()));
  const hhmm = String(d.getHours()).padStart(2, "0") + ":" +
    String(d.getMinutes()).padStart(2, "0");
  for (const r of [rule(ts), normalizedRule(ts)]) {
    assert.strictEqual(K.policyRuleDetail(r), "no matches yet · snoozed until " + hhmm);
  }
  for (const e of [plan(ts), K.normalizeEnforcement(plan(ts))]) {
    assert.strictEqual(K.policyEnforcementText(e),
      "Known applied plan: 1 range. Applied at " + d.toISOString() + ".");
  }
}
console.log("policy timestamp tests ok");
