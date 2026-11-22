"use strict";
// The panel's hotkey offer (js/Binds.js) across the plugin id change.
//
// Through 0.4.6 the plugin was ai.kub0.vallum, and a hotkey written then runs
// `omarchy-shell shell toggle ai.kub0.vallum '{}'`: a plugin that no longer
// exists. Read as someone else's bind it would block our own keys; read as a
// working bind of ours the offer would never come back. It is neither.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log("  ok  " + name);
}

// Binds.js is a QML library (`.pragma library`, no exports): run it as a script.
const src = fs.readFileSync(path.join(__dirname, "../js/Binds.js"), "utf8").replace(/^\.pragma library\s*$/m, "");
const B = {};
vm.createContext(B);
vm.runInContext(src, B);

const SUPER = 64, SHIFT = 1, ALT = 8;
const NEW_CMD = "omarchy-shell shell toggle ai.kub0.agent '{}'";
const OLD_CMD = "omarchy-shell shell toggle ai.kub0.vallum '{}'";
function bind(modmask, key, description, arg) {
  return { modmask: modmask, key: key, description: description, dispatcher: "exec", arg: arg };
}
const someoneElse = bind(SUPER + ALT, "S", "Screenshot", "omarchy-cmd-screenshot");

test("the hotkey opens the plugin under its id now", () => {
  assert.strictEqual(B.PLUGIN_ID, "ai.kub0.agent");
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "../manifest.json"), "utf8"));
  assert.strictEqual(manifest.id, B.PLUGIN_ID, "the manifest and the hotkey name one plugin");
  assert.strictEqual(B.CANDIDATES[0].cmd, NEW_CMD);
});

test("with no hotkey the preferred keys are offered", () => {
  const p = B.plan([]);
  assert.strictEqual(p.needed, true);
  assert.strictEqual(p.toAdd.length, 1);
  assert.strictEqual(p.toAdd[0].chosen, "SUPER + ALT + S");
  assert.strictEqual(B.luaBlock(p.toAdd), 'o.bind("SUPER + ALT + S", "kub0", "' + NEW_CMD + '")');
});

test("a working hotkey is left alone", () => {
  const p = B.plan([bind(SUPER + ALT, "S", "kub0", NEW_CMD)]);
  assert.strictEqual(p.needed, false);
  assert.strictEqual(p.toAdd.length, 0);
});

test("a hotkey written under the old id is not a working one: the offer comes back", () => {
  const stale = bind(SUPER + ALT, "S", "Vallum", OLD_CMD);
  assert.strictEqual(B.isStale(stale), true);
  assert.strictEqual(B.isOurs(stale), true, "it is ours, never a conflict");
  assert.strictEqual(B.oursCount([stale]), 0, "and it opens nothing, so it is not one we have");
  const p = B.plan([stale]);
  assert.strictEqual(p.needed, true);
  assert.strictEqual(p.toAdd.length, 1);
  assert.strictEqual(p.toAdd[0].chosen, "SUPER + ALT + S", "on the keys it already holds");
  assert.strictEqual(p.toAdd[0].cmd, NEW_CMD);
  assert.strictEqual(p.skipped.length, 0);
});

test("the old hotkey on the alternate keys is replaced there, not skipped as taken", () => {
  // The layout this was found on: the preferred keys belong to another app,
  // so the panel's hotkey sits on the alternate, under the old id and title.
  const stale = bind(SUPER + SHIFT + ALT, "S", "Vallum", OLD_CMD);
  const p = B.plan([someoneElse, stale]);
  assert.strictEqual(p.needed, true);
  assert.strictEqual(p.skipped.length, 0, JSON.stringify(p.skipped));
  assert.strictEqual(p.toAdd.length, 1);
  assert.strictEqual(p.toAdd[0].chosen, "SUPER + SHIFT + ALT + S");
  assert.strictEqual(B.luaBlock(p.toAdd), 'o.bind("SUPER + SHIFT + ALT + S", "kub0", "' + NEW_CMD + '")');
});

test("someone else's keys are still stepped around, and still reported when both are taken", () => {
  const p = B.plan([someoneElse]);
  assert.strictEqual(p.toAdd[0].chosen, "SUPER + SHIFT + ALT + S");
  const other = bind(SUPER + SHIFT + ALT, "S", "Other", "something-else");
  const q = B.plan([someoneElse, other]);
  assert.strictEqual(q.toAdd.length, 0);
  assert.strictEqual(q.skipped.length, 1);
  assert.strictEqual(q.skipped[0].conflict, "Screenshot");
});

test("a bind that names both ids is the new one", () => {
  const both = bind(SUPER + ALT, "S", "kub0", NEW_CMD + " # was ai.kub0.vallum");
  assert.strictEqual(B.isStale(both), false);
  assert.strictEqual(B.plan([both]).needed, false);
});

console.log(passed + " hotkey tests passed");
