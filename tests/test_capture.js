"use strict";
const assert = require("assert");
const fs = require("fs");
const vm = require("vm");
const Prefs = require("../js/Prefs.js");
const source = fs.readFileSync(require("path").join(__dirname, "../Service.qml"), "utf8");
const funcs = Array.from(source.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));
assert.strictEqual(Prefs.defaults().captureEnabled, false);
assert.strictEqual(Prefs.sanitize({captureEnabled:"true"}).captureEnabled, false);
assert.strictEqual(Prefs.parse(Prefs.serialize(Prefs.withValue(Prefs.defaults(), "captureEnabled", true))).prefs.captureEnabled, true);
const context = {
  prefs: Prefs.defaults(), Prefs, prefsLoaded: true, prefsSaveTimer: {restart() {}},
  daemonProc: {running:true}, shuttingDown:false, usingFallback:false, captureStatus: {}, health: {sentinel:true}, model: {count:19},
  historyRequest: "unrelated", Health: {applyIngest(){throw Error("capture must not update monitoring freshness")}},
  syncFromModel(){throw Error("capture must not change counts")},
  // Capture runs only in the panel's own daemon, so its switch decides which
  // daemon the panel reads (#61): the source is chosen again on a change.
  eventSource: "user", chosen: 0
};
context.chooseSource = () => { context.chosen += 1; };
context.root = context;
vm.createContext(context);
for (const name of ["ingest", "setPref", "resetPrefs", "startDaemon"]) {
  const fn = funcs.find(f => f[1] === name);
  assert(fn, name);
  vm.runInContext(fn[0], context);
}
context.ingest(JSON.stringify({type:"capture-status",state:"current",kernelDropped:2,collectorDropped:3,userspaceDropped:4}));
assert.strictEqual(context.captureStatus.collectorDropped, 3);
assert.strictEqual(context.model.count, 19);
assert.strictEqual(context.health.sentinel, true);
context.setPref("captureEnabled", true);
assert.strictEqual(context.daemonProc.running, false, "preference change restarts the monitor");
assert.strictEqual(context.chosen, 1, "switching capture on chooses the source again");
context.setPref("shareDestinations", true);
assert.strictEqual(context.chosen, 1, "another preference does not");
context.daemonProc.running = true;
context.resetPrefs();
assert.strictEqual(context.daemonProc.running, false, "reset also detaches capture");
assert.strictEqual(context.chosen, 2, "and so does a reset that switches capture off");
context.Health = {markDaemonAvailable(h){return h},markSocketDown(h){return h}};
context.syncHealthView = () => {};
context.vallumdPath = "/test/kub0d";
context.pluginDir = "/test";
context.adapter = {socketPath:()=>"/test/socket",stateDir:()=>"/test/state"};
context.startDaemon();
assert(!context.daemonProc.command.includes("--capture"));
// One release: the panel's daemon is the one that moves a 0.4.x state
// directory, to the path the panel names (a bare kub0d start never does).
assert(context.daemonProc.command.includes("--migrate-state"), "the panel asks for the move");
assert.strictEqual(context.daemonProc.command[context.daemonProc.command.indexOf("--state-dir") + 1], "/test/state");
context.prefs = Prefs.withValue(context.prefs, "captureEnabled", true);
context.daemonProc.running = false; // model a completed Process before its next start
context.startDaemon();
assert(context.daemonProc.command.includes("--capture"));
console.log("capture defaults, persistence, restart, counter separation and sampler freshness passed");
