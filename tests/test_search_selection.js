"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const H = require("../js/Health.js");

const panelSource = fs.readFileSync(path.join(__dirname, "../Panel.qml"), "utf8");
const panelFns = Array.from(panelSource.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));

function method(name) {
  const found = panelFns.find((x) => x[1] === name);
  assert.ok(found, "missing actual Panel function " + name);
  return found[0];
}

function panelAt(apps, selectedAppId) {
  const c = {
    Health: H,
    apps: apps.slice(),
    selectedAppId: selectedAppId,
    selectedIndex: -1,
    appList: null,
    searchOpen: true,
    searchQuery: "",
    service: null,
    vallum: null,
    liveVallum: null,
    confirmIps: false,
    shown: false
  };
  c.root = c;
  c.controller = {
    show: function() { c.shown = true; },
    hide: function() { c.shown = false; }
  };
  syncIndex(c);
  vm.createContext(c);
  vm.runInContext(
    [method("visibleAppIds"), method("moveSelection"), method("acceptSearch"),
     method("cancelIps"), method("open")].join("\n"),
    c
  );
  return c;
}

function syncIndex(c) {
  c.selectedIndex = -1;
  for (let i = 0; i < c.apps.length; i++) {
    if (c.apps[i] && c.apps[i].id === c.selectedAppId) {
      c.selectedIndex = i;
      break;
    }
  }
}

function feedArrive(c, apps) {
  c.apps = apps.slice();
  syncIndex(c);
  c.selectedAppId = H.retainSelectedId(c.selectedAppId, c.visibleAppIds());
  syncIndex(c);
}

{
  const c = panelAt(
    [{ id: "fixture-0" }, { id: "fixture-1" }, { id: "fixture-3" }],
    "fixture-1"
  );
  c.acceptSearch();
  assert.strictEqual(c.selectedAppId, "fixture-1");
}

{
  const c = panelAt([{ id: "fixture-0" }], "fixture-2");
  c.acceptSearch();
  assert.strictEqual(c.selectedAppId, "fixture-0");
}

{
  const c = panelAt([], "fixture-2");
  c.acceptSearch();
  assert.strictEqual(c.selectedAppId, "fixture-2");
  feedArrive(c, [{ id: "fixture-4" }]);
  assert.strictEqual(c.selectedAppId, "fixture-2");
  assert.strictEqual(H.blockShortcutAllowed("apps", c.selectedAppId, c.visibleAppIds(), []), false);
}

for (const dy of [1, -1]) {
  const c = panelAt([], "departed-app");
  c.moveSelection(dy);
  assert.strictEqual(c.selectedAppId, "departed-app");
  c.acceptSearch();
  assert.strictEqual(c.selectedAppId, "departed-app");
  feedArrive(c, [{ id: "new-app" }]);
  assert.strictEqual(c.selectedAppId, "departed-app");
  assert.strictEqual(H.blockShortcutAllowed("apps", c.selectedAppId, ["new-app"], []), false);
}

{
  const c = panelAt([{ id: "fixture-0" }], "fixture-0");
  feedArrive(c, [{ id: "fixture-1" }]);
  assert.strictEqual(c.selectedAppId, "fixture-0");
  assert.strictEqual(H.blockShortcutAllowed("apps", c.selectedAppId, c.visibleAppIds(), []), false);
}

{
  const c = panelAt([{ id: "fixture-0" }, { id: "fixture-1" }], "fixture-1");
  c.acceptSearch();
  assert.strictEqual(c.selectedAppId, "fixture-1");
  feedArrive(c, [{ id: "fixture-1" }, { id: "fixture-0" }]);
  assert.strictEqual(c.selectedAppId, "fixture-1");
  c.acceptSearch();
  assert.strictEqual(c.selectedAppId, "fixture-1");
}

{
  const c = panelAt([{ id: "a" }, { id: "b" }, { id: "c" }], "a");
  syncIndex(c);
  c.moveSelection(1);
  syncIndex(c);
  assert.strictEqual(c.selectedAppId, "b");
  c.acceptSearch();
  assert.strictEqual(c.selectedAppId, "b");
}

{
  const c = panelAt([{ id: "fixture-0" }], "");
  c.searchQuery = "Firefox";
  c.searchOpen = true;
  c.open("{}");
  assert.strictEqual(c.selectedAppId, "fixture-0");
  assert.strictEqual(c.searchOpen, false);
  assert.strictEqual(c.searchQuery, "");
}

{
  const all = vm.createContext({
    Health: H, apps: [], selectedAppId: "departed-app", selectedIndex: -1, appList: null
  });
  vm.runInContext(panelFns.map((m) => m[0]).join("\n"), all);
  all.moveSelection(1);
  all.moveSelection(-1);
  assert.strictEqual(all.selectedAppId, "departed-app");
  const afterArrival = H.retainSelectedId(all.selectedAppId, ["new-app"]);
  assert.strictEqual(afterArrival, "departed-app");
  assert.strictEqual(H.blockShortcutAllowed("apps", afterArrival, ["new-app"], []), false);
}

console.log("test_search_selection.js ok");
