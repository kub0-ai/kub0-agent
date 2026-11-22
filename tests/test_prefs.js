"use strict";
const assert = require("assert");
const P = require("../js/Prefs.js");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log("  ok  " + name);
}

// --------------------------------------------------------------- defaults

test("defaults are complete and self-consistent", () => {
  const d = P.defaults();
  assert.ok(P.STARTUP_VIEWS.indexOf(d.startupView) >= 0, "startupView in domain");
  assert.ok(P.SORT_KEYS.indexOf(d.sortKey) >= 0, "sortKey in domain");
  assert.ok(P.FILTER_KEYS.indexOf(d.filterKey) >= 0, "filterKey in domain");
  assert.strictEqual(typeof d.confirmBlocks, "boolean");
  assert.strictEqual(typeof d.showWorldMap, "boolean");
  assert.strictEqual(d.notifyIntel, true, "watch hits and warnings notify by default");
  assert.strictEqual(d.shareDestinations, false, "sharing destination networks with kub0 is opt-in");
  assert.strictEqual(P.sanitize({ shareDestinations: 1 }).shareDestinations, false, "1 must not read as true");
  assert.strictEqual(P.sanitize({ shareDestinations: true }).shareDestinations, true);
  assert.strictEqual(P.sanitize({ notifyIntel: "no" }).notifyIntel, true, "a non-boolean falls back");
  assert.strictEqual(P.sanitize({ notifyIntel: false }).notifyIntel, false);
});

test("blocking confirmation defaults ON", () => {
  // Blocking is privileged and kernel-enforced, dispatched from one click on a
  // row. If this ever flips to false by default it should be a deliberate
  // product call, not a drive-by edit.
  assert.strictEqual(P.defaults().confirmBlocks, true);
});

// ------------------------------------------------------------------ parse

test("an absent file is a first run, not an error", () => {
  const r = P.parse("");
  assert.strictEqual(r.error, false);
  assert.strictEqual(r.firstRun, true);
  assert.deepStrictEqual(r.prefs, P.defaults());
});

test("null and undefined parse like an absent file", () => {
  for (const raw of [null, undefined, "   \n  "]) {
    const r = P.parse(raw);
    assert.strictEqual(r.error, false, "raw=" + String(raw));
    assert.deepStrictEqual(r.prefs, P.defaults());
  }
});

test("a truncated file degrades to defaults and reports the error", () => {
  const r = P.parse('{"sortKey": "activi');
  assert.strictEqual(r.error, true);
  assert.ok(r.errorMessage.length > 0, "carries a reason");
  assert.deepStrictEqual(r.prefs, P.defaults(), "still usable");
});

test("a JSON array root is rejected, not spread over the defaults", () => {
  const r = P.parse('["sortKey","activity"]');
  assert.strictEqual(r.error, true);
  assert.deepStrictEqual(r.prefs, P.defaults());
});

test("valid values round-trip", () => {
  const raw = P.serialize({
    startupView: "apps",
    lastView: "apps",
    sortKey: "connections",
    filterKey: "blocked",
    confirmBlocks: false,
    showWorldMap: false
  });
  const r = P.parse(raw);
  assert.strictEqual(r.error, false);
  assert.strictEqual(r.prefs.startupView, "apps");
  assert.strictEqual(r.prefs.lastView, "apps");
  assert.strictEqual(r.prefs.sortKey, "connections");
  assert.strictEqual(r.prefs.filterKey, "blocked");
  assert.strictEqual(r.prefs.confirmBlocks, false);
  assert.strictEqual(r.prefs.showWorldMap, false);
});

test("retired views alias onto Overview/Apps", () => {
  const r = P.parse('{"startupView":"protection","lastView":"activity"}');
  assert.strictEqual(r.prefs.startupView, "apps");
  assert.strictEqual(r.prefs.lastView, "overview");
  assert.strictEqual(P.aliasView("activity"), "overview");
  assert.strictEqual(P.aliasView("protection"), "apps");
});

// --------------------------------------------------------------- clamping
//
// The settings file is hand-editable and survives upgrades. These are the
// cases where a bad value must NOT reach a control.

test("an out-of-domain value falls back instead of sticking", () => {
  const r = P.parse('{"sortKey":"cpu","filterKey":"haunted","startupView":"nowhere"}');
  assert.strictEqual(r.prefs.sortKey, "name");
  assert.strictEqual(r.prefs.filterKey, "all");
  assert.strictEqual(r.prefs.startupView, "overview");
});

test("a non-boolean toggle falls back rather than becoming truthy", () => {
  // "false" the STRING is truthy in JS. Accepting it would silently disable
  // the block confirmation for anyone who hand-edited the file with quotes.
  const r = P.parse('{"confirmBlocks":"false","showWorldMap":0}');
  assert.strictEqual(r.prefs.confirmBlocks, true, "string 'false' must not disable it");
  assert.strictEqual(r.prefs.showWorldMap, true, "0 must not read as false");
});

test("unknown keys are dropped, not carried forward", () => {
  const r = P.parse('{"sortKey":"activity","evilKey":"payload","__proto__":"x"}');
  assert.strictEqual(r.prefs.sortKey, "activity");
  assert.ok(!r.prefs.hasOwnProperty("evilKey"), "unknown key dropped");
  assert.deepStrictEqual(
    Object.keys(r.prefs).sort(),
    Object.keys(P.defaults()).sort(),
    "shape matches defaults exactly"
  );
});

test("sanitize always returns a complete object from any garbage", () => {
  for (const junk of [null, undefined, 42, "string", [], { }]) {
    const p = P.sanitize(junk);
    assert.deepStrictEqual(
      Object.keys(p).sort(),
      Object.keys(P.defaults()).sort(),
      "junk=" + JSON.stringify(junk)
    );
  }
});

// ----------------------------------------------------------- openingView

test("startupView drives the opening view", () => {
  assert.strictEqual(P.openingView({ startupView: "apps" }), "apps");
  assert.strictEqual(P.openingView({ startupView: "protection" }), "apps");
});

test("'last' resolves through lastView", () => {
  assert.strictEqual(
    P.openingView({ startupView: "last", lastView: "activity" }),
    "overview"
  );
});

test("'last' with a corrupt lastView still opens somewhere real", () => {
  const v = P.openingView({ startupView: "last", lastView: "atlantis" });
  assert.ok(P.VIEWS.indexOf(v) >= 0, "opened on a real view, got " + v);
});

test("openingView never returns 'last'", () => {
  // 'last' is an indirection, not a view. Returning it would leave the panel
  // rendering no section at all.
  for (const sv of P.STARTUP_VIEWS) {
    const v = P.openingView({ startupView: sv, lastView: "apps" });
    assert.notStrictEqual(v, "last", "startupView=" + sv);
    assert.ok(P.VIEWS.indexOf(v) >= 0, "startupView=" + sv + " gave " + v);
  }
});

// ------------------------------------------------------------- withValue

test("withValue returns a NEW object, never the same reference", () => {
  // Panel bindings read prefs.*; mutating in place fires no change signal.
  // This is the same defect class as the row model's same-reference
  // setProperty (see test_row_sync.qml) — it is cheap to prevent and
  // invisible once it happens.
  const before = P.defaults();
  const after = P.withValue(before, "sortKey", "activity");
  assert.notStrictEqual(after, before, "new object");
  assert.strictEqual(before.sortKey, "name", "original untouched");
  assert.strictEqual(after.sortKey, "activity");
});

test("withValue refuses an unknown key", () => {
  const after = P.withValue(P.defaults(), "evilKey", "payload");
  assert.ok(!after.hasOwnProperty("evilKey"));
});

test("withValue clamps the value it is handed", () => {
  const after = P.withValue(P.defaults(), "sortKey", "cpu");
  assert.strictEqual(after.sortKey, "name", "invalid write rejected");
});

test("changed detects a real edit and ignores a no-op", () => {
  const a = P.defaults();
  assert.strictEqual(P.changed(a, a), false);
  assert.strictEqual(P.changed(a, P.withValue(a, "filterKey", "live")), true);
  assert.strictEqual(P.changed(a, P.withValue(a, "sortKey", "name")), false);
});

// ------------------------------------------------------------- serialize

test("serialize emits a version and a trailing newline", () => {
  const out = P.serialize(P.defaults());
  assert.ok(out.endsWith("\n"), "trailing newline");
  assert.strictEqual(JSON.parse(out).version, P.SCHEMA_VERSION);
});

test("serialize sanitizes before writing", () => {
  // A bad value must never be persisted, or it outlives the session that
  // produced it and comes back every restart.
  const out = P.serialize({ sortKey: "cpu", confirmBlocks: "false" });
  const back = JSON.parse(out);
  assert.strictEqual(back.sortKey, "name");
  assert.strictEqual(back.confirmBlocks, true);
});

test("Endpoints survives remembering and choosing a startup view", () => {
  const remembered = P.withValue(P.withValue(P.defaults(), "startupView", "last"), "lastView", "endpoints");
  assert.strictEqual(P.openingView(remembered), "endpoints");
  assert.strictEqual(P.openingView(P.parse(P.serialize(remembered)).prefs), "endpoints");
  assert.strictEqual(P.openingView(P.withValue(P.defaults(), "startupView", "endpoints")), "endpoints");
});

// ------------------------------------------- the move out of ~/.config/vallum

test("settings from the old folder are used once, when the new one has none", () => {
  const old = P.serialize(P.withValue(P.defaults(), "textSize", "large"));
  const carried = P.startupSource(null, old);
  assert.deepStrictEqual(carried, { raw: old, carried: true });
  assert.strictEqual(P.parse(carried.raw).prefs.textSize, "large", "nothing is lost on the way");
});

test("a file in the new folder always wins, even an empty or broken one", () => {
  const old = P.serialize(P.withValue(P.defaults(), "textSize", "large"));
  const now = P.serialize(P.withValue(P.defaults(), "textSize", "small"));
  assert.deepStrictEqual(P.startupSource(now, old), { raw: now, carried: false });
  assert.deepStrictEqual(P.startupSource("", old), { raw: "", carried: false }, "empty is still the file that is there");
  assert.deepStrictEqual(P.startupSource("{not json", old), { raw: "{not json", carried: false });
});

test("a first run, or an empty old file, starts from the defaults and carries nothing", () => {
  assert.deepStrictEqual(P.startupSource(null, null), { raw: "", carried: false });
  assert.deepStrictEqual(P.startupSource(null, undefined), { raw: "", carried: false });
  assert.deepStrictEqual(P.startupSource(null, "  \n"), { raw: "", carried: false });
  assert.strictEqual(P.parse(P.startupSource(null, null).raw).error, false, "no file is not an error");
});

test("the panel reads the new folder and the old one, and writes only the new", () => {
  const fs = require("fs");
  const path = require("path");
  const root = path.join(__dirname, "..");
  const adapter = fs.readFileSync(path.join(root, "Kub0Adapter.qml"), "utf8");
  assert.ok(/function configDir\(\) \{\s+return configDirNamed\("kub0"\)/.test(adapter), "configDir is ~/.config/kub0");
  assert.ok(/function legacyConfigDir\(\) \{\s+return configDirNamed\("vallum"\)/.test(adapter), "the old folder is still found");
  const service = fs.readFileSync(path.join(root, "Service.qml"), "utf8");
  assert.ok(service.includes('readonly property string prefsPath: adapter.configDir() + "/ui.json"'));
  assert.ok(service.includes('onLoadFailed: root.legacyPrefsPath = adapter.legacyConfigDir() + "/ui.json"'),
    "a missing file sends the panel to the old folder");
  // Both outcomes of that look must end in loadPrefs, or the settings never
  // load and never save (the runtime check catches the real thing).
  assert.ok(service.includes('onLoaded: if (root.legacyPrefsPath !== "") root.loadPrefs(null, text())'));
  assert.ok(service.includes('onLoadFailed: if (root.legacyPrefsPath !== "") root.loadPrefs(null, null)'));
  assert.ok(!/preload: false/.test(service), "a FileView that does not preload reports nothing on reload()");
  assert.ok(service.includes("if (r.error || source.carried)\n      prefsSaveTimer.restart()"), "carried settings are written at once");
  // The only writer is prefsFile, and that is the new path.
  const writes = service.split("\n").filter((l) => /\.setText\(/.test(l));
  assert.deepStrictEqual(writes.map((l) => l.trim()), ["onTriggered: prefsFile.setText(Prefs.serialize(root.prefs))"]);
  assert.ok(!/legacyPrefsFile\.setText/.test(service), "the old file is never written");
});

console.log("prefs: " + passed + " tests passed");
