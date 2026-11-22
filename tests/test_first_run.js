"use strict";
// The panel's first run and the version notice, on the actual Service.qml
// and Panel.qml functions. `omarchy plugin add` installs a panel and no
// daemon; these are the pieces that get a new user from there to rows.
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const os = require("os");
const vm = require("vm");
const { spawnSync } = require("child_process");
const H = require("../js/Health.js");
const CM = require("../ConnectionModel.js");
const K = require("../js/Kub0.js");
const S = require("../js/Setup.js");

const service = fs.readFileSync(path.join(__dirname, "../Service.qml"), "utf8");
const panel = fs.readFileSync(path.join(__dirname, "../Panel.qml"), "utf8");
const functions = Array.from(service.matchAll(/^  function (\w+)\([^\n]*\) \{[\s\S]*?^  \}/gm));
const load = (c, names) => {
  for (const name of names) {
    const found = functions.find((x) => x[1] === name);
    assert.ok(found, "Missing actual QML function " + name);
    vm.runInContext(found[0], c);
  }
};

// The daemon's version comes from its greeting and goes with its connection.
{
  const c = {
    Kub0: K, Health: H, ConnectionModel: CM, health: H.emptyHealth(), model: CM.emptyState(),
    kub0: K.emptyKub0(), userKub0: K.emptyKub0(), systemView: null, kub0Account: {}, kub0Revision: 0, policyDaemonMode: "unknown",
    eventSource: "system", daemonVersion: "", usingFallback: false,
    captureStatus: {}, historyEntries: [], historyBusy: false, activityEntries: [], activitySinceStart: 0,
    historyRequest: "", blockingReady: true, syncFromModel() {}, Qt: { callLater() {} },
    listeners: [], listenersRevision: 0, watchRules: [], watchError: "", watchRevision: 0,
    investigateRequest: "", investigateBusy: false, investigateError: "", investigateResult: null, investigateTimeout: { stop() {} },
    timelineRequest: "", timelineBusy: false, timelineError: "", timelineResult: null, timelineTimeout: { stop() {} }
  };
  c.root = c;
  vm.createContext(c);
  load(c, ["retirePolicyEvidence", "publishKub0", "applyDeferred", "ingest"]);
  c.ingest(JSON.stringify({ type: "hello", version: "0.5.0", pid: 7, coverage: "tcp", rdns: false, mode: "system" }));
  assert.strictEqual(c.daemonVersion, "0.5.0", "the greeting's version is kept");
  assert.deepStrictEqual(Object.assign({}, S.skew("0.5.1", c.daemonVersion, c.eventSource)),
    { panel: "0.5.1", daemon: "0.5.0", behind: "daemon", summary: "The panel is 0.5.1 and the daemon is 0.5.0.",
      fix: "Update the daemon: ./scripts/install-release.sh in the plugin folder" });
  // The connection ends (a restart, an upgrade, a change of source): what
  // it said about its version is not true of the next one.
  c.retirePolicyEvidence();
  assert.strictEqual(c.daemonVersion, "", "a retired connection's version is forgotten");
  assert.strictEqual(S.skew("0.5.1", c.daemonVersion, c.eventSource), null, "and nothing is said until the next greeting");
  c.ingest(JSON.stringify({ type: "hello", version: "0.5.1", pid: 8, coverage: "tcp", rdns: false, mode: "system" }));
  assert.strictEqual(c.daemonVersion, "0.5.1", "the upgraded daemon's greeting replaces it");
  // A greeting with no version (nothing sends one, but nothing here should
  // keep the last daemon's either).
  c.ingest(JSON.stringify({ type: "hello", mode: "system" }));
  assert.strictEqual(c.daemonVersion, "");
  c.ingest(JSON.stringify({ type: "hello", version: 5, mode: "system" }));
  assert.strictEqual(c.daemonVersion, "", "a version that is not a string is not one");

  // The demo replays a recorded greeting (data/replay.ndjson says 1.0.0).
  // That is not a daemon on this machine: it used to put "the daemon is
  // 1.0.0, update the panel" over the demo.
  const replayHello = fs.readFileSync(path.join(__dirname, "../data/replay.ndjson"), "utf8").split("\n")[0];
  assert.strictEqual(JSON.parse(replayHello).type, "hello", "the replay opens with a greeting");
  assert.ok(S.skew("0.5.0", JSON.parse(replayHello).version, "user"), "and its version is one the notice would speak about");
  c.usingFallback = true;
  c.ingest(replayHello);
  assert.strictEqual(c.daemonVersion, "", "a replayed greeting is not a daemon's version");
  c.usingFallback = false;
  c.ingest(replayHello);
  assert.notStrictEqual(c.daemonVersion, "", "the same line from a daemon is");
}

// `status` is what scripts and bug reports read. statusPayload builds its
// answer from a fixed list of keys, so a field handed to it and not listed
// there was dropped without a word: the three below were.
{
  const c = {
    Health: H, health: H.emptyHealth(), activeCount: 0, model: null, daemonStatus: "missing", blockingReady: false,
    coverage: "", usingFallback: false, helperInstalled: false, polkitAgentPresent: true, needsHelperInstall: false,
    panelVersion: "0.5.1", daemonVersion: "0.5.0", setupStage: "install", offerBinds: false, offerNote: "", anyBlocked: false
  };
  c.root = c;
  vm.createContext(c);
  load(c, ["statusPayload"]);
  const out = c.statusPayload();
  assert.strictEqual(out.panelVersion, "0.5.1");
  assert.strictEqual(out.daemonVersion, "0.5.0");
  assert.strictEqual(out.setup, "install");
  c.daemonVersion = "";
  c.setupStage = "";
  assert.strictEqual(c.statusPayload().daemonVersion, "", "no daemon, no version");
  assert.strictEqual(c.statusPayload().setup, "", "nothing to set up");
  const bare = H.statusPayload(null, {});
  for (const k of ["panelVersion", "daemonVersion", "setup"])
    assert.strictEqual(bare[k], "", k + " is always there, empty when unknown");
}

// The Install button: one terminal, one script, in the plugin's folder.
{
  const launched = [];
  const watched = [];
  const c = {
    helperInstallPending: false, pluginDir: "/home/a user/.config/omarchy/plugins/ai.kub0.agent",
    launchSetupTerminal(inner) { launched.push(inner); return c.terminalOpens; },
    watchHelperInstall(kind) { watched.push(kind); },
    terminalOpens: true
  };
  c.root = c;
  vm.createContext(c);
  load(c, ["shellQuote", "installRelease"]);
  c.installRelease();
  assert.deepStrictEqual(launched, ["cd '/home/a user/.config/omarchy/plugins/ai.kub0.agent' && ./scripts/install-release.sh"]);
  assert.deepStrictEqual(watched, ["helper"], "done when the helper is where kub0 install puts it");
  assert.ok(fs.existsSync(path.join(__dirname, "../scripts/install-release.sh")), "the script it runs ships with the panel");
  assert.ok(fs.statSync(path.join(__dirname, "../scripts/install-release.sh")).mode & 0o111, "and is executable");
  // In the repository too: `omarchy plugin add` is a clone, and a clone gets
  // the mode git recorded, not this checkout's.
  const tracked = spawnSync("git", ["ls-files", "-s", "scripts/install-release.sh"], { cwd: path.join(__dirname, ".."), encoding: "utf8" });
  if (tracked.status === 0 && tracked.stdout.trim())
    assert.ok(tracked.stdout.startsWith("100755 "), "git records it as executable: " + tracked.stdout);

  // One at a time.
  c.helperInstallPending = true;
  c.installRelease();
  assert.strictEqual(launched.length, 1, "a second click while one runs opens nothing");
  c.helperInstallPending = false;
  // No plugin directory, no command.
  c.pluginDir = "";
  c.installRelease();
  assert.strictEqual(launched.length, 1);
  // A terminal that did not open is not an install in progress.
  c.pluginDir = "/p";
  c.terminalOpens = false;
  c.installRelease();
  assert.strictEqual(launched.length, 2);
  assert.strictEqual(watched.length, 1, "nothing to wait for");
}

// A setup terminal is detached: the panel cannot see it exit. Each one
// leaves a file when its command ends, and the watch unlocks the buttons
// then. Before, a failed install (no release yet, a cancelled sudo) kept
// Install and Build from source disabled for ten minutes.
{
  const runs = [];
  let refreshed = 0;
  const c = {
    Setup: S, Date: { now: () => 1700000000000 }, runtime: "/run/user/1000",
    Quickshell: { env(k) { return k === "XDG_RUNTIME_DIR" ? c.runtime : ""; }, execDetached(argv) { if (c.noTerminal) throw new Error("no terminal"); runs.push(argv); } },
    setupDoneFile: "", lastBlockError: "", helperInstallPending: false, helperWatchTicks: 0, setupWatchFor: "",
    helperWatch: { restart() {} }, refreshInstallState() { refreshed += 1; }, noTerminal: false
  };
  c.root = c;
  vm.createContext(c);
  load(c, ["shellQuote", "launchSetupTerminal", "watchHelperInstall", "setupTerminalEnded"]);

  assert.strictEqual(c.launchSetupTerminal("cd /p && ./scripts/install-release.sh"), true);
  assert.strictEqual(c.setupDoneFile, "/run/user/1000/kub0-setup-1700000000000.done", "one file per terminal, in the session's private runtime dir");
  // (Array.from: the argv was built in the vm's realm.)
  assert.deepStrictEqual(Array.from(runs[0]), ["omarchy-launch-floating-terminal-with-presentation",
    "( cd /p && ./scripts/install-release.sh ); kub0_rc=$?; : > '/run/user/1000/kub0-setup-1700000000000.done'; ( exit $kub0_rc )"]);
  c.watchHelperInstall("helper");
  assert.strictEqual(c.helperInstallPending, true);

  // The file appeared: the command ended. Unlock now, keep looking briefly.
  c.setupTerminalEnded();
  assert.strictEqual(c.helperInstallPending, false, "the buttons work again as soon as the command ends");
  assert.strictEqual(c.setupDoneFile, "", "and that terminal is not asked about again");
  assert.strictEqual(refreshed, 1, "what it changed is read at once");
  assert.ok(c.helperWatchTicks >= 295 && c.helperWatchTicks <= 300, "a few more looks, not ten more minutes: " + c.helperWatchTicks);
  // Late, or twice: nothing to unlock.
  c.setupTerminalEnded();
  assert.strictEqual(refreshed, 1);

  // No runtime directory: the command as it always was, and the old timeout.
  c.runtime = "";
  assert.strictEqual(c.launchSetupTerminal("omarchy pkg add nftables"), true);
  assert.deepStrictEqual(Array.from(runs[1]), ["omarchy-launch-floating-terminal-with-presentation", "omarchy pkg add nftables"]);
  assert.strictEqual(c.setupDoneFile, "");
  // A terminal that did not open leaves nothing to wait for.
  c.runtime = "/run/user/1000";
  c.noTerminal = true;
  c.setupDoneFile = "";
  assert.strictEqual(c.launchSetupTerminal("true"), false);
  assert.strictEqual(c.setupDoneFile, "");
  assert.strictEqual(c.launchSetupTerminal(""), false);

  // The check the watch runs, for real: it answers once per file.
  const m = /id: setupDoneCheck\s+command: \["sh", "-c", "((?:[^"\\]|\\.)*)", "sh", root\.setupDoneFile\]/.exec(service);
  assert.ok(m, "the setupDoneCheck command");
  const sh = JSON.parse('"' + m[1] + '"');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kub0-done-"));
  try {
    const f = path.join(dir, "kub0-setup-1.done");
    assert.strictEqual(spawnSync("sh", ["-c", sh, "sh", f]).status, 1, "no file: still running");
    fs.writeFileSync(f, "");
    assert.strictEqual(spawnSync("sh", ["-c", sh, "sh", f]).status, 0, "the file: ended");
    assert.ok(!fs.existsSync(f), "and it is taken away");
    assert.strictEqual(spawnSync("sh", ["-c", sh, "sh", f]).status, 1, "so it is reported once");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
  const sv = service.replace(/\s+/g, " ");
  assert.ok(sv.includes("root.refreshInstallState() if (root.setupDoneFile) root.rerun(setupDoneCheck)"), "the watch asks on every tick while a terminal is out");
  assert.ok(sv.includes("onExited: function(code) { if (code === 0) root.setupTerminalEnded() }"));
}

// The session's group is asked whenever the install state is, once there is
// a kub0 to be in the group of. A machine with nothing installed refreshes
// every few seconds and should not start four more processes each time.
{
  const ran = [];
  const c = {
    installCheck: "installCheck", kub0Check: "kub0Check", groupCheck: "groupCheck", kub0Installed: false,
    helperInstalled: true, daemonAvailable: true, rerun(p) { ran.push(p); }, probeBinaries() {}, probeHelperStatus() {}, probeBlockingTools() {}
  };
  c.root = c;
  vm.createContext(c);
  load(c, ["refreshInstallState"]);
  c.refreshInstallState();
  assert.ok(ran.includes("kub0Check") && !ran.includes("groupCheck"), "nothing installed, nothing to be a member of: " + ran);
  ran.length = 0;
  c.kub0Installed = true;
  c.refreshInstallState();
  assert.ok(ran.includes("groupCheck"), "installed: the group is asked with the rest: " + ran);
}

// The wiring the functions above depend on, read as text: these are
// bindings and handlers, which the extraction cannot run.
{
  const flat = (s) => s.replace(/\s+/g, " ");
  const sv = flat(service);
  const pn = flat(panel);
  assert.ok(sv.includes("readonly property var versionSkew: Setup.skew(panelVersion, daemonVersion, eventSource)"));
  assert.ok(sv.includes('readonly property string panelVersion: manifest && typeof manifest.version === "string" ? manifest.version : ""'));
  assert.ok(sv.includes("readonly property string setupStage: Setup.stage({"));
  assert.ok(sv.includes('onKub0InstalledChanged: { if (kub0Installed) rerun(groupCheck) if (kub0Installed && daemonStatus === "missing") chooseSource() }'),
    "a panel that said 'not built' looks for the system daemon, and asks about the group, once kub0 is installed");
  // The check and what its answer means are in Setup.js, where
  // test_setup.js runs them for real.
  assert.ok(sv.includes('command: ["sh", "-c", Setup.GROUP_CHECK]'));
  assert.ok(sv.includes("onStreamFinished: root.sessionGroup = Setup.sessionGroup(text)"));
  // The demo's greeting is not recorded as a daemon's version (run above).
  assert.ok(sv.includes('daemonVersion = (!root.usingFallback && typeof ev.version === "string") ? ev.version : ""'));

  assert.ok(pn.includes('visible: root.setupStage !== ""'), "the first-run block shows for every stage");
  assert.ok(pn.includes('text: root.setupTitle()') && pn.includes('text: root.setupBody()'));
  assert.ok(pn.includes("return Setup.title(setupStage)") && pn.includes("return Setup.body(setupStage, panelVersion)"));
  assert.ok(pn.includes('visible: root.versionSkew !== null'), "the version notice shows only when there is one");
  // `i` and the buttons: with nothing installed the release comes first.
  const key = pn.indexOf('if (root.setupStage === "install") root.launchReleaseInstall() else if (root.needsHelperInstall)');
  assert.ok(key >= 0, "`i` installs the release when nothing is installed");
  assert.strictEqual((pn.match(/onClicked: root\.launchReleaseInstall\(\)/g) || []).length, 2, "Overview and Settings each offer it");
  assert.ok(pn.includes("function launchReleaseInstall() { if (!root.liveVallum) return root.liveVallum.installRelease() root.close() }"));
  // Text that names a command or a version is plain text, never markup:
  // the title, the sentence under it, and the version notice.
  const from = panel.indexOf("id: firstRun");
  const region = panel.slice(from, panel.indexOf("WorldMap {", from));
  assert.ok(from >= 0 && region.length > 500, "the first-run block and the notice sit above the map");
  const texts = region.split(/^\s+Text \{$/m).slice(1);
  assert.strictEqual(texts.length, 3, "title, sentence, version notice");
  for (const t of texts)
    assert.ok(/^\s+textFormat: Text\.PlainText$/m.test(t.slice(0, t.indexOf("}"))), "plain text:\n" + t.slice(0, 200));
  // The two buttons wrap instead of running off a narrow panel.
  assert.ok(/Flow \{\s+visible: root\.setupStage === "install"\s+width: parent\.width/.test(region));
}

console.log("first-run tests passed");
