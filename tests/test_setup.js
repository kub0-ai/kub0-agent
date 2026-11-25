"use strict";
// js/Setup.js: the panel and the daemon are installed separately. A new user
// has a panel and no daemon (the first-run stages), and later the two can
// differ in version (the notice names both and the one command that fixes it,
// and says nothing when it does not know).
const assert = require("assert");
const V = require("../js/Setup.js");

assert.deepStrictEqual((V.parse("0.5.1")), [0, 5, 1]);
assert.deepStrictEqual((V.parse("v0.5.1")), [0, 5, 1]);
assert.deepStrictEqual((V.parse(" 1.20.3\n")), [1, 20, 3]);
for (const bad of ["", "0.5", "0.5.1-rc1", "0.5.1+4", "main", "1.0.0.0", undefined, null, {}])
  assert.strictEqual(V.parse(bad), null, "not a release version: " + JSON.stringify(bad));

// Numbers, not strings: 0.10.0 is after 0.9.0.
assert.strictEqual(V.compare("0.10.0", "0.9.0"), 1);
assert.strictEqual(V.compare("0.5.0", "0.5.1"), -1);
assert.strictEqual(V.compare("1.0.0", "0.99.99"), 1);
assert.strictEqual(V.compare("v0.5.1", "0.5.1"), 0);
assert.strictEqual(V.compare("0.5.1", ""), null);

// The same version, or one it cannot read: nothing to say.
assert.strictEqual(V.skew("0.5.1", "0.5.1", "system"), null);
assert.strictEqual(V.skew("0.5.1", "", "system"), null, "no hello yet");
assert.strictEqual(V.skew("", "0.5.1", "system"), null, "a manifest with no version");
assert.strictEqual(V.skew("0.5.1", "1.0.0-dev", "system"), null, "a development build is not behind or ahead");

// The panel was updated and the system daemon was not: the daemon is behind,
// and the fix is one command, the script the Install button runs.
let s = V.skew("0.5.1", "0.5.0", "system");
assert.strictEqual(s.behind, "daemon");
assert.strictEqual(s.summary, "The panel is 0.5.1 and the daemon is 0.5.0.");
assert.strictEqual(s.fix, "Update the daemon: ./scripts/install-release.sh in the plugin folder");

// The daemon was upgraded and the panel was not.
s = V.skew("0.5.0", "0.5.1", "system");
assert.strictEqual(s.behind, "panel");
assert.strictEqual(s.fix, "Update the panel: omarchy plugin update");
assert.strictEqual(V.skew("0.5.0", "0.5.1", "user").fix, s.fix, "whichever daemon it reads");

// A daemon the panel starts itself: usually a stale ./build.sh, and it can
// also be a kub0d found on PATH, so the text does not say "rebuild" flatly.
s = V.skew("0.5.1", "0.5.0", "user");
assert.strictEqual(s.behind, "daemon");
assert.strictEqual(s.fix, "Update the kub0d this panel starts: ./build.sh in the plugin folder rebuilds its own");
assert.strictEqual(V.skew("0.5.1", "0.5.0", undefined).fix, V.skew("0.5.1", "0.5.0", "system").fix, "the system daemon is the default");

// ---- first run ----
const base = { fallback: false, daemonStatus: "reconnecting", source: "user", installed: true, ownDaemon: false, sessionGroup: "unknown" };
const st = (o) => V.stage(Object.assign({}, base, o));

// `omarchy plugin add` and nothing else: no kub0 on the machine, none built.
assert.strictEqual(st({ daemonStatus: "missing", installed: false }), "install");
// After `kub0 install`: the account is in the group, this session is not yet.
assert.strictEqual(st({ sessionGroup: "relogin" }), "relogin");
// Installed by someone else, for someone else.
assert.strictEqual(st({ sessionGroup: "out" }), "group");
// In the group, installed, and no system daemon to read: it is stopped, or
// it answered and is too old for this panel. Both are one stage.
assert.strictEqual(st({ sessionGroup: "in" }), "unreachable");
// Not asked yet: say nothing rather than guess.
assert.strictEqual(st({ sessionGroup: "unknown" }), "");
// Nothing to set up: reading the system daemon, on its own daemon, the demo.
assert.strictEqual(st({ source: "system", sessionGroup: "in", daemonStatus: "connected" }), "");
assert.strictEqual(st({ ownDaemon: true, sessionGroup: "relogin", daemonStatus: "connected" }), "", "its own daemon works meanwhile");
assert.strictEqual(st({ installed: false, sessionGroup: "out" }), "", "not installed is 'missing', which is asked first");
assert.strictEqual(st({ fallback: true, daemonStatus: "missing" }), "", "the demo is not a first run");
assert.strictEqual(st({ shuttingDown: true, daemonStatus: "missing" }), "");
assert.strictEqual(V.stage(null), "");

// Every stage has its own title and sentence, and each says the thing that
// stage is about: a title borrowed from another stage is a wrong instruction.
const STAGES = {
  install: [/not installed/, /Install kub0 opens a terminal/],
  relogin: [/Log out and back in/, /joins a group only when it starts/],
  group: [/not in the kub0 group/, /sudo gpasswd -a \$USER kub0/],
  unreachable: [/cannot read the kub0 daemon/, /stopped or too old/]
};
const titles = new Set();
for (const s2 of Object.keys(STAGES)) {
  assert.ok(STAGES[s2][0].test(V.title(s2)), s2 + " title: " + V.title(s2));
  assert.ok(STAGES[s2][1].test(V.body(s2, "0.5.1")), s2 + " body: " + V.body(s2, "0.5.1"));
  titles.add(V.title(s2));
}
assert.strictEqual(titles.size, 4, "no two stages share a title");
assert.strictEqual(V.title(""), "");
assert.strictEqual(V.body("", "0.5.1"), "");
assert.strictEqual(V.title("something-new"), "");
assert.strictEqual(V.title("stopped"), "", "the old name for unreachable is gone, not an alias");

// The install sentence says what the button will do before it does it:
// which release, from where, that it is checked, and that it uses sudo.
const install = V.body("install", "0.5.1");
for (const part of ["release 0.5.1", "github.com/kub0-ai/kub0-agent", "the digest this panel carries", "sudo ./kub0 install", "password", "Build from source"])
  assert.ok(install.includes(part), "the install text names " + part + ":\n" + install);
assert.ok(V.body("install", "").includes("the release that matches this panel"), "no version, no made-up number");
// Logging out does not start a new session where the user's service manager
// outlives the logout (lingering, or a second session). Both stages that end
// in "log out and back in" say what to do when that is not enough.
for (const s2 of ["relogin", "group"])
  assert.ok(/reboot: a user service manager that outlives the logout keeps the old groups/.test(V.body(s2)), s2 + ": " + V.body(s2));
assert.ok(V.body("unreachable").includes("sudo systemctl start kub0d") && V.body("unreachable").includes("kub0 doctor"));
assert.ok(V.body("unreachable").includes("./scripts/install-release.sh"), "too old has a fix as well as stopped");

// The button, the script and the sentence name the same place.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync } = require("child_process");
const script = fs.readFileSync(path.join(__dirname, "../scripts/install-release.sh"), "utf8");
assert.ok(script.includes("https://github.com/kub0-ai/kub0-agent/releases/download/v$version"), "the script fetches from the repository the text names");

// ---- the group check, run for real against an `id` that says what we tell it ----
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "kub0-setup-"));
try {
  const bin = path.join(tmp, "bin");
  fs.mkdirSync(bin);
  // `id -Gn` is the session; `id -Gn <name>` is the account; `id -un` the name.
  fs.writeFileSync(path.join(bin, "id"), [
    "#!/bin/sh",
    '[ -n "$ID_FAILS" ] && exit 1',
    'if [ "$1" = "-un" ]; then echo alice; exit 0; fi',
    'if [ "$1" = "-Gn" ] && [ -n "$2" ]; then [ "$2" = alice ] && [ -z "$ACCOUNT_FAILS" ] || exit 1; echo "$ACCOUNT_GROUPS"; exit 0; fi',
    'if [ "$1" = "-Gn" ]; then [ -z "$SESSION_FAILS" ] || exit 1; echo "$SESSION_GROUPS"; exit 0; fi',
    "exit 2", ""
  ].join("\n"), { mode: 0o755 });
  const groupCheck = (session, account, extra) => {
    const env = Object.assign({ PATH: bin + ":/usr/bin:/bin", SESSION_GROUPS: session, ACCOUNT_GROUPS: account }, extra || {});
    const r = spawnSync("sh", ["-c", V.GROUP_CHECK], { env, encoding: "utf8" });
    return V.sessionGroup(r.stdout);
  };
  assert.strictEqual(groupCheck("alice wheel kub0", "alice wheel kub0"), "in");
  assert.strictEqual(groupCheck("alice wheel", "alice wheel kub0"), "relogin", "a member whose session is older than the membership");
  assert.strictEqual(groupCheck("alice wheel", "alice wheel"), "out");
  // The name is matched whole. A group that only contains "kub0" is another group.
  assert.strictEqual(groupCheck("alice kub0-admins akub0 kub", "alice kub0-admins"), "out", "kub0-admins is not kub0");
  assert.strictEqual(groupCheck("alice wheel", "alice kub0x"), "out");
  assert.strictEqual(groupCheck("kub0", "kub0"), "in", "the only group");
  // An `id` that fails is no answer: "unknown" says nothing, where "out"
  // would tell a member to add themselves.
  assert.strictEqual(groupCheck("alice kub0", "alice kub0", { ID_FAILS: "1" }), "unknown");
  // Each half on its own: not knowing the session's groups is not "log in
  // again", and not knowing the account's is not "add yourself".
  assert.strictEqual(groupCheck("alice", "alice kub0", { SESSION_FAILS: "1" }), "unknown");
  assert.strictEqual(groupCheck("alice", "alice kub0", { ACCOUNT_FAILS: "1" }), "unknown");
  // What is not one of the three words is not an answer.
  for (const noise of ["", "in\nout", "IN", "yes", undefined, null, "relogin now"])
    assert.strictEqual(V.sessionGroup(noise), "unknown", JSON.stringify(noise));
  assert.strictEqual(V.sessionGroup(" relogin\n"), "relogin");

  // ---- the setup terminal's command, run the way Omarchy's launcher runs it ----
  // omarchy-launch-floating-terminal-with-presentation runs
  //   bash -c "omarchy-show-logo; $cmd; code=$?; ... omarchy-show-done $code"
  // so the wrapped command must leave its file, hand back the inner status,
  // and not end the shell before `code=$?`.
  const marker = path.join(tmp, "it's done");
  const quoted = "'" + marker.replace(/'/g, "'\\''") + "'";
  const present = (inner) => spawnSync("bash", ["-c", "true; " + V.terminalCommand(inner, quoted) + "; code=$?; echo code=$code"], { encoding: "utf8" });
  for (const [inner, code] of [["exit 3", 3], ["true", 0], ["cd /nonexistent-dir && ./x", 1], ["false || exit 7", 7]]) {
    if (fs.existsSync(marker)) fs.unlinkSync(marker);
    const r = present(inner);
    assert.strictEqual(r.stdout.trim(), "code=" + code, inner + ": the terminal still reports the inner status\n" + r.stdout + r.stderr);
    assert.ok(fs.existsSync(marker), inner + ": the file that says it ended is there, whatever it achieved");
  }
  assert.strictEqual(V.terminalCommand("cd /x && ./y", ""), "cd /x && ./y", "no runtime dir, no file: the command as it was");
} finally {
  fs.rmSync(tmp, { recursive: true, force: true });
}

console.log("setup tests passed");
