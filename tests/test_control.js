"use strict";
// js/Control.js: where each panel change goes (#61 step 1b, the hybrid).
const assert = require("assert");
const C = require("../js/Control.js");

// Raises are control requests to the system daemon, with the fields the
// daemon's verbs read (daemon/src/main.rs helper_argv).
assert.deepStrictEqual(C.route(["block-app", "firefox", "12", 34]),
  { path: "system", cmd: "block", request: { app: "firefox", pids: ["12", "34"] } });
assert.deepStrictEqual(C.route(["block-scoped", "firefox", "203.0.113.9", "900", "12"]),
  { path: "system", cmd: "block-dest", request: { app: "firefox", ip: "203.0.113.9", seconds: 900, pids: ["12"] } });
assert.strictEqual(typeof C.route(["block-scoped", "a", "192.0.2.1", "300", "1"]).request.seconds, "number",
  "the daemon reads seconds as a number");
assert.deepStrictEqual(C.route(["resume"]), { path: "system", cmd: "resume", request: {} });
assert.deepStrictEqual(C.route(["execgate-untrust", "a".repeat(64)]),
  { path: "system", cmd: "untrust", request: { sha256: "a".repeat(64) } });

// What the system daemon keeps to root runs `pkexec kub0 --json <kub0 words>`.
assert.deepStrictEqual(C.route(["block-ips", "firefox", "192.0.2.1", "2001:db8::1"]),
  { path: "root", cmd: "block", argv: ["block", "firefox", "--ip", "192.0.2.1", "2001:db8::1"] });
assert.deepStrictEqual(C.route(["unblock-app", "firefox"]).argv, ["unblock", "firefox"]);
assert.deepStrictEqual(C.route(["unblock-ips", "firefox"]).argv, ["unblock", "firefox", "--ips"]);
assert.deepStrictEqual(C.route(["unblock-scoped", "firefox", "203.0.113.9"]).argv, ["unblock", "firefox", "--to", "203.0.113.9"]);
assert.deepStrictEqual(C.route(["pause"]).argv, ["pause"]);
assert.deepStrictEqual(C.route(["execgate-trust", "b".repeat(64)]).argv, ["trust", "b".repeat(64)]);
assert.deepStrictEqual(C.route(["execgate-allow-once", "c".repeat(64)]).argv, ["allow-once", "c".repeat(64)]);
// Policy changes go to the system daemon, the only one that enforces: a
// snooze through the root path, a resume as a request.
assert.deepStrictEqual(C.route(["policy-snooze", "r-1", "3600"]),
  { path: "root", cmd: "policy-snooze", argv: ["policy", "snooze", "r-1", "--for", "3600s"] });
assert.deepStrictEqual(C.route(["policy-snooze", "r-1", "junk"]).argv.slice(-1), ["3600s"], "a bad duration is the default hour");
assert.deepStrictEqual(C.route(["policy-resume", "r-1"]), { path: "system", cmd: "policy-resume", request: { rule: "r-1" }, argv: ["policy", "resume", "r-1"] },
  "a resume has a kub0 argv too, for a system install this session cannot reach");
assert.ok(C.isPolicyChange(["policy-snooze", "r"]) && C.isPolicyChange(["policy-resume", "r"]));
// Destination sharing (#61): on needs root, off is a request; neither is the helper's.
assert.deepStrictEqual(C.route(["share-on"]), { path: "root", cmd: "share-on", argv: ["share", "on"] });
assert.deepStrictEqual(C.route(["share-off"]), { path: "system", cmd: "share-off", request: {}, argv: ["share", "off"] });
assert.ok(C.isSharingChange(["share-on"]) && C.isSharingChange(["share-off"]));
assert.ok(!C.isSharingChange(["policy-snooze", "r"]) && !C.isSharingChange(null));
assert.ok(!C.isPolicyChange(["block-app", "a"]) && !C.isPolicyChange(null));
for (const verb of Object.keys(C.ROUTES))
  assert.strictEqual(C.route([verb, "x", "y", "300"]).path, C.ROUTES[verb].path, verb);
assert.strictEqual(C.route(["teardown"]), null, "nothing the panel does not send");
assert.strictEqual(C.route([]), null);
assert.strictEqual(C.route(null), null);
assert.strictEqual(C.route(["toString"]), null, "no prototype keys");

assert.deepStrictEqual(C.kub0Command("/usr/bin/pkexec", "/usr/bin/kub0", ["unblock", "firefox"]),
  ["/usr/bin/pkexec", "/usr/bin/kub0", "--json", "unblock", "firefox"]);
assert.strictEqual(C.KUB0, "/usr/bin/kub0", "the path polkit's ai.kub0.agent.kub0 action names");

// A request line carries the daemon's fields plus req and cmd, which win.
assert.deepStrictEqual(JSON.parse(C.requestLine("panel-1", "block", { app: "a", pids: ["1"], cmd: "x", req: "y" })),
  { app: "a", pids: ["1"], req: "panel-1", cmd: "block" });

// The request connection reads hello and replies, and skips everything else
// unparsed.
assert.deepStrictEqual(C.systemFrame('{"type":"hello","version":"0.4.4","mode":"system","requests":true}'),
  { type: "hello", requests: true, mode: "system" });
assert.strictEqual(C.systemFrame('{"type":"reply","req":"panel-1","ok":true}').req, "panel-1");
assert.strictEqual(C.systemFrame('{"type": "reply", "req": "panel-2", "ok": false}').req, "panel-2", "whitespace is not a different frame");
assert.strictEqual(C.systemFrame('{"type":"snapshot","connections":[{"hostname":"reply"}]}'), null);
assert.strictEqual(C.systemFrame('{"type":"snapshot","connections":[]}'), null);
assert.strictEqual(C.systemFrame('{"type":"reply"'), null, "a torn line");
assert.strictEqual(C.systemFrame('{"type":"reply","ok":true}'), null, "a reply without req");
assert.strictEqual(C.systemFrame(""), null);
{
  // The system daemon broadcasts every user's rows; the request connection
  // parses none of them.
  const parse = JSON.parse;
  let parsed = 0;
  JSON.parse = (t) => { parsed += 1; return parse(t); };
  try {
    for (let i = 0; i < 200; i++)
      C.systemFrame(JSON.stringify({ type: "connect", ts: i, id: "row-" + i, app: { id: "reply" } }));
    assert.strictEqual(parsed, 0, "a broadcast row was parsed");
    C.systemFrame('{"type":"reply","req":"panel-9","ok":true}');
    assert.strictEqual(parsed, 1);
  } finally {
    JSON.parse = parse;
  }
}
assert.ok(C.helloUsable({ requests: true, mode: "system" }));
assert.ok(!C.helloUsable({ requests: false, mode: "system" }), "an older daemon");
assert.ok(!C.helloUsable({ requests: true, mode: "user" }), "a user daemon behind the path");

// A reply as the helper's own JSON.
assert.deepStrictEqual(C.replyEvent({ ok: true, result: { ok: true, verified: true, mechanism: "cgroup" } }),
  { ok: true, verified: true, mechanism: "cgroup" });
assert.deepStrictEqual(C.replyEvent({ ok: true, result: null }), { ok: true });
const refused = C.replyEvent({ ok: false, error: "no live processes", result: { ok: false, code: "empty-forest", rollback: true } });
assert.deepStrictEqual(refused, { ok: false, code: "empty-forest", rollback: true, error: "no live processes" },
  "the fallback offer still sees code and rollback");
assert.deepStrictEqual(C.replyEvent({ ok: false, error: "unblock: lowers protection; needs root: sudo kub0 unblock <app>" }),
  { ok: false, error: "unblock: lowers protection; needs root: sudo kub0 unblock <app>" });
assert.strictEqual(C.replyEvent(null).ok, false);

// kub0 through pkexec.
assert.deepStrictEqual(C.kub0Event('{\n  "ok": true,\n  "mechanism": "endpoints"\n}\n', "", 0),
  { ok: true, mechanism: "endpoints" });
assert.deepStrictEqual(C.kub0Event('{"paused":true}', "", 0), { paused: true, ok: true });
assert.deepStrictEqual(C.kub0Event("", "kub0 unblock: blocking runs in the system daemon only\n", 1),
  { ok: false, error: "blocking runs in the system daemon only" });
assert.deepStrictEqual(C.kub0Event("", "", 126), { ok: false, error: "authorization was refused or cancelled" });
assert.deepStrictEqual(C.kub0Event("", "Error executing command as another user: Not authorized\n", 127),
  { ok: false, error: "Error executing command as another user: Not authorized" });
assert.deepStrictEqual(C.kub0Event("", "kub0: cannot reach kub0d at /run/kub0/kub0.sock\nno system daemon", 3),
  { ok: false, error: "no system daemon" });
assert.strictEqual(C.kub0Event("not json", "", 0).ok, false);
assert.strictEqual(C.kub0Event("", "", 0).ok, false);
assert.strictEqual(C.kub0Event("", "", 9).error, "kub0 exited 9");

console.log("test_control.js ok");
