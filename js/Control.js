// Where each change the panel makes goes (#61 step 1b, the hybrid).
//
// The panel reads everything from its own user daemon, and sends every change
// to the system daemon, which runs the helper as root for it:
//   - a change a member of the kub0 group may make (it raises
//     protection) is a control request on a request-only connection to the
//     system socket, answered by `req`;
//   - a change the system daemon keeps to root (it lowers protection, or it
//     is an address block, which applies to the whole host) runs
//     `pkexec /usr/bin/kub0 --json …`, so polkit asks for the password once,
//     through the kub0 action;
//   - when the system socket cannot be reached (no system daemon, or this
//     user is not in the group), the change goes through the helper with
//     pkexec, as before. That fallback stays for one release.
// Policy snoozes go to the system daemon too, since only it enforces (#61
// step 2): a snooze lowers protection (root path), a resume raises it (system
// path). Watch rules and tags are not here: they go to the daemon the panel
// reads (Service.setWatch, Service.tagNetwork), as requests to the system
// daemon or as legacy lines to the panel's own.
//
// Pure; tested under Node (tests/test_control.js), and the routes are pinned
// to the daemon's verb table by daemon/tests/parity.rs.

var KUB0 = "/usr/bin/kub0"

// Keyed by the helper verb the panel used to run, or by the daemon verb for a
// change the helper never made (the policy ones). One route per line, in
// this exact shape: the parity test reads it. `cmd` is the daemon's verb;
// `ips` marks an address block.
var ROUTES = {
    "block-app": { path: "system", cmd: "block", ips: false },
    "block-scoped": { path: "system", cmd: "block-dest", ips: false },
    "resume": { path: "system", cmd: "resume", ips: false },
    "execgate-untrust": { path: "system", cmd: "untrust", ips: false },
    "block-ips": { path: "root", cmd: "block", ips: true },
    "unblock-app": { path: "root", cmd: "unblock", ips: false },
    "unblock-ips": { path: "root", cmd: "unblock", ips: true },
    "unblock-scoped": { path: "root", cmd: "unblock-dest", ips: false },
    "pause": { path: "root", cmd: "pause", ips: false },
    "execgate-trust": { path: "root", cmd: "trust", ips: false },
    "execgate-allow-once": { path: "root", cmd: "allow-once", ips: false },
    "policy-snooze": { path: "root", cmd: "policy-snooze", ips: false },
    "policy-resume": { path: "system", cmd: "policy-resume", ips: false },
    "share-on": { path: "root", cmd: "share-on", ips: false },
    "share-off": { path: "system", cmd: "share-off", ips: false }
}

// A policy change: without a reachable system daemon it goes to the user
// daemon as a legacy line (a user-only install, where nothing enforces), not
// to the helper.
function isPolicyChange(args) {
    return isArray(args) && (String(args[0]) === "policy-snooze" || String(args[0]) === "policy-resume")
}

// Destination sharing: a setting of the system daemon and nothing the helper
// knows, so it never falls back to the helper.
function isSharingChange(args) {
    return isArray(args) && (String(args[0]) === "share-on" || String(args[0]) === "share-off")
}

function isArray(v) {
    return Object.prototype.toString.call(v) === "[object Array]"
}

function isPlainObject(v) {
    return v !== null && typeof v === "object" && !isArray(v)
}

function strings(a) {
    var out = []
    for (var i = 0; i < a.length; i++)
        out.push(String(a[i]))
    return out
}

// The route for one change, given the helper argv the panel built:
//   { path: "system", cmd, request }  a control request's fields
//   { path: "root", cmd, argv }       the `kub0` words after `--json`
// null for anything this table does not know (it then stays on the helper).
function route(args) {
    if (!isArray(args) || !args.length)
        return null
    var a = strings(args)
    var r = Object.prototype.hasOwnProperty.call(ROUTES, a[0]) ? ROUTES[a[0]] : null
    if (!r)
        return null
    switch (a[0]) {
    case "block-app":
        return { path: r.path, cmd: r.cmd, request: { app: a[1] || "", pids: a.slice(2) } }
    case "block-scoped":
        return { path: r.path, cmd: r.cmd, request: { app: a[1] || "", ip: a[2] || "", seconds: Number(a[3]), pids: a.slice(4) } }
    case "resume":
        return { path: r.path, cmd: r.cmd, request: {} }
    case "execgate-untrust":
        return { path: r.path, cmd: r.cmd, request: { sha256: a[1] || "" } }
    case "block-ips":
        return { path: r.path, cmd: r.cmd, argv: ["block", a[1] || "", "--ip"].concat(a.slice(2)) }
    case "unblock-app":
        return { path: r.path, cmd: r.cmd, argv: ["unblock", a[1] || ""] }
    case "unblock-ips":
        return { path: r.path, cmd: r.cmd, argv: ["unblock", a[1] || "", "--ips"] }
    case "unblock-scoped":
        return { path: r.path, cmd: r.cmd, argv: ["unblock", a[1] || "", "--to", a[2] || ""] }
    case "pause":
        return { path: r.path, cmd: r.cmd, argv: ["pause"] }
    case "execgate-trust":
        return { path: r.path, cmd: r.cmd, argv: ["trust", a[1] || ""] }
    case "execgate-allow-once":
        return { path: r.path, cmd: r.cmd, argv: ["allow-once", a[1] || ""] }
    case "policy-snooze":
        return { path: r.path, cmd: r.cmd, argv: ["policy", "snooze", a[1] || "", "--for", String(Number(a[2]) || 3600) + "s"] }
    case "policy-resume":
        return { path: r.path, cmd: r.cmd, request: { rule: a[1] || "" }, argv: ["policy", "resume", a[1] || ""] }
    case "share-on":
        return { path: r.path, cmd: r.cmd, argv: ["share", "on"] }
    case "share-off":
        return { path: r.path, cmd: r.cmd, request: {}, argv: ["share", "off"] }
    }
    return null
}

// The process the root path runs: absolute pkexec, the installed kub0.
function kub0Command(pkexec, kub0, argv) {
    return [String(pkexec), String(kub0 || KUB0), "--json"].concat(strings(argv || []))
}

// One control request line (without the newline).
function requestLine(req, cmd, fields) {
    var o = {}
    var f = isPlainObject(fields) ? fields : {}
    for (var k in f)
        if (Object.prototype.hasOwnProperty.call(f, k))
            o[k] = f[k]
    o.req = String(req)
    o.cmd = String(cmd)
    return JSON.stringify(o)
}

// The two frames the request connection reads; everything else the system
// daemon broadcasts (rows for every user, ticks, bandwidth) is skipped before
// it is parsed. serde writes the `type` tag first.
var FRAME_HEAD = /^\s*\{\s*"type"\s*:\s*"(reply|hello)"/

function systemFrame(line) {
    var s = String(line || "")
    if (!FRAME_HEAD.test(s))
        return null
    var v
    try { v = JSON.parse(s) } catch (e) { return null }
    if (!isPlainObject(v))
        return null
    if (v.type === "hello")
        return { type: "hello", requests: v.requests === true, mode: String(v.mode || "user") }
    if (v.type === "reply" && typeof v.req === "string")
        return v
    return null
}

// A system daemon that answers requests: anything else is not the system
// daemon this path is for (an older one, or a user daemon behind the path).
function helloUsable(hello) {
    return !!hello && hello.requests === true && hello.mode === "system"
}

// A reply frame as the helper's own JSON, which the panel already knows how
// to read: the helper's result on success; on a refusal the helper's result
// (`code`, `rollback`) when the daemon carried one, with `ok: false` and the
// daemon's error.
function replyEvent(reply) {
    var r = isPlainObject(reply) ? reply : {}
    var result = isPlainObject(r.result) ? r.result : {}
    var ev = {}
    for (var k in result)
        if (Object.prototype.hasOwnProperty.call(result, k))
            ev[k] = result[k]
    if (r.ok === true) {
        if (ev.ok === undefined)
            ev.ok = true
        return ev
    }
    ev.ok = false
    ev.error = r.error ? String(r.error) : (ev.error ? String(ev.error) : "the system daemon refused")
    return ev
}

// `kub0 --json …` run through pkexec: its stdout is the daemon's reply
// result (the helper's JSON) on success; a refusal is `kub0 <verb>: <why>`
// on stderr. pkexec itself exits 126 when the prompt is dismissed or refused
// and 127 when authentication fails, printing nothing to stdout.
function kub0Event(stdout, stderr, code) {
    var out = String(stdout || "").replace(/^\s+|\s+$/g, "")
    var err = String(stderr || "").replace(/^\s+|\s+$/g, "")
    if (Number(code) === 0) {
        var v = null
        try { v = JSON.parse(out) } catch (e) { v = null }
        if (!isPlainObject(v))
            return { ok: false, error: out ? "kub0 printed no JSON reply" : "kub0 printed nothing" }
        if (v.ok === undefined)
            v.ok = true
        return v
    }
    if (Number(code) === 126 || Number(code) === 127)
        return { ok: false, error: err || "authorization was refused or cancelled" }
    var lines = err.split("\n")
    var last = lines.length ? lines[lines.length - 1] : ""
    // "kub0 unblock: unblock: lowers protection; …" → the daemon's own words.
    var m = /^kub0 [a-z-]+: (.*)$/.exec(err.split("\n")[0] || "")
    var msg = m ? m[1] : (last || err)
    return { ok: false, error: msg || ("kub0 exited " + code) }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        KUB0: KUB0,
        ROUTES: ROUTES,
        route: route,
        isPolicyChange: isPolicyChange,
        isSharingChange: isSharingChange,
        kub0Command: kub0Command,
        requestLine: requestLine,
        systemFrame: systemFrame,
        helloUsable: helloUsable,
        replyEvent: replyEvent,
        kub0Event: kub0Event
    }
}
