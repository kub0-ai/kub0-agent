// Getting from a freshly added panel to one that shows connections, and
// keeping the two halves in step afterwards.
//
// The panel and the daemon are installed separately: the panel by
// `omarchy plugin add` or `update`, the daemon by `sudo kub0 install`. So a
// new user has a panel and no daemon, and later the two can be different
// versions, where one that is behind may not know a field or a command the
// other uses. This says which, and what to run.

// "0.5.1" or "v0.5.1" as [0, 5, 1]; anything else (a pre-release, a git
// describe, an empty string) is null, and nothing is said about it.
function parse(v) {
    var m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(v === undefined || v === null ? "" : v).trim())
    if (!m)
        return null
    return [Number(m[1]), Number(m[2]), Number(m[3])]
}

// -1, 0 or 1; null when either is not a version.
function compare(a, b) {
    var x = parse(a)
    var y = parse(b)
    if (!x || !y)
        return null
    var i
    for (i = 0; i < 3; i++) {
        if (x[i] !== y[i])
            return x[i] < y[i] ? -1 : 1
    }
    return 0
}

// What to tell the user when the panel and the daemon it reads differ, or
// null when they match or either version is unknown.
//   source: "system" (kub0d.service, installed by `kub0 install`) or "user"
//           (a kub0d the panel starts itself: the one ./build.sh puts in the
//           plugin's bin/, or one found on PATH)
function skew(panelVersion, daemonVersion, source) {
    var c = compare(panelVersion, daemonVersion)
    if (c === null || c === 0)
        return null
    var panel = String(panelVersion).trim().replace(/^v/, "")
    var daemon = String(daemonVersion).trim().replace(/^v/, "")
    var behind = c > 0 ? "daemon" : "panel"
    var fix
    if (behind === "panel")
        fix = "Update the panel: omarchy plugin update"
    else if (source === "user")
        fix = "Update the kub0d this panel starts: ./build.sh in the plugin folder rebuilds its own"
    else
        fix = "Update the daemon: ./scripts/install-release.sh in the plugin folder"
    return {
        panel: panel,
        daemon: daemon,
        behind: behind,
        summary: "The panel is " + panel + " and the daemon is " + daemon + ".",
        fix: fix
    }
}

// What stands between the panel and a daemon it can read. `omarchy plugin
// add` installs the panel and nothing else, so a new user starts at
// "install"; `kub0 install` adds the account to the kub0 group, which a
// session only joins when it starts, so the next stop is "relogin".
//   s.fallback       the panel is playing its demo
//   s.daemonStatus   "missing" when no kub0 is installed and none is built here
//   s.source         "system" when the panel reads the system daemon
//   s.installed      /usr/bin/kub0 exists
//   s.ownDaemon      the plugin has a kub0d of its own (./build.sh)
//   s.sessionGroup   "in" | "relogin" | "out" | "unknown" (see sessionGroup)
// Returns "install", "relogin", "group", "unreachable", or "" for nothing to
// do. "unreachable" is every case where kub0 is installed, this session may
// read it, and the panel still has no system daemon to read: it is stopped,
// or it answered and is too old for this panel.
function stage(s) {
    if (!s || s.fallback === true || s.shuttingDown === true)
        return ""
    if (s.daemonStatus === "missing")
        return "install"
    if (s.source === "system" || s.installed !== true || s.ownDaemon === true)
        return ""
    if (s.sessionGroup === "relogin")
        return "relogin"
    if (s.sessionGroup === "out")
        return "group"
    return s.sessionGroup === "in" ? "unreachable" : ""
}

// Whether this login session is in the kub0 group, as one word on stdout:
// "in", "relogin" (the account is a member and this session began before it
// was) or "out". `id -Gn` is this session's groups; `id -Gn <name>` is the
// account's, as the group database has them now. The name is matched whole:
// a group called kub0-admins is not kub0.
// An `id` that fails prints nothing, which is "unknown": no advice is better
// than telling a member to add themselves.
var GROUP_CHECK = "g=kub0; has() { printf '%s\\n' \"$1\" | tr ' ' '\\n' | grep -qx \"$g\"; }; "
    + "s=$(id -Gn) || exit 1; "
    + "if has \"$s\"; then echo in; exit 0; fi; "
    + "a=$(id -Gn \"$(id -un)\") || exit 1; "
    + "if has \"$a\"; then echo relogin; else echo out; fi"

// What GROUP_CHECK printed, or "unknown" for anything else (it failed, or
// has not run yet).
function sessionGroup(text) {
    var t = String(text === undefined || text === null ? "" : text).trim()
    return (t === "in" || t === "relogin" || t === "out") ? t : "unknown"
}

// `inner` for a setup terminal, followed by a file that says it has ended.
// The panel cannot see a detached terminal exit, and without this a failed
// install kept every setup button disabled until a ten-minute watch ran out.
// The subshell at the end hands inner's exit status back, so the terminal's
// Done or Failed line is still about inner. `quotedMarker` is already quoted
// for a shell; "" leaves inner as it is.
function terminalCommand(inner, quotedMarker) {
    if (!quotedMarker)
        return inner
    return "( " + inner + " ); kub0_rc=$?; : > " + quotedMarker + "; ( exit $kub0_rc )"
}

var RELEASES = "github.com/kub0-ai/kub0-agent"

function title(st) {
    if (st === "install")
        return "kub0 is not installed on this machine yet."
    if (st === "relogin")
        return "kub0 is installed. Log out and back in once."
    if (st === "group")
        return "This account is not in the kub0 group."
    if (st === "unreachable")
        return "This panel cannot read the kub0 daemon."
    return ""
}

// A session joins a group when it starts, and on a machine where the user's
// service manager outlives a logout (lingering, or a second session still
// open) logging out does not start a new one.
var REBOOT = "If the panel still cannot read the daemon after you log back in, reboot: "
    + "a user service manager that outlives the logout keeps the old groups."

// The sentence under the title. `panelVersion` is the release the Install
// button fetches: the one that matches this panel.
function body(st, panelVersion) {
    if (st === "install") {
        var v = parse(panelVersion) ? ("release " + String(panelVersion).trim().replace(/^v/, "")) : "the release that matches this panel"
        return "The panel shows connections once the kub0 daemon runs. Install kub0 opens a terminal that downloads "
            + v + " for this machine from " + RELEASES + ", checks it against the digest this panel carries and runs sudo ./kub0 install. "
            + "You read each step there, and that is where it asks for your password. "
            + "Build from source compiles it in the plugin folder instead, and installs Rust to do it."
    }
    if (st === "relogin")
        return "The install added your account to the kub0 group, and a session joins a group only when it starts. "
            + "Until then this panel cannot read the daemon. " + REBOOT
    if (st === "group")
        return "The daemon answers members of that group. Add yourself, then log out and back in: sudo gpasswd -a $USER kub0. " + REBOOT
    if (st === "unreachable")
        return "kub0 is installed and this session is in the kub0 group, so the daemon is stopped or too old for this panel. "
            + "kub0 doctor says which. Start it with sudo systemctl start kub0d, "
            + "or update it with ./scripts/install-release.sh in the plugin folder."
    return ""
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        parse: parse,
        compare: compare,
        skew: skew,
        stage: stage,
        GROUP_CHECK: GROUP_CHECK,
        sessionGroup: sessionGroup,
        terminalCommand: terminalCommand,
        title: title,
        body: body
    }
}
