// Local activity timeline helpers. Newest-first in memory; nothing is sent off-box.

var INGEST_CAP = 1000

var KIND_GROUPS = {
    all: null,
    apps: ["app_first_seen"],
    networks: ["new_network"],
    blocks: ["block", "unblock", "block_failed", "exec_gate_deny"],
    unknown: ["unknown_owner"],
    intel: ["watch_hit", "indicator"],
    kub0: ["kub0_connected", "kub0_disconnected", "heartbeat_ok", "heartbeat_failed"],
    system: ["daemon_start", "source_changed"]
}

var KIND_LABELS = {
    daemon_start: "start",
    source_changed: "source",
    app_first_seen: "app",
    new_network: "network",
    unknown_owner: "unknown",
    block: "block",
    unblock: "unblock",
    block_failed: "block failed",
    kub0_connected: "kub0",
    kub0_disconnected: "kub0",
    heartbeat_ok: "heartbeat",
    heartbeat_failed: "heartbeat",
    watch_hit: "watch",
    indicator: "indicator",
    exec_gate_deny: "exec gate"
}

// One desktop notification per sha256 per this long.
var EXEC_GATE_NOTIFY_WINDOW_MS = 10 * 60 * 1000

function execDecisionText(decision) {
    if (decision === "blocked") return "blocked"
    if (decision === "allowed_local_trust") return "allowed (trusted on this machine)"
    if (decision === "allowed_once") return "allowed once"
    if (decision === "allowed_failopen") return "not blocked (fail-open)"
    return String(decision || "")
}

// "2026-10-20" from an RFC 3339 created_at, or "" when it does not parse.
function dayOf(iso) {
    if (typeof iso !== "string" || !iso)
        return ""
    var t = Date.parse(iso)
    if (!isFinite(t))
        return ""
    return new Date(t).toISOString().substring(0, 10)
}

function pad2(n) {
    return (n < 10 ? "0" : "") + n
}

function isArray(v) {
    return Object.prototype.toString.call(v) === "[object Array]"
}

function isPlainObject(v) {
    return v !== null && typeof v === "object" && !isArray(v)
}

function entryId(e) {
    if (!e)
        return ""
    var appId = e.app && e.app.id ? String(e.app.id) : ""
    return String(e.ts) + ":" + String(e.kind || "") + ":" + appId
}

function kindLabel(kind) {
    return KIND_LABELS[kind] || String(kind || "")
}

function detailLine(e) {
    if (!e)
        return "—"
    var d = e.detail && isPlainObject(e.detail) ? e.detail : {}
    var kind = e.kind
    if (kind === "new_network") {
        var net = d.network ? String(d.network) : ""
        var country = d.country ? String(d.country) : ""
        return [net, country].filter(function (s) { return s }).join(" ") || "—"
    }
    if (kind === "unknown_owner") {
        var uid = d.uid === undefined || d.uid === null ? "" : String(d.uid)
        var reason = d.reason ? String(d.reason) : ""
        return [uid ? "uid " + uid : "", reason].filter(function (s) { return s }).join(" ") || "—"
    }
    if (kind === "block" || kind === "unblock" || kind === "block_failed") {
        var mech = d.mechanism ? String(d.mechanism) : ""
        var err = d.error ? String(d.error) : ""
        return [mech, err].filter(function (s) { return s }).join(" ") || "—"
    }
    if (kind === "watch_hit") {
        var peer = [d.hostname ? String(d.hostname) : (d.remote ? String(d.remote) : ""), d.port ? String(d.port) : ""].filter(function (s) { return s }).join(":")
        return [d.match ? String(d.match) : "", peer].filter(function (s) { return s }).join(" → ") || "—"
    }
    if (kind === "indicator") {
        var what = d.indicator ? String(d.indicator) : ""
        var where = d.hostname ? String(d.hostname) : (d.remote ? String(d.remote) : "")
        return [what, where].filter(function (s) { return s }).join(" → ") || "—"
    }
    if (kind === "exec_gate_deny") {
        var exe = d.exe ? String(d.exe) : ""
        var why = d.reason ? String(d.reason) : ""
        return [execDecisionText(d.decision), exe, why].filter(function (s) { return s }).join(" · ") || "—"
    }
    if (kind === "heartbeat_ok")
        return "ok"
    if (kind === "heartbeat_failed")
        return "failed"
    if (kind === "source_changed" && d.source)
        return String(d.source)
    return "—"
}

// What to notify for one live entry, or null. Only a watch hit or a
// warning-level indicator earns an interruption; notices and info are read
// in the panel.
function notification(e) {
    var n = normalize(e)
    if (!n)
        return null
    var d = n.detail || {}
    var who = n.app && (n.app.name || n.app.id) ? String(n.app.name || n.app.id) : "An app"
    var peer = [d.hostname ? String(d.hostname) : (d.remote ? String(d.remote) : ""), d.port ? String(d.port) : ""].filter(function (s) { return s }).join(":")
    if (n.kind === "watch_hit") {
        return {
            headline: "Watch rule matched",
            body: who + " reached " + (peer || "a destination") + (d.match ? " · " + String(d.match) : "")
        }
    }
    if (n.kind === "indicator" && d.severity === "warning") {
        return {
            headline: "kub0 warning: " + (d.indicator ? String(d.indicator) : "indicator"),
            body: who + (peer ? " → " + peer : "") + (d.basis ? "\n" + String(d.basis) : "")
        }
    }
    if (n.kind === "exec_gate_deny")
        return execGateNotification(n)
    return null
}

// The exec gate refused a file, or wanted to and could not. A trusted or
// one-shot allow is the owner's own decision and is not announced. The
// `actions` run `pkexec /usr/bin/kub0` (#61 step 1b): both lower protection,
// so the system daemon keeps them to root and polkit asks every time;
// `withArgs` is appended to every action's argv by `omarchy notification
// send --with`, which is where an untrusted word like a digest has to travel.
function execGateNotification(n) {
    var d = n.detail || {}
    var decision = d.decision ? String(d.decision) : "blocked"
    if (decision !== "blocked" && decision !== "allowed_failopen")
        return null
    var sha = typeof d.sha256 === "string" && /^[0-9a-f]{64}$/.test(d.sha256) ? d.sha256 : ""
    if (!sha)
        return null
    var comm = d.comm ? String(d.comm) : (n.app && n.app.name ? String(n.app.name) : "a file")
    var day = dayOf(d.createdAt)
    var reason = d.reason ? String(d.reason) : ""
    var matched = "this file matches a sample kub0 detonated" + (day ? " on " + day : "") + (reason ? " (" + reason + ")" : "")
    if (decision === "allowed_failopen") {
        return {
            headline: "kub0 could not block " + comm,
            body: matched + ". The deny was not delivered in time, so it ran.",
            urgency: "critical",
            sha256: sha,
            actions: [
                { label: "Trust on this machine", argv: ["/usr/bin/pkexec", "/usr/bin/kub0", "trust"] }
            ],
            withArgs: [sha]
        }
    }
    return {
        headline: "kub0 blocked " + comm,
        body: matched + ".",
        urgency: "critical",
        sha256: sha,
        actions: [
            { label: "Allow once", argv: ["/usr/bin/pkexec", "/usr/bin/kub0", "allow-once"] },
            { label: "Trust on this machine", argv: ["/usr/bin/pkexec", "/usr/bin/kub0", "trust"] }
        ],
        withArgs: [sha]
    }
}

// Rate limit: one notification per sha256 per EXEC_GATE_NOTIFY_WINDOW_MS.
// `seen` maps sha256 -> last notified ms; the returned object is the new map
// (expired entries dropped) so the caller never mutates shared state.
function execGateNotifyAllowed(seen, sha256, nowMs) {
    var now = typeof nowMs === "number" ? nowMs : Date.now()
    var next = {}
    var src = isPlainObject(seen) ? seen : {}
    for (var k in src) {
        if (typeof src[k] === "number" && now - src[k] < EXEC_GATE_NOTIFY_WINDOW_MS)
            next[k] = src[k]
    }
    var key = String(sha256 || "")
    if (!key)
        return { allowed: false, seen: next }
    if (next[key] !== undefined)
        return { allowed: false, seen: next }
    next[key] = now
    return { allowed: true, seen: next }
}

// `fmt` is the panel's ux object (js/Ux.js). Its `time` is set when the user
// chose how timestamps read; without it this prints HH:MM:SS as it always has.
function formatTime(ts, fmt, now) {
    if (fmt && fmt.time && typeof ts === "number")
        return fmt.time(ts, typeof now === "number" ? now : Date.now())
    var d = new Date(typeof ts === "number" ? ts : 0)
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes()) + ":" + pad2(d.getSeconds())
}

function ymd(d) {
    return d.getFullYear() * 10000 + (d.getMonth() + 1) * 100 + d.getDate()
}

function hourKey(d) {
    return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + "T" + pad2(d.getHours())
}

function hourLabel(d, nowMs) {
    var now = new Date(typeof nowMs === "number" ? nowMs : Date.now())
    var hh = pad2(d.getHours()) + ":00"
    if (ymd(d) === ymd(now))
        return "Today " + hh
    var yest = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1)
    if (ymd(d) === ymd(yest))
        return "Yesterday " + hh
    return pad2(d.getMonth() + 1) + "/" + pad2(d.getDate()) + " " + hh
}

function normalize(e) {
    if (!e || typeof e !== "object")
        return null
    var ts = typeof e.ts === "number" && isFinite(e.ts) ? e.ts : 0
    var kind = typeof e.kind === "string" ? e.kind : ""
    var app = null
    if (e.app && typeof e.app === "object") {
        app = {
            id: e.app.id ? String(e.app.id) : "",
            name: e.app.name ? String(e.app.name) : ""
        }
    }
    var detail = isPlainObject(e.detail) ? e.detail : {}
    return { ts: ts, kind: kind, app: app, detail: detail }
}

function ingest(store, incoming, cap) {
    cap = typeof cap === "number" && cap > 0 ? cap : INGEST_CAP
    store = store && isArray(store) ? store : []
    incoming = incoming && isArray(incoming) ? incoming : []
    var next = []
    var i
    for (i = incoming.length - 1; i >= 0; i--) {
        var e = normalize(incoming[i])
        if (e)
            next.push(e)
    }
    for (i = 0; i < store.length; i++)
        next.push(store[i])
    if (next.length > cap)
        next.length = cap
    return next
}

function groupByHour(entries, nowMs) {
    entries = entries && isArray(entries) ? entries : []
    nowMs = typeof nowMs === "number" ? nowMs : Date.now()
    var groups = []
    var last = ""
    var cur = null
    var i
    for (i = 0; i < entries.length; i++) {
        var e = entries[i]
        var d = new Date(e && typeof e.ts === "number" ? e.ts : 0)
        var key = hourKey(d)
        if (key !== last) {
            cur = { key: key, label: hourLabel(d, nowMs), entries: [] }
            groups.push(cur)
            last = key
        }
        cur.entries.push(e)
    }
    return groups
}

function flattenHourGroups(groups) {
    groups = groups && isArray(groups) ? groups : []
    var out = []
    var i, j
    for (i = 0; i < groups.length; i++) {
        var g = groups[i]
        out.push({
            rowType: "header",
            id: "h:" + g.key,
            label: g.label,
            hourKey: g.key
        })
        var list = g.entries || []
        for (j = 0; j < list.length; j++) {
            var e = list[j]
            out.push({
                rowType: "entry",
                id: entryId(e),
                ts: e.ts,
                kind: e.kind,
                kindLabel: kindLabel(e.kind),
                appName: e.app && e.app.name ? e.app.name : "—",
                appId: e.app && e.app.id ? e.app.id : "",
                detail: detailLine(e),
                time: formatTime(e.ts),
                hourKey: g.key,
                entry: e
            })
        }
    }
    return out
}

function filterEntries(entries, kindGroup, query) {
    entries = entries && isArray(entries) ? entries : []
    var kinds = KIND_GROUPS[kindGroup]
    if (kindGroup && kindGroup !== "all" && !kinds)
        kinds = []
    var q = query ? String(query).toLowerCase() : ""
    var out = []
    var i
    for (i = 0; i < entries.length; i++) {
        var e = entries[i]
        if (!e)
            continue
        if (kinds) {
            var ok = false
            var k
            for (k = 0; k < kinds.length; k++) {
                if (e.kind === kinds[k]) {
                    ok = true
                    break
                }
            }
            if (!ok)
                continue
        }
        if (q) {
            var name = e.app && e.app.name ? String(e.app.name).toLowerCase() : ""
            var id = e.app && e.app.id ? String(e.app.id).toLowerCase() : ""
            var det = ""
            try { det = JSON.stringify(e.detail || {}).toLowerCase() } catch (err) { det = "" }
            var blob = name + " " + id + " " + det + " " + String(e.kind || "").toLowerCase() + " " + detailLine(e).toLowerCase()
            if (blob.indexOf(q) < 0)
                continue
        }
        out.push(e)
    }
    return out
}

function visibleRows(entries, kindGroup, query, nowMs) {
    return flattenHourGroups(groupByHour(filterEntries(entries, kindGroup, query), nowMs))
}

function digestEntries(entries, query, cap, fmt, now) {
    cap = typeof cap === "number" && cap > 0 ? cap : 4
    var src = filterEntries(entries, "all", query)
    var out = []
    var n = Math.min(src.length, cap)
    var i
    for (i = 0; i < n; i++) {
        var e = src[i]
        if (!e)
            continue
        var line = formatTime(e.ts, fmt, now) + "  " + kindLabel(e.kind)
        var name = e.app && e.app.name ? String(e.app.name) : ""
        var d = detailLine(e)
        if (name)
            line += "  " + name
        if (d && d !== "—")
            line += "  " + d
        out.push({
            // Stable across new entries arriving, unlike a position: the
            // panel's keyboard focus names a row by this.
            id: entryId(e),
            line: line,
            appId: e.app && e.app.id ? String(e.app.id) : "",
            kind: e.kind || ""
        })
    }
    return out
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        INGEST_CAP: INGEST_CAP,
        KIND_GROUPS: KIND_GROUPS,
        ingest: ingest,
        groupByHour: groupByHour,
        flattenHourGroups: flattenHourGroups,
        filterEntries: filterEntries,
        visibleRows: visibleRows,
        digestEntries: digestEntries,
        entryId: entryId,
        kindLabel: kindLabel,
        detailLine: detailLine,
        notification: notification,
        execGateNotification: execGateNotification,
        execGateNotifyAllowed: execGateNotifyAllowed,
        EXEC_GATE_NOTIFY_WINDOW_MS: EXEC_GATE_NOTIFY_WINDOW_MS,
        execDecisionText: execDecisionText,
        formatTime: formatTime,
        hourLabel: hourLabel
    }
}
