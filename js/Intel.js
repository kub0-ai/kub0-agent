// The Intel view's pure half: indicators, exposure, watch rules, and the
// pivot drawer, computed from what the daemon already sent. No I/O, no QML,
// so every rule here is pinned by tests/test_intel.js under Node.
//
// The daemon decides what an indicator IS (daemon/src/intel.rs); this file
// only decides how the panel orders, groups and phrases it. A severity it
// does not know sorts last and keeps its own name, so a newer daemon never
// renders as a blank.

var SEVERITY_RANK = { warning: 3, notice: 2, info: 1 }
var SEVERITY_LABEL = { warning: "Warning", notice: "Notice", info: "Info" }

var INDICATOR_LABEL = {
    "watchlist": "Watch rule",
    "exe-deleted": "Executable deleted",
    "exe-temp-dir": "Runs from temp",
    "exe-world-writable": "World-writable executable",
    "exe-hidden-home": "Hidden home directory",
    "exe-build-dir": "Go build directory",
    "exe-changed": "Executable changed",
    "exe-unpackaged": "Unpackaged executable",
    "new-asn": "New network for app",
    "new-country": "New country for app",
    "uncommon-port": "Uncommon port",
    "beacon-cadence": "Regular cadence",
    "upload-heavy": "Upload heavy",
    "fan-out": "Many destinations",
    "hosting": "Hosting provider",
    "no-ptr": "No reverse DNS"
}

function isArray(v) {
    return Object.prototype.toString.call(v) === "[object Array]"
}

function rank(severity) {
    return SEVERITY_RANK[severity] || 0
}

function severityLabel(severity) {
    return SEVERITY_LABEL[severity] || String(severity || "")
}

function indicatorLabel(id) {
    return INDICATOR_LABEL[id] || String(id || "")
}

// Normalize one wire indicator. Unknown shapes degrade to a row with no
// basis rather than to `undefined` in a template.
function normalizeIndicator(raw) {
    if (!raw || typeof raw !== "object" || typeof raw.id !== "string" || !raw.id)
        return null
    var attack = raw.attack && typeof raw.attack === "object" && typeof raw.attack.id === "string"
        ? { id: raw.attack.id, name: typeof raw.attack.name === "string" ? raw.attack.name : "" }
        : null
    return {
        id: raw.id,
        severity: typeof raw.severity === "string" ? raw.severity : "info",
        attack: attack,
        basis: typeof raw.basis === "string" ? raw.basis : ""
    }
}

function normalizeIndicators(list) {
    if (!isArray(list))
        return []
    var out = []
    for (var i = 0; i < list.length; i++) {
        var n = normalizeIndicator(list[i])
        if (n)
            out.push(n)
    }
    return out
}

// "AS13335 Cloudflare, Inc." / "AS13335" / "" — the network a peer sits in.
function networkLabel(c) {
    if (!c)
        return ""
    var asn = typeof c.asn === "number" ? "AS" + c.asn : ""
    var org = c.org ? String(c.org) : ""
    if (asn && org)
        return asn + " " + org
    return asn || org
}

// Mirrors ConnectionModel.isLive / DEAD_STATES: the one finished state any
// source produces is CLOSED, compared case-insensitively. tests/test_intel.js
// asserts the two agree so they cannot drift apart silently.
function isLive(c) {
    return !c || String(c.state || "").toUpperCase() !== "CLOSED"
}

function peerLabel(c) {
    if (!c || !c.remote)
        return ""
    var ip = c.remote.ip || ""
    var host = c.hostname ? String(c.hostname) : ""
    var port = c.remote.port ? ":" + c.remote.port : ""
    if (host)
        return host + port
    return (ip.indexOf(":") >= 0 ? "[" + ip + "]" : ip) + port
}

// One row per (connection, indicator), highest severity first, then newest.
// `connections` is the model's dict or an array of normalized connections.
function indicatorRows(connections) {
    var list = isArray(connections) ? connections : []
    if (!isArray(connections) && connections && typeof connections === "object") {
        for (var k in connections)
            list.push(connections[k])
    }
    var rows = []
    for (var i = 0; i < list.length; i++) {
        var c = list[i]
        if (!c || !isArray(c.indicators) || !c.indicators.length)
            continue
        for (var j = 0; j < c.indicators.length; j++) {
            var ind = c.indicators[j]
            if (!ind || !ind.id)
                continue
            rows.push({
                key: c.id + "#" + ind.id,
                connectionId: c.id,
                severity: ind.severity,
                indicator: ind.id,
                title: indicatorLabel(ind.id),
                attack: ind.attack || null,
                basis: ind.basis || "",
                appId: c.app ? c.app.id : "",
                appName: c.app ? (c.app.name || c.app.id || "") : "",
                peer: peerLabel(c),
                ip: c.remote ? c.remote.ip : "",
                port: c.remote ? c.remote.port : 0,
                country: c.country || "",
                network: networkLabel(c),
                live: isLive(c),
                seenAt: typeof c.seenAt === "number" ? c.seenAt : 0,
                connection: c
            })
        }
    }
    rows.sort(function (a, b) {
        var d = rank(b.severity) - rank(a.severity)
        if (d !== 0)
            return d
        if (b.seenAt !== a.seenAt)
            return b.seenAt - a.seenAt
        return a.key < b.key ? -1 : a.key > b.key ? 1 : 0
    })
    return rows
}

// {warning: n, notice: n, info: n, total: n}
function summarize(rows) {
    var out = { warning: 0, notice: 0, info: 0, total: 0 }
    for (var i = 0; i < rows.length; i++) {
        var s = rows[i].severity
        if (out.hasOwnProperty(s))
            out[s] += 1
        out.total += 1
    }
    return out
}

function summaryLine(rows) {
    var s = summarize(rows)
    if (s.total === 0)
        return "Nothing to flag on the current rows."
    var parts = []
    if (s.warning) parts.push(s.warning + (s.warning === 1 ? " warning" : " warnings"))
    if (s.notice) parts.push(s.notice + (s.notice === 1 ? " notice" : " notices"))
    if (s.info) parts.push(s.info + " info")
    return parts.join(" · ")
}

// Filter by severity ("" = all) and a free-text query over app, peer, ip,
// country, network, indicator id/title and basis.
function filterRows(rows, severity, query) {
    var q = String(query || "").toLowerCase().replace(/^\s+|\s+$/g, "")
    var out = []
    for (var i = 0; i < rows.length; i++) {
        var r = rows[i]
        if (severity && r.severity !== severity)
            continue
        if (q) {
            var blob = [r.appName, r.appId, r.peer, r.ip, r.country, r.network, r.indicator, r.title, r.basis,
                r.attack ? r.attack.id + " " + r.attack.name : ""].join(" ").toLowerCase()
            if (blob.indexOf(q) < 0)
                continue
        }
        out.push(r)
    }
    return out
}

// ---------------------------------------------------------- timed block

var BLOCK_DURATIONS = [{ seconds: 300, label: "5 min" }, { seconds: 900, label: "15 min" }, { seconds: 3600, label: "1 hour" }]

// Whether an indicator row may offer "block this destination for a while",
// and if not, why, in the words the row shows. The mechanism is the existing
// timed destination rule (block-scoped): one rule per app, never for system
// or unknown rows, never while the whole app is blocked, never without a pid
// to scope to, never for an address the host cannot afford to lose (the
// helper refuses those too; this says so before the round trip).
//
// `ctx`: { app (grouped app row or null), ip, port, blockingReady, helperBusy,
// current, enforcementPaused, rules (service.temporaryRules), helperId (fn),
// isBlockable (fn), hostWideUnsafe (fn ip,port -> bool), now }.
function destinationBlockState(ctx) {
    var c = ctx || {}
    var app = c.app || null
    var ip = c.ip ? String(c.ip) : ""
    var out = { canBlock: false, reason: "", existingRule: null, appId: app ? app.id : "" }
    if (!ip)
        return out
    if (!app) {
        out.reason = "App is not in the current list"
        return out
    }
    var rules = isArray(c.rules) ? c.rules : []
    var hid = typeof c.helperId === "function" ? c.helperId(app.id) : String(app.id || "")
    for (var i = 0; i < rules.length; i++) {
        if (rules[i] && rules[i].app === hid) {
            out.existingRule = rules[i]
            break
        }
    }
    if (out.existingRule) {
        out.reason = out.existingRule.ip === ip
            ? "Already blocked by a timed rule"
            : "One timed rule per app; " + out.existingRule.ip + " is already ruled"
        return out
    }
    if (typeof c.isBlockable === "function" ? !c.isBlockable(app) : app.system === true) {
        out.reason = "System and unknown rows cannot be blocked"
        return out
    }
    if (app.blocked) {
        out.reason = "The whole app is blocked already"
        return out
    }
    if (typeof c.hostWideUnsafe === "function" && c.hostWideUnsafe(ip, c.port)) {
        out.reason = "This address is one the host cannot afford to lose"
        return out
    }
    if (!isArray(app.pids) || app.pids.length === 0) {
        out.reason = "No running process to scope the rule to"
        return out
    }
    if (!c.blockingReady) {
        out.reason = "Blocking needs the installed helper"
        return out
    }
    if (c.enforcementPaused) {
        out.reason = "Enforcement is paused; the rule would wait for resume"
        return out
    }
    if (c.helperBusy) {
        out.reason = "The helper is busy"
        return out
    }
    if (c.current === false) {
        out.reason = "Monitoring is not current"
        return out
    }
    out.canBlock = true
    return out
}

// ---------------------------------------------------------------- exposure

function scopeLabel(scope) {
    if (scope === "all")
        return "All interfaces"
    if (scope === "loopback")
        return "Loopback only"
    if (scope === "address")
        return "One address"
    return String(scope || "")
}

function normalizeListener(raw) {
    if (!raw || typeof raw !== "object")
        return null
    var app = raw.app && typeof raw.app === "object" ? raw.app : {}
    return {
        proto: typeof raw.proto === "string" ? raw.proto : "tcp",
        ip: typeof raw.ip === "string" ? raw.ip : "",
        port: typeof raw.port === "number" ? raw.port : 0,
        appId: app.id ? String(app.id) : "unknown",
        appName: app.name ? String(app.name) : (app.id ? String(app.id) : "unknown"),
        system: app.system === true,
        pid: typeof app.pid === "number" ? app.pid : 0,
        exe: typeof raw.exe === "string" ? raw.exe : "",
        uid: typeof raw.uid === "number" ? raw.uid : null,
        scope: typeof raw.scope === "string" ? raw.scope : ""
    }
}

// Exposed-first: everything reachable from the network sorts above loopback,
// then by port. The key is stable so a view can keep selection across updates.
function listenerRows(listeners) {
    var out = []
    if (!isArray(listeners))
        return out
    for (var i = 0; i < listeners.length; i++) {
        var l = normalizeListener(listeners[i])
        if (!l)
            continue
        l.key = l.proto + ":" + l.ip + ":" + l.port + ":" + l.appId
        l.exposed = l.scope !== "loopback"
        l.scopeLabel = scopeLabel(l.scope)
        out.push(l)
    }
    out.sort(function (a, b) {
        if (a.exposed !== b.exposed)
            return a.exposed ? -1 : 1
        if (a.port !== b.port)
            return a.port - b.port
        if (a.proto !== b.proto)
            return a.proto < b.proto ? -1 : 1
        return a.key < b.key ? -1 : a.key > b.key ? 1 : 0
    })
    return out
}

function exposureLine(rows) {
    var exposed = 0
    for (var i = 0; i < rows.length; i++)
        if (rows[i].exposed)
            exposed += 1
    if (rows.length === 0)
        return "No listening sockets observed."
    if (exposed === 0)
        return rows.length + (rows.length === 1 ? " socket listens" : " sockets listen") + ", all on loopback only."
    return exposed + " of " + rows.length + (rows.length === 1 ? " socket is" : " sockets are") + " reachable from the network."
}

// ---------------------------------------------------------------- watchlist

var WATCH_KINDS = [
    { value: "asn", label: "ASN", hint: "AS13335 or 13335" },
    { value: "country", label: "Country", hint: "two-letter code, e.g. KP" },
    { value: "cidr", label: "IP or range", hint: "203.0.113.7 or 203.0.113.0/24" },
    { value: "host", label: "Hostname suffix", hint: "example.com matches cdn.example.com" },
    { value: "port", label: "Remote port", hint: "4444" },
    { value: "app", label: "App id or path", hint: "curl or /usr/bin/curl" }
]

// Light client-side check so the form can refuse the obviously empty or
// malformed value before a round trip. The daemon is authoritative and
// reports its own error on the watchlist frame.
function validateWatch(kind, value) {
    var v = String(value || "").replace(/^\s+|\s+$/g, "")
    if (!v)
        return "Enter a value"
    if (v.length > 256)
        return "Too long"
    if (kind === "asn" && !/^(as|AS)?\d+$/.test(v))
        return "An ASN is a number, like AS13335"
    if (kind === "country" && !/^[A-Za-z]{2}$/.test(v))
        return "A country is a two-letter code"
    if (kind === "port" && !(/^\d+$/.test(v) && Number(v) <= 65535))
        return "A port is 0..65535"
    if (kind === "host" && (v.indexOf(".") < 0 || /\s/.test(v)))
        return "A hostname needs a dot and no spaces"
    if (kind === "cidr" && !/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(v))
        return "An address or CIDR range, like 203.0.113.0/24"
    return ""
}

function normalizeWatchRule(raw) {
    if (!raw || typeof raw !== "object" || typeof raw.id !== "string")
        return null
    return {
        id: raw.id,
        kind: typeof raw.kind === "string" ? raw.kind : "",
        value: typeof raw.value === "string" ? raw.value : "",
        note: typeof raw.note === "string" ? raw.note : "",
        ts: typeof raw.ts === "number" ? raw.ts : 0,
        hits: typeof raw.hits === "number" ? raw.hits : 0,
        lastHit: typeof raw.last_hit === "number" ? raw.last_hit : 0
    }
}

function kindLabel(kind) {
    for (var i = 0; i < WATCH_KINDS.length; i++)
        if (WATCH_KINDS[i].value === kind)
            return WATCH_KINDS[i].label
    return String(kind || "")
}

function ruleTitle(r) {
    if (!r)
        return ""
    var v = r.kind === "asn" ? "AS" + r.value : r.value
    return kindLabel(r.kind) + " " + v
}

function ruleDetail(r, now, fmt) {
    if (!r)
        return ""
    var parts = []
    if (r.note)
        parts.push(r.note)
    if (r.hits > 0)
        parts.push(r.hits + (r.hits === 1 ? " hit" : " hits") + (r.lastHit ? ", last " + ago(r.lastHit, now, fmt) : ""))
    else
        parts.push("no hits yet")
    return parts.join(" · ")
}

// Most recently hit first, then newest rule first.
function watchRows(rules, now) {
    var out = []
    if (!isArray(rules))
        return out
    for (var i = 0; i < rules.length; i++) {
        var r = normalizeWatchRule(rules[i])
        if (!r)
            continue
        r.title = ruleTitle(r)
        r.detail = ruleDetail(r, now)
        out.push(r)
    }
    out.sort(function (a, b) {
        if (a.lastHit !== b.lastHit)
            return b.lastHit - a.lastHit
        return b.ts - a.ts
    })
    return out
}

// ------------------------------------------------------------------- pivot

// "ip:1.2.3.4" from a row for the investigate drawer; `kind` picks the
// dimension to pivot on.
function subjectFor(c, kind) {
    if (!c)
        return ""
    if (kind === "app")
        return c.app && c.app.id ? "app:" + c.app.id : ""
    if (kind === "asn")
        return typeof c.asn === "number" ? "asn:" + c.asn : ""
    if (kind === "host")
        return c.hostname ? "host:" + registrable(c.hostname) : ""
    if (kind === "country")
        return c.country ? "country:" + c.country : ""
    if (kind === "network")
        return c.networkKey ? "network:" + c.networkKey : ""
    return c.remote && c.remote.ip ? "ip:" + c.remote.ip : ""
}

function registrable(host) {
    var parts = String(host || "").split(".").filter(function (p) { return p })
    return parts.length >= 2 ? parts.slice(-2).join(".") : String(host || "")
}

// Subjects worth offering on a row, in the order the buttons appear.
function pivotOptions(c) {
    var out = []
    var seen = {}
    var kinds = ["ip", "host", "asn", "app", "country"]
    for (var i = 0; i < kinds.length; i++) {
        var s = subjectFor(c, kinds[i])
        if (s && !seen[s]) {
            seen[s] = true
            out.push({ kind: kinds[i], subject: s, label: pivotLabel(kinds[i], s) })
        }
    }
    return out
}

function pivotLabel(kind, subject) {
    var v = subject.indexOf(":") >= 0 ? subject.substring(subject.indexOf(":") + 1) : subject
    if (kind === "asn")
        return "AS" + v
    if (kind === "app")
        return "app " + v
    if (kind === "host")
        return "*." + v
    return v
}

function normalizePivot(raw) {
    var p = raw && typeof raw === "object" ? raw : {}
    function num(v) { return typeof v === "number" && isFinite(v) ? v : 0 }
    function arr(v) { return isArray(v) ? v : [] }
    return {
        subject: p.subject && typeof p.subject === "object" ? { kind: String(p.subject.kind || ""), value: String(p.subject.value || "") } : null,
        since: num(p.since),
        until: num(p.until),
        connections: num(p.connections),
        live: num(p.live),
        tx: num(p.tx),
        rx: num(p.rx),
        first: num(p.first),
        last: num(p.last),
        apps: arr(p.apps),
        destinations: arr(p.destinations),
        countries: arr(p.countries),
        asns: arr(p.asns),
        ports: arr(p.ports),
        indicators: arr(p.indicators),
        timeline: arr(p.timeline).map(num),
        timelineBucketMs: num(p.timelineBucketMs),
        cadenceMs: typeof p.cadenceMs === "number" ? p.cadenceMs : null,
        truncated: p.truncated === true
    }
}

// `fmt` is the panel's ux object (js/Ux.js). Its `time` is set when the user
// chose how timestamps read; without it this prints the age it always has.
function ago(ts, now, fmt) {
    if (!ts)
        return "never"
    if (fmt && fmt.time)
        return fmt.time(ts, typeof now === "number" ? now : Date.now())
    var s = Math.max(0, Math.round(((typeof now === "number" ? now : Date.now()) - ts) / 1000))
    if (s < 60) return s + "s ago"
    if (s < 3600) return Math.round(s / 60) + "m ago"
    if (s < 86400) return Math.round(s / 3600) + "h ago"
    return Math.round(s / 86400) + "d ago"
}

function duration(ms) {
    var s = Math.round(ms / 1000)
    if (s < 90) return s + "s"
    if (s < 5400) return Math.round(s / 60) + "m"
    if (s < 172800) return Math.round(s / 3600) + "h"
    return Math.round(s / 86400) + "d"
}

function bytes(n, fmt) {
    if (fmt && fmt.bytes)
        return fmt.bytes(n)
    var K = 1024
    if (n >= K * K * K) return (n / (K * K * K)).toFixed(1) + " GiB"
    if (n >= K * K) return (n / (K * K)).toFixed(1) + " MiB"
    if (n >= K) return Math.round(n / K) + " KiB"
    return n + " B"
}

// Fact rows for the pivot drawer: [{label, value}].
function pivotFacts(raw, now, fmt) {
    var p = normalizePivot(raw)
    var rows = []
    function row(label, value) { rows.push({ label: label, value: String(value) }) }
    if (p.connections === 0) {
        row("Matched", "no retained observations in this window")
        return rows
    }
    row("Matched", p.connections + (p.connections === 1 ? " connection" : " connections") + " (" + p.live + " live)" + (p.truncated ? " · history capped, a floor" : ""))
    row("Seen", "first " + ago(p.first, now, fmt) + ", last " + ago(p.last, now, fmt))
    row("Sampled transfer", "↑ " + bytes(p.tx, fmt) + " ↓ " + bytes(p.rx, fmt))
    if (p.cadenceMs !== null)
        row("Cadence", "about every " + duration(p.cadenceMs))
    if (p.apps.length)
        row("Apps", p.apps.slice(0, 8).map(function (a) { return (a.name || a.id) + " ×" + a.connections }).join(", ") + (p.apps.length > 8 ? ", +" + (p.apps.length - 8) + " more" : ""))
    if (p.destinations.length)
        row("Destinations", p.destinations.slice(0, 6).map(function (d) { return (d.hostname || d.ip) + ":" + d.port + " ×" + d.connections }).join("\n") + (p.destinations.length > 6 ? "\n+" + (p.destinations.length - 6) + " more" : ""))
    if (p.asns.length)
        row("Networks", p.asns.slice(0, 6).map(function (f) { return f.label + " ×" + f.connections }).join("\n"))
    if (p.countries.length)
        row("Countries", p.countries.slice(0, 10).map(function (f) { return f.label + " ×" + f.connections }).join(", "))
    if (p.ports.length)
        row("Ports", p.ports.slice(0, 10).map(function (f) { return f.label + " ×" + f.connections }).join(", "))
    if (p.indicators.length)
        row("Indicators", p.indicators.map(function (i) { return severityLabel(i.severity) + " · " + indicatorLabel(i.id) + " ×" + i.connections }).join("\n"))
    return rows
}

// ---------------------------------------------------------------- timeline

function normalizeTimeline(raw) {
    var t = raw && typeof raw === "object" ? raw : {}
    function num(v) { return typeof v === "number" && isFinite(v) && v >= 0 ? v : 0 }
    function counts(v, n) {
        var out = []
        for (var i = 0; i < n; i++)
            out.push(isArray(v) && typeof v[i] === "number" && isFinite(v[i]) && v[i] >= 0 ? v[i] : 0)
        return out
    }
    var buckets = Math.max(0, Math.floor(num(t.buckets)))
    var apps = []
    if (isArray(t.apps)) {
        for (var i = 0; i < t.apps.length; i++) {
            var a = t.apps[i]
            if (!a || typeof a !== "object" || typeof a.id !== "string" || !a.id)
                continue
            apps.push({ id: a.id, name: typeof a.name === "string" && a.name ? a.name : a.id, counts: counts(a.counts, buckets), total: num(a.total) })
        }
    }
    var other = isArray(t.other) && t.other.length ? counts(t.other, buckets) : []
    return {
        since: num(t.since),
        until: num(t.until),
        bucketMs: Math.max(60000, num(t.bucketMs)),
        buckets: buckets,
        apps: apps,
        other: other,
        otherApps: Math.floor(num(t.otherApps)),
        total: counts(t.total, buckets),
        max: num(t.max),
        truncated: t.truncated === true
    }
}

// Rows for the heatmap: apps, then one folded row. Each cell carries its
// count and a 0..1 shade, sqrt-scaled against the busiest cell so a quiet
// hour next to a busy one is still visible. One hue, light to dark: the
// shade is magnitude and nothing else.
function timelineRows(raw) {
    var t = normalizeTimeline(raw)
    var rows = []
    function row(label, id, counts, total) {
        var cells = []
        for (var i = 0; i < counts.length; i++) {
            var n = counts[i]
            cells.push({ count: n, shade: n > 0 && t.max > 0 ? Math.sqrt(n / t.max) : 0 })
        }
        rows.push({ label: label, id: id, cells: cells, total: total })
    }
    for (var i = 0; i < t.apps.length; i++)
        row(t.apps[i].name, t.apps[i].id, t.apps[i].counts, t.apps[i].total)
    if (t.other.length) {
        var sum = 0
        for (var j = 0; j < t.other.length; j++) sum += t.other[j]
        row("+" + t.otherApps + " other " + (t.otherApps === 1 ? "app" : "apps"), "", t.other, sum)
    }
    return rows
}

function pad2(n) { return (n < 10 ? "0" : "") + n }

// Column labels in local time: every 6 buckets for a day, every 4 (a day of
// six-hour buckets) for a week. [{index, label}].
function timelineLabels(raw) {
    var t = normalizeTimeline(raw)
    var out = []
    if (!t.buckets)
        return out
    var week = t.bucketMs >= 6 * 3600000
    var step = week ? 4 : 6
    for (var i = 0; i < t.buckets; i += step) {
        var d = new Date(t.since + i * t.bucketMs)
        out.push({ index: i, label: week ? pad2(d.getMonth() + 1) + "/" + pad2(d.getDate()) : pad2(d.getHours()) + ":" + pad2(d.getMinutes()) })
    }
    return out
}

// The cell under a point in a grid of `rows` × `buckets` filling w×h. Null
// when outside. For the hover tooltip.
function timelineCellAt(rows, buckets, x, y, w, h) {
    if (!rows.length || !buckets || w <= 0 || h <= 0 || x < 0 || y < 0 || x >= w || y >= h)
        return null
    var r = Math.floor(y / (h / rows.length))
    var c = Math.floor(x / (w / buckets))
    if (r < 0 || r >= rows.length || c < 0 || c >= buckets)
        return null
    return { row: r, col: c }
}

function timelineHoverText(raw, rows, cell) {
    if (!cell || !rows[cell.row])
        return ""
    var t = normalizeTimeline(raw)
    var row = rows[cell.row]
    var n = row.cells[cell.col] ? row.cells[cell.col].count : 0
    var from = new Date(t.since + cell.col * t.bucketMs)
    var to = new Date(Math.min(t.until, t.since + (cell.col + 1) * t.bucketMs))
    var when = pad2(from.getMonth() + 1) + "/" + pad2(from.getDate()) + " " + pad2(from.getHours()) + ":" + pad2(from.getMinutes()) + "–" + pad2(to.getHours()) + ":" + pad2(to.getMinutes())
    return row.label + " · " + when + " · " + n + (n === 1 ? " connection" : " connections")
}

function timelineSummary(raw) {
    var t = normalizeTimeline(raw)
    if (!t.buckets)
        return "No timeline yet."
    var total = 0
    for (var i = 0; i < t.total.length; i++) total += t.total[i]
    if (total === 0)
        return "No observations in retained history for this window."
    var span = t.bucketMs >= 6 * 3600000 ? "six-hour" : "hourly"
    return (t.apps.length + t.otherApps) + " apps over " + t.buckets + " " + span + " buckets. A connection counts in every bucket it was observed in; shade is sqrt-scaled to the busiest cell." + (t.truncated ? " History was capped; counts are a floor." : "")
}

// Timeline bars normalized to 0..1 for a Canvas sparkline; empty when flat.
function timelineBars(raw) {
    var t = normalizePivot(raw).timeline
    var max = 0
    for (var i = 0; i < t.length; i++)
        if (t[i] > max)
            max = t[i]
    if (max === 0)
        return []
    return t.map(function (n) { return n / max })
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        SEVERITY_RANK: SEVERITY_RANK,
        WATCH_KINDS: WATCH_KINDS,
        rank: rank,
        severityLabel: severityLabel,
        indicatorLabel: indicatorLabel,
        normalizeIndicator: normalizeIndicator,
        normalizeIndicators: normalizeIndicators,
        networkLabel: networkLabel,
        isLive: isLive,
        peerLabel: peerLabel,
        indicatorRows: indicatorRows,
        summarize: summarize,
        summaryLine: summaryLine,
        filterRows: filterRows,
        BLOCK_DURATIONS: BLOCK_DURATIONS,
        destinationBlockState: destinationBlockState,
        scopeLabel: scopeLabel,
        normalizeListener: normalizeListener,
        listenerRows: listenerRows,
        exposureLine: exposureLine,
        validateWatch: validateWatch,
        normalizeWatchRule: normalizeWatchRule,
        kindLabel: kindLabel,
        ruleTitle: ruleTitle,
        ruleDetail: ruleDetail,
        watchRows: watchRows,
        subjectFor: subjectFor,
        registrable: registrable,
        pivotOptions: pivotOptions,
        normalizePivot: normalizePivot,
        pivotFacts: pivotFacts,
        timelineBars: timelineBars,
        normalizeTimeline: normalizeTimeline,
        timelineRows: timelineRows,
        timelineLabels: timelineLabels,
        timelineCellAt: timelineCellAt,
        timelineHoverText: timelineHoverText,
        timelineSummary: timelineSummary,
        ago: ago,
        duration: duration,
        bytes: bytes
    }
}
