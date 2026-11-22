function dict() {
    return Object.create(null)
}

function dictHas(map, key) {
    return !!(map && Object.prototype.hasOwnProperty.call(map, String(key)))
}

function dictGet(map, key) {
    if (!dictHas(map, key))
        return undefined
    return map[String(key)]
}

function dictSet(map, key, value) {
    if (!map)
        return
    key = String(key)
    if (key === "__proto__") {
        Object.defineProperty(map, key, {
            value: value,
            enumerable: true,
            writable: true,
            configurable: true
        })
        return
    }
    map[key] = value
}

function dictDel(map, key) {
    if (!dictHas(map, key))
        return
    delete map[String(key)]
}

function asDict(obj) {
    var d = dict()
    if (!obj)
        return d
    var keys = Object.keys(obj)
    var i
    for (i = 0; i < keys.length; i++)
        dictSet(d, keys[i], obj[keys[i]])
    return d
}

function emptyState() {
    return {
        revision: 0,
        hello: false,
        coverage: "TCP + connected UDP",
        rdns: false,
        connections: dict(),
        traffic: dict(),
        apps: dict(),
        // id -> { name, icon, desktop, system }, remembered for the lifetime of
        // the session. A blocked app's connections die by design, so without a
        // cache its row would come back as a bare id the moment the block took
        // effect — the name is the only handle the user has on it.
        appMeta: dict(),
        ordered: [],
        count: 0,
        historyApps: dict(),
        historyOrdered: [],
        historyCount: 0,
        // What the daemon says it is tracking, all states. Diagnostic only —
        // never rendered as a live count. See the tick branch in applyEvent.
        sourceCount: 0,
        pulse: false,
        pulseNetwork: "",
        awayKeys: [],
        digestText: "",
        blocked: dict(),
        temporaryRules: [],
        lastError: ""
    }
}

function copyDict(map) {
    var d = dict()
    if (!map)
        return d
    for (var k in map)
        dictSet(d, k, map[k])
    return d
}

// The state applyLine hands back is a new object, and the one it was given is
// never modified -- Health.applyIngest relies on that to drop a line that
// throws halfway without keeping half of it.
//
// That used to be bought with a JSON round trip of the whole state on every
// event, which at 300 connections cost ~70 ms per daemon sample on the GUI
// thread (~230 ms at 1000) and is what made the panel stutter. It is now
// copy-on-write: this copies only the containers applyEvent writes into, and
// shares everything it only reads or replaces wholesale. Connection objects
// are never modified after normalizeConn builds them, and rebuild() makes
// fresh app rows, so both can be shared. The one in-place write to a shared
// row, the sparkline sample on tick, copies the row first (sampleSparklines).
//
// Adding a new in-place write to applyEvent means adding its container here;
// test_connection_model.js checks every event type leaves its input intact.
function cloneState(state) {
    if (!state)
        return emptyState()
    var next = {}
    for (var k in state)
        next[k] = state[k]
    next.connections = copyDict(state.connections)
    next.apps = copyDict(state.apps)
    next.appMeta = copyDict(state.appMeta)
    next.blocked = copyDict(state.blocked)
    next.awayKeys = (state.awayKeys || []).slice()
    return next
}

// opts.deferRebuild: connect and disconnect only mark the state stale
// (needsRebuild) instead of regrouping and re-sorting every app on the spot.
// The daemon sends a burst of them per sample; Service.qml applies the whole
// burst this way and then calls settle() once. Everything that reads derived
// state first (a tick's sparkline sample) settles on its own.
function applyLine(state, line, now, opts) {
    if (!state)
        state = emptyState()
    if (!line)
        return state
    var trimmed = String(line).replace(/^\s+|\s+$/g, "")
    if (!trimmed || trimmed.charAt(0) === "#")
        return state
    var ev
    try {
        ev = JSON.parse(trimmed)
    } catch (e) {
        var failed = cloneState(state)
        failed.lastError = "bad json"
        failed.revision += 1
        return failed
    }
    var next = cloneState(state)
    try {
        applyEvent(next, ev, now || Date.now(), opts)
    } catch (e) {
        throw e
    }
    return next
}

function applyEvent(state, ev, now, opts) {
    if (!ev || !ev.type)
        return state
    var defer = !!(opts && opts.deferRebuild)
    if (ev.type === "hello") {
        state.hello = true
        state.traffic = dict()
        state.coverage = ev.coverage === "tcp+connected-udp" ? "TCP + connected UDP" : (ev.coverage || state.coverage)
        state.rdns = ev.rdns === true
    } else if (ev.type === "snapshot") {
        var list = ev.connections
        if (!list || Object.prototype.toString.call(list) !== "[object Array]")
            return state
        var i
        for (i = 0; i < list.length; i++) {
            if (!list[i] || typeof list[i] !== "object" || !list[i].id)
                return state
        }
        state.connections = dict()
        for (i = 0; i < list.length; i++)
            putConnection(state, list[i], now, false)
        rebuild(state, now)
    } else if (ev.type === "connect") {
        putConnection(state, ev, now, true)
        rebuildOrDefer(state, now, defer)
    } else if (ev.type === "disconnect") {
        if (ev.id && dictHas(state.connections, ev.id))
            dictDel(state.connections, ev.id)
        rebuildOrDefer(state, now, defer)
    } else if (ev.type === "bandwidth") {
        state.traffic = dict()
        for (var ti = 0; ti < ev.apps.length; ti++)
            dictSet(state.traffic, ev.apps[ti].id, ev.apps[ti])
        rebuildOrDefer(state, now, defer)
    } else if (ev.type === "tick") {
        settle(state, now)
        // A tick's count is the daemon's tally of every row it is tracking, in
        // any state. It must not touch state.count, which is the live-only
        // number the bar pill renders: letting a heartbeat overwrite it puts
        // history back under a label that says "live connections", which is the
        // defect the Live/History split exists to fix. A tick changes no
        // connection, so the counts from the last rebuild are already correct.
        if (typeof ev.count === "number")
            state.sourceCount = ev.count
        sampleSparklines(state)
        state.revision += 1
    } else if (ev.type === "digest") {
        state.awayKeys = ev.keys || []
        var n = typeof ev.newNetworks === "number" ? ev.newNetworks : state.awayKeys.length
        state.digestText = digestLine(n)
        state.revision += 1
    } else if (ev.type === "status") {
        state.lastError = ev.message === "ok" ? "" : (ev.message || "")
        state.revision += 1
    }
    return state
}

function putConnection(state, raw, now, detectPulse) {
    if (!raw)
        return
    var conn = normalizeConn(raw, now)
    if (!conn || !conn.id)
        return
    var isNew = !dictHas(state.connections, conn.id)
    dictSet(state.connections, conn.id, conn)
    if (detectPulse && isNew && conn.newNetwork && !conn.unresolved) {
        // The away digest counts history on purpose. "N new networks while you
        // were away" is a question about the past, and a backfill is the best
        // answer to it there is.
        if (state.awayKeys.indexOf(conn.networkKey) === -1 && conn.networkKey)
            state.awayKeys.push(conn.networkKey)
        state.digestText = digestLine(state.awayKeys.length)
        // The amber pulse is not. It animates the bar and tooltips "new
        // network" in the present tense, so a finished row out of yesterday's
        // OpenSnitch database must not fire it. enrich() marks historical rows
        // new_network from the same seen-set as live ones (daemon/src/main.rs),
        // so state is the only thing here that tells them apart.
        if (isLive(conn)) {
            state.pulse = true
            state.pulseNetwork = conn.networkKey || conn.remote.ip
        }
    }
}

function normalizeConn(raw, now) {
    if (!raw)
        return { id: "", proto: "tcp", inode: 0, app: { id: "unknown", name: "unknown", icon: "", desktop: "", pid: 0, system: false, exe: "", owner: null }, local: { ip: "", port: 0 }, remote: { ip: "", port: 0 }, state: "", country: "", lat: 0, lon: 0, unresolved: false, newNetwork: false, networkKey: "", hostname: "", hostnameSource: "", clue: null, tag: null, policy: [], asn: null, org: "", indicators: [], seenAt: now || Date.now() }
    var app = raw.app || {}
    var local = raw.local || {}
    var remote = raw.remote || {}
    return {
        id: raw.id || "",
        proto: raw.proto || "tcp",
        inode: raw.inode || 0,
        exe: typeof raw.exe === "string" ? raw.exe : "",
        uid: typeof raw.uid === "number" ? raw.uid : null,
        reason: typeof raw.reason === "string" ? raw.reason : "",
        bytes: raw.bytes || null,
        evidence: raw.evidence && typeof raw.evidence === "object" ? {
            source: String(raw.evidence.source || ""),
            recordedAt: typeof raw.evidence.recordedAt === "number" ? raw.evidence.recordedAt : null,
            ownerMethod: String(raw.evidence.ownerMethod || ""),
            hash: String(raw.evidence.hash || ""),
            container: String(raw.evidence.container || ""),
            // Distribution package owning the executable ("none" when the
            // manager said nothing does); absent until the lookup lands.
            package: typeof raw.evidence.package === "string" ? raw.evidence.package : "",
            // Ancestors, command line and cwd at first sight (docs/INTEL.md).
            lineage: raw.evidence.lineage && typeof raw.evidence.lineage === "object" ? {
                ancestors: Object.prototype.toString.call(raw.evidence.lineage.ancestors) === "[object Array]"
                    ? raw.evidence.lineage.ancestors.filter(function(a) { return a && typeof a.pid === "number" })
                        .map(function(a) { return { pid: a.pid, comm: String(a.comm || ""), exe: String(a.exe || "") } })
                    : [],
                cmdline: typeof raw.evidence.lineage.cmdline === "string" ? raw.evidence.lineage.cmdline : "",
                cwd: typeof raw.evidence.lineage.cwd === "string" ? raw.evidence.lineage.cwd : "",
                truncated: raw.evidence.lineage.truncated === true
            } : null,
            verdict: raw.evidence.verdict && typeof raw.evidence.verdict === "object" ? {
                action: String(raw.evidence.verdict.action || ""),
                provenance: String(raw.evidence.verdict.provenance || ""),
                rule_id: String(raw.evidence.verdict.rule_id || "")
            } : null
        } : null,
        app: {
            id: app.id || "unknown",
            name: app.name || app.id || "unknown",
            icon: app.icon || "",
            desktop: app.desktop || "",
            pid: app.pid || 0,
            system: app.system === true,
            exe: app.exe ? String(app.exe) : "",
            // The account the process runs as, sent only when it is not the
            // daemon's own user (the system daemon naming a logged-in user's
            // app): { uid, name }. Null on every row a user daemon sends.
            owner: app.owner && typeof app.owner === "object" && typeof app.owner.uid === "number"
                ? { uid: app.owner.uid, name: String(app.owner.name || "") }
                : null
        },
        local: { ip: local.ip || "", port: local.port || 0 },
        remote: { ip: remote.ip || "", port: remote.port || 0 },
        state: raw.state || "",
        country: raw.country || "",
        lat: typeof raw.lat === "number" ? raw.lat : 0,
        lon: typeof raw.lon === "number" ? raw.lon : 0,
        unresolved: raw.unresolved === true,
        newNetwork: raw.newNetwork === true,
        networkKey: raw.networkKey || networkKey(remote.ip || ""),
        // The PTR name the daemon resolved. Peers.peerName prefers it to the
        // bare address, but this allow-list never named it, so the Live tab
        // showed IPs for every peer the daemon had already named. The wire
        // contract test (tests/test_wire_contract.js) now fails on any field
        // the daemon sends that this function drops.
        hostname: typeof raw.hostname === "string" ? raw.hostname : "",
        // "dns" (what the app asked for, from the optional collector), "ptr"
        // (a reverse lookup), "source" (a database source reported it), "".
        hostnameSource: typeof raw.hostnameSource === "string" ? raw.hostnameSource : "",
        // The daemon's evidence for WHO this peer is. This function is an
        // allow-list, so a field the daemon sends is invisible to the whole UI
        // until it is named here -- and that is not a theoretical risk: the
        // naming feature shipped with these two missing and every peer row
        // rendered as a bare address with no evidence and no tag, while the
        // daemon was emitting both. Peers.js reads `label`/`basis`/
        // `confidence`/`source`; normalize to that shape rather than passing
        // the raw object, so a daemon that renames a subfield degrades to "no
        // evidence" instead of to `undefined` in a template.
        clue: raw.clue ? {
            label: raw.clue.label || "",
            basis: raw.clue.basis || "",
            confidence: raw.clue.confidence || "",
            kind: raw.clue.kind || ""
        } : null,
        tag: raw.tag ? {
            label: raw.tag.label || "",
            source: raw.tag.source || "",
            kind: raw.tag.kind || ""
        } : null,
        // Org network-policy rules this connection matched (monitor only). Named here
        // because this function is an allow-list: see the clue note above.
        policy: Object.prototype.toString.call(raw.policy) === "[object Array]"
            ? raw.policy.filter(function(p) { return p && typeof p.label === "string" && p.label })
                .map(function(p) { return { ruleId: String(p.ruleId || ""), label: p.label } })
            : [],
        // The peer's autonomous system and its registrant, from the bundled
        // DB-IP ASN database. Null/empty when private, unresolved or unlisted.
        asn: typeof raw.asn === "number" ? raw.asn : null,
        org: typeof raw.org === "string" ? raw.org : "",
        // Local indicators (docs/INTEL.md). Normalized to the shape js/Intel.js
        // reads so a renamed subfield degrades to an empty basis, not undefined.
        indicators: Object.prototype.toString.call(raw.indicators) === "[object Array]"
            ? raw.indicators.filter(function(i) { return i && typeof i.id === "string" && i.id })
                .map(function(i) { return {
                    id: i.id,
                    severity: typeof i.severity === "string" ? i.severity : "info",
                    attack: i.attack && typeof i.attack === "object" && typeof i.attack.id === "string"
                        ? { id: i.attack.id, name: typeof i.attack.name === "string" ? i.attack.name : "" } : null,
                    basis: typeof i.basis === "string" ? i.basis : ""
                } })
            : [],
        seenAt: now || Date.now()
    }
}

// Connection states that mean the conversation is over.
//
// This list is the only thing separating the Live tab from History (SCHEMA 2.4),
// and it decides what the bar pill counts — the pill's tooltip says "live
// connections", so a wrong answer here makes the product lie on its most
// visible surface.
//
// One entry, and the reason it is only one is the whole lesson here.
//
//   opensnitch is the only source that reports finished conversations.
//     row_to_flow hardcodes FlowState::Closed on every row
//     (daemon/src/source/opensnitch.rs:289) and Flow::to_legacy renders that
//     as "CLOSED" (daemon/src/flow.rs:204). Nothing else ever produces it.
//   procfs, the DEFAULT source, reports only sockets that still exist in the
//     kernel's table, and it never reports a finished one: sample() drops
//     LISTEN, TIME_WAIT and TCP CLOSE before a Connection is built
//     (daemon/src/main.rs:680, procfs.rs:48), and a TCP conversation that ends
//     arrives as a `disconnect` event, which deletes the row rather than
//     filing it. So procfs contributes nothing to History at all.
//   ebpf, when it lands, emits OBSERVED for listen mode and is otherwise
//     unspecified — so an unrecognised string is a case that WILL occur.
//
// ⚠ "CLOSE" was in this list and had to be removed. It looked safe: the string
// is right there in procfs's state table. But that filter is TCP-only, and an
// *unconnected UDP socket* — an mDNS listener, say — has no remote endpoint and
// so parses as state CLOSE (procfs.rs:259) while being perfectly alive. Denying
// it hid live sockets from the pill, which is the severe direction. Reading the
// emitter's vocabulary is not the same as reading what can reach the consumer.
//
// Deny-listing the dead rather than allow-listing the live is still right: an
// allow-list has to name every live state correctly and silently drops any it
// misses, including whatever a future source invents. But that argument only
// holds while every entry here is a state that *can only* mean finished.
var DEAD_STATES = { "CLOSED": true }

// @param {object} conn - a normalized connection; conn.state is a string and
//                        may be "" for a source that does not report one.
// @returns {boolean} true if this belongs in Live and counts toward the pill.
function isLive(conn) {
    if (!conn)
        return false
    return !DEAD_STATES[String(conn.state || "").toUpperCase()]
}

// Order rows by a key that does not move.
//
// This list used to sort by `lastActivity` descending, and it is rebuilt on
// every daemon sample — 500ms (Service.qml passes --interval-ms 500). So rows
// physically reordered twice a second, under the pointer, while the user was
// aiming at one. Hover is a commitment signal: the row carries a block toggle,
// so a row that moves out from under a committed click is not a cosmetic
// annoyance, it is a misfire on a privileged action.
//
// Name is the key the user actually reads and remembers, so it is the key that
// makes a row an address. Activity has not been discarded — `activityRank` and
// `lastActivity` ride along on each row, so the UI can mark the busy ones
// without paying for the movement.
function nameIdCmp(x, y) {
    var n = String(x.name || x.id).localeCompare(String(y.name || y.id))
    if (n !== 0)
        return n
    // localeCompare can tie on two different apps with the same display
    // name. id is unique and never changes, so it settles the tie the same
    // way on every rebuild — which is the whole point of this function.
    return String(x.id).localeCompare(String(y.id))
}

function liveConnectionCount(app) {
    var cs = (app && app.connections) || []
    var n = 0
    for (var i = 0; i < cs.length; i++) {
        if (isLive(cs[i]))
            n++
    }
    return n
}

function isUnknownApp(app) {
    if (!app)
        return false
    return String(app.id || "").toLowerCase() === "unknown"
}

function orderRows(apps, sortKey) {
    var ordered = []
    for (var k in apps)
        ordered.push(apps[k])
    // Rank BEFORE ordering, so the badge still reflects activity even though
    // position no longer does. 0 is the busiest. Computed for every sort key.
    var byActivity = ordered.slice().sort(function (x, y) {
        return (y.lastActivity || 0) - (x.lastActivity || 0)
    })
    for (var i = 0; i < byActivity.length; i++)
        byActivity[i].activityRank = i
    var key = sortKey || "name"
    ordered.sort(function (x, y) {
        var d = 0
        if (key === "activity")
            d = (y.lastActivity || 0) - (x.lastActivity || 0)
        else if (key === "connections")
            d = liveConnectionCount(y) - liveConnectionCount(x)
        else if (key === "bandwidth") {
            var xt = x.traffic, yt = y.traffic
            var xs = xt && xt.txRate !== null && xt.rxRate !== null ? xt.txRate + xt.rxRate : -1
            var ys = yt && yt.txRate !== null && yt.rxRate !== null ? yt.txRate + yt.rxRate : -1
            d = ys - xs
        } else if (key === "blocked")
            d = (x.blocked === true ? 0 : 1) - (y.blocked === true ? 0 : 1)
        if (d !== 0)
            return d
        return nameIdCmp(x, y)
    })
    return ordered
}

// Group a flat connection list into per-app rows.
//
// `prior` is the app map to inherit sparkline history from, or null when the
// caller has no history to carry (the History tab has no sparkline — a bar
// chart of finished conversations would imply a rate that is not being sampled).
function groupApps(state, list, prior) {
    var apps = dict()
    for (var i = 0; i < list.length; i++) {
        var c = list[i]
        var aid = c.app.id || "unknown"
        if (!dictHas(apps, aid)) {
            var priorApp = dictGet(prior, aid)
            var known = dictGet(state.blocked, aid)
            dictSet(apps, aid, {
                id: aid,
                name: c.app.name || aid,
                icon: c.app.icon || "",
                desktop: c.app.desktop || "",
                system: c.app.system === true,
                pids: [],
                // Distinct executables behind this row; see blockProgramsLine.
                exes: [],
                connections: [],
                unresolved: 0,
                lastActivity: 0,
                spark: (priorApp && priorApp.spark) ? priorApp.spark.slice() : [],
                blocked: !!known,
                mechanism: (known && known.mechanism) || "",
                // A row built from live connections is never dormant. Only
                // injectBlockedRows below sets this.
                dormant: false,
                traffic: dictGet(state.traffic, aid) || null,
                activityRank: 0
            })
        }
        var a = dictGet(apps, aid)
        a.connections.push(c)
        if (c.app.pid && a.pids.indexOf(c.app.pid) === -1)
            a.pids.push(c.app.pid)
        if (c.app.exe && a.exes.indexOf(c.app.exe) === -1)
            a.exes.push(c.app.exe)
        if (c.unresolved)
            a.unresolved += 1
        if (c.seenAt > a.lastActivity)
            a.lastActivity = c.seenAt
        if (c.app.name)
            a.name = c.app.name
        if (c.app.icon)
            a.icon = c.app.icon
    }
    // Preserve spark history for apps that dropped out this tick? No — gone apps leave.
    //
    // …but remember what they were called. A blocked app leaves precisely
    // because the block worked, and it still needs a row (injectBlockedRows).
    if (state.appMeta) {
        for (var id in apps) {
            var m = apps[id]
            dictSet(state.appMeta, id, {
                name: m.name,
                icon: m.icon,
                desktop: m.desktop,
                system: m.system
            })
        }
    }
    return { apps: apps, ordered: orderRows(apps) }
}

// Give every blocked app a row, whether or not it still has a connection.
//
// Rows are built from the live connection list, so a successful block deleted
// its own row: connections drop, the app stops appearing, and its toggle — the
// only unblock affordance in the UI — disappears with it. The nftables rule
// stays up. That made blocking a one-way door, and the more completely a block
// worked, the faster the way back vanished.
//
// A dormant row is the same row with zero flows. It keeps the toggle reachable
// and states plainly that the block is the reason the app is quiet.
function injectBlockedRows(state, apps) {
    if (!state.blocked)
        return apps
    var meta = state.appMeta || dict()
    for (var aid in state.blocked) {
        if (!dictHas(state.blocked, aid))
            continue
        if (dictHas(apps, aid))
            continue
        var m = dictGet(meta, aid) || {}
        var known = dictGet(state.blocked, aid)
        dictSet(apps, aid, {
            id: aid,
            name: m.name || aid,
            icon: m.icon || "",
            desktop: m.desktop || "",
            system: m.system === true,
            pids: [],
            connections: [],
            unresolved: 0,
            // Never "now". A dormant row has had no activity by definition, and
            // stamping it with the clock would rank it as the busiest app on the
            // machine on every single rebuild.
            lastActivity: 0,
            spark: [],
            blocked: true,
            mechanism: (known && known.mechanism) || "",
            dormant: true,
            activityRank: 0
        })
    }
    return apps
}

function injectTemporaryRows(state, apps) {
    var known = sessionIdsByHelperId(state), rules = state.temporaryRules || []
    for (var i = 0; i < rules.length; i++) {
        var aid = String(rules[i].app || "")
        if (!aid) continue
        var sid = dictGet(known, helperId(aid)) || aid
        var row = dictGet(apps, sid)
        if (!row) {
            var meta = dictGet(state.appMeta, sid) || {}
            row = { id:sid, name:meta.name || sid, icon:meta.icon || "", desktop:meta.desktop || "",
                system:meta.system === true, pids:[], connections:[], unresolved:0, lastActivity:0,
                spark:[], blocked:false, mechanism:"", dormant:true, activityRank:0 }
            dictSet(apps, sid, row)
        }
        // A retained scoped rule supplies a cancellation surface, not a
        // whole-app block or invented live socket/process count.
        row.hasTemporaryRule = true
    }
    return apps
}

function setTemporaryRules(state, rules, now) {
    state.temporaryRules = (rules || []).slice()
    rebuild(state, now || Date.now())
}

function rebuildOrDefer(state, now, defer) {
    if (defer) {
        state.needsRebuild = true
        return
    }
    rebuild(state, now)
}

// Bring derived state (apps, ordered, counts) up to date after deferred
// events. Modifies `state` in place: it is for the state its owner already
// holds, not for applyLine's copy-on-write chain. Returns whether it rebuilt.
function settle(state, now) {
    if (!state || !state.needsRebuild)
        return false
    rebuild(state, now || Date.now())
    return true
}

function rebuild(state, now) {
    var ids = Object.keys(state.connections)
    var live = []
    var past = []
    for (var i = 0; i < ids.length; i++) {
        var c = state.connections[ids[i]]
        if (isLive(c))
            live.push(c)
        else
            past.push(c)
    }
    var l = groupApps(state, live, state.apps)
    var h = groupApps(state, past, null)
    // Live only. History is finished conversations, and a block that is still
    // in force is not a finished conversation — a dormant row there would be
    // claiming the app once talked to somewhere it never did.
    //
    // state.count below is unaffected on purpose: it counts live CONNECTIONS,
    // which is what the pill renders. A dormant row has none, so a blocked app
    // must never nudge that number.
    state.apps = injectTemporaryRows(state, injectBlockedRows(state, l.apps))
    state.ordered = orderRows(state.apps)
    state.historyApps = h.apps
    state.historyOrdered = h.ordered
    // state.count feeds Service.activeCount, which is what the bar pill renders.
    // It counts live only; a day of backfilled history must never inflate it.
    state.count = live.length
    state.historyCount = past.length
    state.needsRebuild = false
    state.revision += 1
    return state
}

function sampleSparklines(state) {
    var k
    for (k in state.apps) {
        var a = state.apps[k]
        // Copy the row before writing: it is shared with the previous state
        // (see cloneState), which must not change under its holder.
        var row = {}
        for (var f in a)
            row[f] = a[f]
        var spark = (a.spark || []).slice()
        spark.push(a.connections.length)
        if (spark.length > 24)
            spark.shift()
        row.spark = spark
        dictSet(state.apps, k, row)
    }
    // `ordered` is the list the panel renders, and it holds rows, not ids. Point
    // it at the sampled rows, or the sparklines on screen only move when some
    // connect or disconnect happens to rebuild it.
    var ordered = state.ordered || []
    var fresh = []
    for (var i = 0; i < ordered.length; i++)
        fresh.push(dictGet(state.apps, ordered[i].id) || ordered[i])
    state.ordered = fresh
}

function digestLine(n) {
    if (!n)
        return ""
    if (n === 1)
        return "1 new network while you were away"
    return n + " new networks while you were away"
}

function markLooked(state) {
    state.awayKeys = []
    state.digestText = ""
    state.pulse = false
    state.revision += 1
    return state
}

function clearPulse(state) {
    state.pulse = false
    state.pulseNetwork = ""
    state.revision += 1
    return state
}

function resetNetworkObservations(state, now) {
    if (!state)
        state = emptyState()
    var _n = now
    state.connections = dict()
    state.apps = dict()
    state.ordered = []
    state.count = 0
    state.historyApps = dict()
    state.historyOrdered = []
    state.historyCount = 0
    state.sourceCount = 0
    state.pulse = false
    state.pulseNetwork = ""
    state.digestText = ""
    state.awayKeys = []
    state.hello = false
    // blocked is session-known helper result, not a live observation.
    state.revision += 1
    return state
}

function setBlocked(state, appId, mechanism) {
    if (!state.blocked)
        state.blocked = dict()
    // The badge has to land on both tabs. An app can hold a live socket and
    // also own finished rows, and blocking it is a statement about the app, not
    // about one of its connections.
    var rows = [dictGet(state.apps, appId), dictGet(state.historyApps, appId)]
    for (var i = 0; i < rows.length; i++) {
        if (!rows[i])
            continue
        rows[i].blocked = !!mechanism
        rows[i].mechanism = mechanism || ""
    }
    if (mechanism)
        dictSet(state.blocked, appId, { mechanism: mechanism })
    else
        dictDel(state.blocked, appId)
    // Reflect the change in the row list NOW rather than waiting on the next
    // daemon sample. Blocking is a click the user just made on a privileged
    // action; a row that takes half a second to acknowledge it reads as a
    // failure, and half a second is long enough to click again.
    if (state.apps) {
        if (!mechanism && dictHas(state.apps, appId) && dictGet(state.apps, appId).dormant)
            dictDel(state.apps, appId)
        else if (mechanism)
            injectBlockedRows(state, state.apps)
        state.ordered = orderRows(state.apps)
    }
    state.revision += 1
    return state
}

// Reconcile the endpoint-block half of `state.blocked` against the helper.
//
// `owners` is the map the privileged helper keeps on disk and reports from its
// `status` verb: { appId: [ip, …] } out of /var/lib/kub0/endpoint-owners.json.
// It is the ONLY record of an endpoint block that outlives this process — the
// nftables rules are real and still in force after a shell restart, while
// `state.blocked` is rebuilt empty. Without this the UI came back up believing
// nothing was blocked while the kernel disagreed, and offered no way to find
// out, let alone undo it.
//
// Endpoint blocks only. A cgroup block leaves no entry here (it migrates PIDs
// instead of owning IPs), so a cgroup entry in state.blocked must survive this
// reconcile untouched — clearing it would drop a live block off the UI, which
// is the same bug in the other direction.
// The id the privileged helper stores an app under: helper/src/ids.rs
// sanitize_app, mirrored exactly. The daemon names an app after its .desktop
// file and keeps the case (com.discordapp.Discord); the helper lowercases and
// flattens it (com.discordapp.discord). Compared raw, the two never matched:
// every panel open replaced the real blocked entry with a lowercase ghost row,
// and only the ghost could unblock.
function helperId(id) {
    var out = ""
    var s = String(id || "")
    for (var i = 0; i < s.length; i++) {
        var c = s.charAt(i)
        out += /[A-Za-z0-9._-]/.test(c) ? c.toLowerCase() : "-"
    }
    return out.replace(/^-+|-+$/g, "")
}

// Map helper ids back to the ids this session actually uses for those apps.
function sessionIdsByHelperId(state) {
    var out = dict()
    var maps = [state.appMeta, state.apps, state.historyApps, state.blocked]
    for (var m = 0; m < maps.length; m++) {
        for (var k in (maps[m] || {})) {
            if (!dictHas(out, helperId(k)))
                dictSet(out, helperId(k), k)
        }
    }
    return out
}

// Reconcile `state.blocked` against what the helper says is in force.
//
// `owners` is the helper's on-disk map of endpoint blocks, { appId: [ip, …] }.
// `cgroupApps` is the list of apps with a live cgroup drop rule, from the
// helper's `status` (cgroupBlocks), or undefined when that is unknown (an
// older helper, or a table that could not be read), in which case cgroup
// entries are left exactly as they are.
//
// Both kinds of block live in nftables and outlive this process, while
// `state.blocked` is rebuilt empty on every launch. Without this the UI came
// back up believing nothing was blocked while the kernel disagreed, and
// offered no way to find out, let alone undo it. Each kind is reconciled only
// against its own source: an endpoint entry must survive a cgroup listing
// that does not mention it, and the other way round.
function rehydrateBlocked(state, owners, cgroupApps) {
    if (!state)
        return state
    if (!state.blocked)
        state.blocked = dict()
    var known = sessionIdsByHelperId(state)
    var changed = false
    // cgroup first: if an app's cgroup rule has gone but it still owns
    // addresses, the endpoint pass then puts it back as an endpoint block
    // rather than leaving it looking unblocked until the next check.
    var sources = []
    if (cgroupApps && typeof cgroupApps.length === "number")
        sources.push({ mechanism: "cgroup", ids: cgroupApps })
    sources.push({ mechanism: "endpoints", ids: Object.keys(owners || {}) })
    for (var s = 0; s < sources.length; s++) {
        var mech = sources[s].mechanism
        var live = dict()
        for (var i = 0; i < sources[s].ids.length; i++) {
            var aid = String(sources[s].ids[i])
            var hid = helperId(aid)
            dictSet(live, hid, true)
            // An app this session has not seen yet has no better name to use.
            var sid = dictGet(known, hid) || aid
            var preferred = dictGet(state.blocked, sid)
            var cur = preferred
            // A status can arrive before the daemon names the app. Move its
            // helper-id row to the session id once that name appears; keeping
            // both would render two blocked apps for one kernel rule.
            for (var alias in state.blocked) {
                if (alias === sid || helperId(alias) !== hid)
                    continue
                var old = dictGet(state.blocked, alias)
                if (old && (!cur || (old.mechanism === "cgroup" && cur.mechanism !== "cgroup")))
                    cur = old
                dictDel(state.blocked, alias)
                changed = true
            }
            if (cur && cur !== preferred) {
                dictSet(state.blocked, sid, cur)
                changed = true
            }
            // A cgroup block is the stronger claim; never demote one to an
            // endpoint entry because the same app also owns addresses.
            if (!cur || (cur.mechanism !== mech && mech === "cgroup")) {
                dictSet(state.blocked, sid, { mechanism: mech })
                changed = true
            }
        }
        for (var have in state.blocked) {
            if (!dictHas(state.blocked, have))
                continue
            var entry = dictGet(state.blocked, have)
            if (!entry || entry.mechanism !== mech)
                continue
            if (!dictHas(live, helperId(have))) {
                dictDel(state.blocked, have)
                changed = true
            }
        }
    }
    return changed
}

// The block confirmation's line naming what the block moves, by executable.
// Rows group by app id, and a process can reach another app's id through its
// exe name, its comm or a .desktop file, so more than one executable under
// one name is the thing to see before confirming. Empty when none is known.
function blockProgramsLine(app) {
    var exes = (app && app.exes) ? app.exes.slice().sort() : []
    if (exes.length === 0)
        return ""
    var shown = exes.slice(0, 4)
    var more = exes.length - shown.length
    var head = exes.length === 1
        ? "Program: "
        : exes.length + " different programs are under this name: "
    return head + shown.join(", ") + (more > 0 ? ", and " + more + " more" : "")
}

function isBlockable(app) {
    if (!app)
        return false
    if (app.system === true)
        return false
    var id = String(app.id || "").toLowerCase()
    if (id === "system" || id === "unknown" || id === "")
        return false
    return true
}

function anyBlocked(state) {
    if (!state || !state.blocked)
        return false
    for (var k in state.blocked) {
        if (dictHas(state.blocked, k))
            return true
    }
    return false
}

function filterApps(ordered, query, filterKey) {
    var list = ordered || []
    var key = filterKey || "all"
    var q = query ? String(query).toLowerCase() : ""
    if (!q && key === "all")
        return list
    var out = []
    for (var i = 0; i < list.length; i++) {
        var a = list[i]
        if (key === "live") {
            if (liveConnectionCount(a) < 1)
                continue
        } else if (key === "blocked") {
            if (a.blocked !== true)
                continue
        } else if (key === "unknown") {
            if (!isUnknownApp(a))
                continue
        }
        if (q) {
            var blob = (a.name + " " + a.id + " " + countryBlob(a)).toLowerCase()
            if (blob.indexOf(q) === -1)
                continue
        }
        out.push(a)
    }
    return out
}

function countryBlob(app) {
    var s = ""
    var cs = app.connections || []
    for (var i = 0; i < cs.length; i++) {
        if (cs[i].country)
            s += " " + cs[i].country
        if (cs[i].remote && cs[i].remote.ip)
            s += " " + cs[i].remote.ip
    }
    return s
}

// Arcs are a "right now" surface: an arc says this machine is talking to that
// place. Drawing a backfilled day of finished conversations would be the same
// lie the pill was telling, moved to a bigger widget — so history is excluded
// unless a caller asks for it explicitly.
function drawableArcs(connections, origin, cap, includeHistory) {
    cap = cap || 40
    var list = []
    var ids = Object.keys(connections || {})
    for (var i = 0; i < ids.length; i++) {
        var c = connections[ids[i]]
        if (!c || c.unresolved)
            continue
        if (!includeHistory && !isLive(c))
            continue
        if (!c.country)
            continue
        if (c.lat === 0 && c.lon === 0)
            continue
        list.push(c)
    }
    list.sort(function (a, b) { return (b.seenAt || 0) - (a.seenAt || 0) })
    if (list.length > cap)
        list = list.slice(0, cap)
    return list
}

function networkKey(ip) {
    if (!ip)
        return ""
    if (ip.indexOf(":") === -1) {
        var p = ip.split(".")
        if (p.length !== 4)
            return ip
        return p[0] + "." + p[1] + "." + p[2] + ".0/24"
    }
    // Mapped v4
    var mapped = ip.toLowerCase()
    var idx = mapped.lastIndexOf(":")
    if (mapped.indexOf(".") !== -1 && mapped.indexOf(":ffff:") !== -1) {
        var v4 = mapped.split(":").pop()
        return networkKey(v4)
    }
    var parts = expandV6(ip)
    if (!parts)
        return ip + "/48"
    return parts[0] + ":" + parts[1] + ":" + parts[2] + "::/48"
}

function expandV6(ip) {
    var s = String(ip).split("%")[0]
    if (s.charAt(0) === "[" )
        s = s.substring(1, s.length - 1)
    var halves = s.split("::")
    var head = halves[0] ? halves[0].split(":") : []
    var tail = halves.length > 1 && halves[1] ? halves[1].split(":") : []
    var miss = 8 - (head.length + tail.length)
    if (miss < 0)
        return null
    var full = []
    var i
    for (i = 0; i < head.length; i++)
        full.push(head[i] || "0")
    for (i = 0; i < miss; i++)
        full.push("0")
    for (i = 0; i < tail.length; i++)
        full.push(tail[i] || "0")
    if (full.length !== 8)
        return null
    return full
}

function pidsOf(app) {
    return (app && app.pids) ? app.pids : []
}

// The pids of an app that run as `uid`. The system daemon lists the whole
// host, and gives one binary the same app id under every account that runs
// it, so `app.pids` can hold another account's processes; the helper refuses
// a block that names one. A row says whose it is (`uid`, else `app.owner`).
function pidsOwnedBy(state, appId, uid) {
    var out = []
    if (!state || !state.connections)
        return out
    for (var id in state.connections) {
        var c = state.connections[id]
        if (!c || !c.app || c.app.id !== appId || !c.app.pid)
            continue
        var owner = typeof c.uid === "number" ? c.uid : (c.app.owner ? c.app.owner.uid : null)
        if (owner === uid && out.indexOf(c.app.pid) === -1)
            out.push(c.app.pid)
    }
    return out
}

// Addresses an endpoint block must never take. The block is host-wide, so
// this is about what the whole machine can afford to lose, not about the app:
// with systemd-resolved every app resolves names through 127.0.0.53, and an
// app's connected UDP to it is exactly what the daemon reports. The helper
// refuses these too (helper/src/endpoints.rs), and also the nameservers it
// reads from resolv.conf; this side adds what only it can see, the port.
var DNS_PORTS = { 53: true, 853: true }

function unmappedIp(ip) {
    var a = String(ip || "").toLowerCase()
    var mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    return mapped ? mapped[1] : a
}

function hostWideUnsafe(ip, port) {
    if (DNS_PORTS[port])
        return true
    var a = String(ip || "").toLowerCase()
    if (!a)
        return true
    var mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)
    if (mapped)
        a = mapped[1]
    if (a.indexOf(":") === -1) {
        var o = a.split(".").map(Number)
        // 100.64.0.0/10 mirrors the helper's refusal: tailnet peers and the
        // path to their coordination server.
        return o[0] === 0 || o[0] === 127 || (o[0] === 169 && o[1] === 254)
            || (o[0] >= 224 && o[0] <= 239) || a === "255.255.255.255"
            || (o[0] === 100 && (o[1] & 0xc0) === 64)
    }
    return a === "::" || a === "::1" || /^fe[89ab]/.test(a) || /^ff/.test(a)
        || /^fd7a:115c:a1e0:/.test(a)
}

// `critical` is the helper's own list of this machine's nameservers and
// default gateways (status `hostCritical`), refused by lookup rather than by
// range, so hostWideUnsafe cannot know them.
function remotesOf(app, critical) {
    var out = []
    if (!app)
        return out
    var skip = {}
    for (var k = 0; critical && k < critical.length; k++)
        skip[unmappedIp(critical[k])] = true
    var cs = app.connections || []
    for (var i = 0; i < cs.length; i++) {
        if (cs[i].unresolved)
            continue
        var ip = cs[i].remote && cs[i].remote.ip
        var port = cs[i].remote && cs[i].remote.port
        if (ip && !hostWideUnsafe(ip, port) && !skip[unmappedIp(ip)] && out.indexOf(ip) === -1)
            out.push(ip)
    }
    return out
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        emptyState: emptyState,
        applyLine: applyLine,
        settle: settle,
        hostWideUnsafe: hostWideUnsafe,
        helperId: helperId,
        applyEvent: applyEvent,
        networkKey: networkKey,
        digestLine: digestLine,
        filterApps: filterApps,
        drawableArcs: drawableArcs,
        markLooked: markLooked,
        setBlocked: setBlocked,
        isBlockable: isBlockable,
        blockProgramsLine: blockProgramsLine,
        anyBlocked: anyBlocked,
        remotesOf: remotesOf,
        isLive: isLive,
        rebuild: rebuild,
        resetNetworkObservations: resetNetworkObservations,
        pidsOf: pidsOf,
        pidsOwnedBy: pidsOwnedBy,
        orderRows: orderRows,
        injectBlockedRows: injectBlockedRows,
        setTemporaryRules: setTemporaryRules,
        rehydrateBlocked: rehydrateBlocked
    }
}
