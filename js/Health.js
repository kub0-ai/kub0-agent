// Monitoring freshness and block-dispatch gates.
// Receive time is local Date.now() at ingest. Event.ts is never used as freshness.

var STALE_MS = 3000

var KNOWN_TYPES = {
    hello: true,
    snapshot: true,
    connect: true,
    disconnect: true,
    bandwidth: true,
    tick: true,
    digest: true,
    status: true
}

function emptyHealth() {
    return {
        daemonAvailable: false,
        socketConnected: false,
        snapshotReady: false,
        lastFreshAt: 0,
        lastSnapshotAt: 0,
        lastType: "",
        demo: false,
        reason: "waiting for service"
    }
}

function copyHealth(health) {
    var h = emptyHealth()
    if (!health)
        return h
    h.daemonAvailable = health.daemonAvailable === true
    h.socketConnected = health.socketConnected === true
    h.snapshotReady = health.snapshotReady === true
    h.lastFreshAt = typeof health.lastFreshAt === "number" ? health.lastFreshAt : 0
    h.lastSnapshotAt = typeof health.lastSnapshotAt === "number" ? health.lastSnapshotAt : 0
    h.lastType = health.lastType ? String(health.lastType) : ""
    h.demo = health.demo === true
    h.reason = health.reason ? String(health.reason) : ""
    return h
}

function isArray(v) {
    return Object.prototype.toString.call(v) === "[object Array]"
}

function hasOwn(obj, key) {
    return !!(obj && Object.prototype.hasOwnProperty.call(obj, key))
}

function isPlainObject(v) {
    return v !== null && typeof v === "object" && !isArray(v)
}

function isFiniteNumber(v) {
    return typeof v === "number" && isFinite(v)
}

function isNonNegInt(v) {
    return isFiniteNumber(v) && v >= 0 && Math.floor(v) === v
}

function isU16(v) {
    return isNonNegInt(v) && v <= 65535
}

function isU32(v) {
    return isNonNegInt(v) && v <= 4294967295
}

function isU64(v) {
    return isNonNegInt(v) && v <= 9007199254740991
}

function isNonEmptyString(v) {
    return typeof v === "string" && v.length > 0
}

function isKnownType(t) {
    return typeof t === "string" && hasOwn(KNOWN_TYPES, t) && KNOWN_TYPES[t] === true
}

function validEndpoint(ep) {
    if (!isPlainObject(ep))
        return false
    if (typeof ep.ip !== "string")
        return false
    if (!isU16(ep.port))
        return false
    return true
}

function validApp(app) {
    if (!isPlainObject(app))
        return false
    if (typeof app.id !== "string")
        return false
    if (typeof app.name !== "string")
        return false
    if (typeof app.icon !== "string")
        return false
    if (typeof app.desktop !== "string")
        return false
    if (!isU32(app.pid))
        return false
    if (hasOwn(app, "system") && typeof app.system !== "boolean")
        return false
    return true
}

function validTs(ev) {
    return hasOwn(ev, "ts") && isU64(ev.ts)
}

function validConnection(row) {
    if (!isPlainObject(row))
        return false
    if (typeof row.id !== "string" || !row.id)
        return false
    if (typeof row.proto !== "string")
        return false
    if (!isU64(row.inode))
        return false
    if (!validApp(row.app))
        return false
    if (!validEndpoint(row.local))
        return false
    if (!validEndpoint(row.remote))
        return false
    if (typeof row.state !== "string")
        return false
    if (hasOwn(row, "country") && typeof row.country !== "string")
        return false
    if (hasOwn(row, "lat") && !isFiniteNumber(row.lat))
        return false
    if (hasOwn(row, "lon") && !isFiniteNumber(row.lon))
        return false
    if (hasOwn(row, "unresolved") && typeof row.unresolved !== "boolean")
        return false
    if (hasOwn(row, "newNetwork") && typeof row.newNetwork !== "boolean")
        return false
    if (hasOwn(row, "networkKey") && typeof row.networkKey !== "string")
        return false
    if (hasOwn(row, "hostname") && typeof row.hostname !== "string")
        return false
    return true
}

function validStringList(list) {
    if (!isArray(list))
        return false
    var i
    for (i = 0; i < list.length; i++) {
        if (typeof list[i] !== "string")
            return false
    }
    return true
}

function validEnvelope(ev, t) {
    if (!isPlainObject(ev) || !isKnownType(t))
        return false
    if (t === "hello") {
        return typeof ev.version === "string"
            && isU32(ev.pid)
            && typeof ev.coverage === "string"
            && typeof ev.rdns === "boolean"
    }
    if (t === "snapshot") {
        if (!validTs(ev) || !isArray(ev.connections))
            return false
        var i
        for (i = 0; i < ev.connections.length; i++) {
            if (!validConnection(ev.connections[i]))
                return false
        }
        return true
    }
    if (t === "connect")
        return validTs(ev) && validConnection(ev)
    if (t === "disconnect")
        return validTs(ev) && isNonEmptyString(ev.id)
    if (t === "tick")
        return validTs(ev) && isU64(ev.count)
    if (t === "bandwidth") {
        if (!validTs(ev) || !isArray(ev.apps)) return false
        for (var bi = 0; bi < ev.apps.length; bi++) {
            var b = ev.apps[bi]
            if (!isPlainObject(b) || !isNonEmptyString(b.id) || !isU64(b.txBytes) || !isU64(b.rxBytes)
                || !isU64(b.measured) || !isU64(b.tcp) || b.measured > b.tcp
                || !(b.txRate === null || (isFiniteNumber(b.txRate) && b.txRate >= 0))
                || !(b.rxRate === null || (isFiniteNumber(b.rxRate) && b.rxRate >= 0))) return false
        }
        return true
    }
    if (t === "digest") {
        if (!validTs(ev) || !isU64(ev.newNetworks) || !validStringList(ev.keys))
            return false
        return true
    }
    if (t === "status")
        return typeof ev.message === "string"
    return false
}

function classifyLine(line) {
    if (line === undefined || line === null)
        return { ok: false, malformed: false, parseError: false, unknown: false, type: "" }
    var trimmed = String(line).replace(/^\s+|\s+$/g, "")
    if (!trimmed || trimmed.charAt(0) === "#")
        return { ok: false, malformed: false, parseError: false, unknown: false, type: "" }
    var ev
    try {
        ev = JSON.parse(trimmed)
    } catch (e) {
        return { ok: false, malformed: true, parseError: true, unknown: false, type: "" }
    }
    if (!isPlainObject(ev) || !hasOwn(ev, "type") || typeof ev.type !== "string" || !ev.type)
        return { ok: false, malformed: true, parseError: false, unknown: false, type: "" }
    var t = ev.type
    if (!isKnownType(t))
        return { ok: false, malformed: false, parseError: false, unknown: true, type: t }
    if (!validEnvelope(ev, t))
        return { ok: false, malformed: true, parseError: false, unknown: false, type: t }
    return { ok: true, malformed: false, parseError: false, unknown: false, type: t }
}

function ingestDecision(health, line) {
    var kind = classifyLine(line)
    if (kind.parseError)
        return { kind: kind, applyModel: true, noteFresh: false }
    if (!kind.ok)
        return { kind: kind, applyModel: false, noteFresh: false }
    var apply = true
    // Live reconnects wait for a snapshot. The explicit demo fixture is a
    // connect-stream with no snapshot, so demo is allowed to apply rows.
    if ((kind.type === "connect" || kind.type === "disconnect") && !(health && (health.snapshotReady || health.demo)))
        apply = false
    if (kind.type === "bandwidth" && !(health && health.snapshotReady)) apply = false
    return { kind: kind, applyModel: apply, noteFresh: kind.type !== "bandwidth" }
}

function noteProtocol(health, kind, now) {
    var h = copyHealth(health)
    if (!kind || !kind.ok)
        return h
    h.lastFreshAt = now
    h.lastType = kind.type
    if (kind.type === "snapshot") {
        h.snapshotReady = true
        h.lastSnapshotAt = now
    }
    return h
}

function applyIngest(health, model, line, now, applyLineFn) {
    var d = ingestDecision(health, line)
    var next = model
    if (d.applyModel && applyLineFn) {
        try {
            var applied = applyLineFn(model, line, now)
            if (applied)
                next = applied
        } catch (e) {
            d = { kind: d.kind, applyModel: false, noteFresh: false, error: String(e && e.message ? e.message : e) }
            return { health: health, model: model, decision: d }
        }
    }
    if (d.noteFresh)
        health = noteProtocol(health, d.kind, now)
    return { health: health, model: next, decision: d }
}

function markDaemonAvailable(health, available, reason) {
    var h = copyHealth(health)
    h.daemonAvailable = available === true
    if (!h.daemonAvailable && !h.demo) {
        h.socketConnected = false
        h.snapshotReady = false
        h.reason = reason || "kub0d is not available"
    }
    return h
}

function markSocketUp(health, now) {
    var h = copyHealth(health)
    var _n = now
    h.socketConnected = true
    h.snapshotReady = false
    h.reason = "waiting for an authoritative snapshot"
    return h
}

function markSocketDown(health, reason) {
    var h = copyHealth(health)
    h.socketConnected = false
    h.snapshotReady = false
    h.reason = reason || "not connected to kub0d"
    return h
}

function enterDemo(health, now) {
    var h = copyHealth(health)
    var _n = now
    h.demo = true
    h.snapshotReady = false
    h.lastFreshAt = 0
    h.lastSnapshotAt = 0
    h.lastType = ""
    h.reason = "explicit demo replay — not this machine"
    return h
}

function exitDemo(health) {
    var h = copyHealth(health)
    h.demo = false
    h.snapshotReady = false
    h.socketConnected = false
    h.lastFreshAt = 0
    h.lastSnapshotAt = 0
    h.lastType = ""
    h.reason = "leaving demo"
    return h
}

function derive(health, now, extras) {
    extras = extras || {}
    var h = copyHealth(health)
    now = typeof now === "number" ? now : 0
    var monitoring
    var reason
    if (h.demo) {
        monitoring = "demo"
        reason = "explicit demo replay — not this machine"
    } else if (!h.daemonAvailable && !h.socketConnected) {
        monitoring = "unavailable"
        reason = h.reason || "kub0d is not available"
    } else if (!h.socketConnected) {
        monitoring = "connecting"
        reason = h.reason || "connecting to kub0d"
    } else if (!h.snapshotReady) {
        monitoring = "awaiting_snapshot"
        reason = "waiting for an authoritative snapshot"
    } else if (!h.lastFreshAt || (now - h.lastFreshAt) > STALE_MS) {
        monitoring = "stale"
        reason = "no recognized updates for " + formatAge(now - h.lastFreshAt)
    } else {
        monitoring = "current"
        reason = ""
    }
    var count = typeof extras.count === "number" ? extras.count : 0
    var idle = monitoring === "current" && count === 0
    var view = {
        monitoring: monitoring,
        snapshotReady: h.snapshotReady === true,
        lastFreshAt: h.lastFreshAt,
        lastSnapshotAt: h.lastSnapshotAt,
        ageMs: h.lastFreshAt ? Math.max(0, now - h.lastFreshAt) : 0,
        observationAgeMs: h.lastSnapshotAt ? Math.max(0, now - h.lastSnapshotAt) : 0,
        idle: idle,
        reason: reason,
        receiving: monitoring === "current",
        demo: h.demo === true
    }
    view.label = barLabel(view)
    return view
}

var BAR_STATE_LABELS = ["Off", "…", "Wait", "Idle", "On", "Stale", "Demo", "Paused"]

function barStateLabels() {
    return BAR_STATE_LABELS
}

function barLabel(view) {
    if (!view)
        return "Off"
    if (view.monitoring === "unavailable")
        return "Off"
    if (view.monitoring === "connecting")
        return "…"
    if (view.monitoring === "awaiting_snapshot")
        return "Wait"
    if (view.monitoring === "current")
        return view.idle ? "Idle" : "On"
    if (view.monitoring === "stale")
        return "Stale"
    if (view.monitoring === "demo")
        return "Demo"
    return "Off"
}

// barLabel reads monitoring only. A live pause rule sits at the head of
// vallum's chain and every block below it is skipped, so "On" or "Idle" over
// it would tell the bar the rampart holds when it does not. Degraded
// monitoring states already avoid the wall glyph and are left as they are.
function barPostureLabel(label, paused) {
    if (paused === true && (label === "On" || label === "Idle"))
        return "Paused"
    return label
}

function retainSelectedId(selectedId, visibleIds) {
    if (!selectedId) {
        if (visibleIds && visibleIds.length)
            return visibleIds[0]
        return ""
    }
    return selectedId
}

function acceptSearchSelection(selectedId, visibleIds) {
    if (visibleIds && visibleIds.length) {
        if (selectedId && idInList(selectedId, visibleIds))
            return selectedId
        return visibleIds[0]
    }
    return selectedId || ""
}

function formatAge(ms) {
    if (typeof ms !== "number" || ms < 0 || !isFinite(ms))
        return "unknown age"
    if (ms < 1000)
        return "just now"
    var s = Math.round(ms / 1000)
    if (s < 60)
        return s + "s ago"
    var m = Math.round(s / 60)
    if (m < 60)
        return m + "m ago"
    var hr = Math.round(m / 60)
    return hr + "h ago"
}

function barTooltip(view, info) {
    info = info || {}
    view = view || derive(emptyHealth(), 0, {})
    var parts = []
    parts.push("kub0")
    if (view.monitoring === "demo")
        parts.push("DEMO — replay fixture, not this machine")
    if (view.monitoring === "current") {
        if (view.idle)
            parts.push("Receiving updates; idle (no current connections)")
        else
            parts.push("Receiving updates; " + String(info.count || 0) + " current connections, "
                + String(info.appCount || 0) + " apps")
    } else if (view.monitoring === "stale") {
        parts.push("Last-known observations, " + formatAge(view.observationAgeMs || view.ageMs) + " — not live")
        if (typeof info.count === "number")
            parts.push("Last-known connection rows: " + String(info.count))
    } else if (view.monitoring === "awaiting_snapshot") {
        parts.push("Socket is up; waiting for an authoritative snapshot")
        if (view.lastSnapshotAt && typeof info.count === "number")
            parts.push("Last-known rows still shown, " + formatAge(view.observationAgeMs))
    } else if (view.monitoring === "connecting") {
        parts.push(view.reason || "Connecting to kub0d")
        if (view.lastSnapshotAt)
            parts.push("Last-known data, " + formatAge(view.observationAgeMs) + " — not live")
    } else if (view.monitoring === "unavailable") {
        parts.push(view.reason || "kub0d is not available")
        if (view.lastSnapshotAt)
            parts.push("Last-known data, " + formatAge(view.observationAgeMs) + " — not live")
    }
    var coverage = info.coverage || "TCP + connected UDP"
    parts.push("Sampler coverage: " + coverage + ". A heartbeat is not full capture or automatic protection")
    if (info.blockingReady)
        parts.push("Manual block helper available (capability, not continuous protection)")
    else
        parts.push("Manual blocking unavailable" + (info.blockHint ? " — " + String(info.blockHint) : ""))
    if (info.anyBlocked)
        parts.push("Session-known block(s) remembered; not a kernel inventory")
    if (view.reason && view.monitoring !== "connecting" && view.monitoring !== "unavailable" && view.monitoring !== "demo")
        parts.push(view.reason)
    return parts.join(". ")
}

function idInList(id, list) {
    if (!id || !list)
        return false
    var i
    for (i = 0; i < list.length; i++) {
        if (list[i] === id)
            return true
    }
    return false
}

function blockShortcutAllowed(view, selectedId, visibleAppIds, sessionKnownIds) {
    if (!selectedId)
        return false
    if (view === "apps")
        return idInList(selectedId, visibleAppIds)
    if (view === "protection")
        return idInList(selectedId, sessionKnownIds)
    return false
}

function canDispatchNewBlock(health, now) {
    var view = derive(health, now, {})
    if (view.demo)
        return false
    return view.monitoring === "current" && health && health.snapshotReady === true
}

function canDispatchUnblock(blockedMap, appId, blockingReady) {
    if (!blockingReady)
        return false
    if (!appId || !blockedMap)
        return false
    return hasOwn(blockedMap, appId) && !!blockedMap[appId]
}

function sessionKnownIds(blockedMap) {
    var out = []
    if (!blockedMap)
        return out
    for (var k in blockedMap) {
        if (!hasOwn(blockedMap, k))
            continue
        if (blockedMap[k])
            out.push(k)
    }
    out.sort()
    return out
}

function overviewSummaryAllowed(view) {
    return !!(view && view.monitoring === "current")
}

function activityEmptyText(historyCount, searchQuery) {
    if (searchQuery)
        return "Nothing in recorded source history matches."
    if (historyCount > 0)
        return ""
    return "No closed-connection history. The default procfs sampler reports sockets that exist now and deletes a conversation when it ends, so there is no durable incident timeline."
}

function statusPayload(view, extras) {
    extras = extras || {}
    view = view || derive(emptyHealth(), 0, {})
    return {
        count: typeof extras.count === "number" ? extras.count : 0,
        history: typeof extras.history === "number" ? extras.history : 0,
        daemon: extras.daemon || "",
        blocking: extras.blocking === true,
        coverage: extras.coverage || "",
        fallback: extras.fallback === true,
        helper: extras.helper === true,
        polkit: extras.polkit === true,
        needsHelper: extras.needsHelper === true,
        panelVersion: typeof extras.panelVersion === "string" ? extras.panelVersion : "",
        daemonVersion: typeof extras.daemonVersion === "string" ? extras.daemonVersion : "",
        setup: typeof extras.setup === "string" ? extras.setup : "",
        bindOfferNeeded: extras.bindOfferNeeded === true,
        bindOfferNote: extras.bindOfferNote || "",
        monitoring: view.monitoring,
        snapshotReady: view.snapshotReady === true,
        lastFreshAt: view.lastFreshAt || 0,
        stale: view.monitoring === "stale",
        monitoringLabel: view.label,
        blockingReady: extras.blocking === true,
        anyBlocked: extras.anyBlocked === true,
        sessionKnownBlocks: extras.sessionKnownBlocks || [],
        freshnessMs: view.ageMs || 0,
        observationAgeMs: view.observationAgeMs || 0
    }
}

function helperOwnerCount(owners) {
    if (!owners || typeof owners !== "object")
        return 0
    var n = 0
    var k
    for (k in owners) {
        if (hasOwn(owners, k))
            n++
    }
    return n
}

// Every app with a helper block record, from BOTH arms.
//
// `owners` is the persisted ENDPOINT-block map only. A cgroup block migrates
// PIDs into vallum.slice/vallum-<app> and writes no owners entry at all, so
// counting owners alone returns 0 while an app is genuinely blocked -- and the
// hero would then read "Active" (nothing blocked) mid-enforcement, which is the
// precise inversion this posture line exists to prevent. Verified live: with an
// app blocked, status.owners == {} while status.raw carries the rule.
//
// The cgroup arm is visible only in the ruleset, as
//   socket cgroupv2 level N "vallum.slice/vallum-<app>" drop
function blockedAppCount(status) {
    status = status || {}
    var seen = {}
    var n = 0
    var k
    var owners = status.owners
    if (owners && typeof owners === "object") {
        for (k in owners) {
            if (hasOwn(owners, k) && !hasOwn(seen, k)) {
                seen[k] = true
                n++
            }
        }
    }
    var cgroupBlocks = status.cgroupBlocks
    if (isArray(cgroupBlocks)) {
        for (var i = 0; i < cgroupBlocks.length; i++) {
            k = String(cgroupBlocks[i])
            if (!hasOwn(seen, k)) {
                seen[k] = true
                n++
            }
        }
    }
    var raw = typeof status.raw === "string" ? status.raw : ""
    var re = /vallum\.slice\/vallum-([A-Za-z0-9._:-]+)/g
    var m = re.exec(raw)
    while (m !== null) {
        if (!hasOwn(seen, m[1])) {
            seen[m[1]] = true
            n++
        }
        m = re.exec(raw)
    }
    return n
}

// PanelHero meta line. `blockingReady` here is the helper's own
// `status.blockingReady`, never the UI composite of polkit/helper/daemon/tools.
function heroPosture(info) {
    info = info || {}
    var helperInstalled = info.helperInstalled === true
    var statusFailed = info.helperStatusFailed === true
    var blockingReady = info.blockingReady === true
    var blockCount = typeof info.blockCount === "number" ? info.blockCount : 0
    if (!helperInstalled || statusFailed)
        return "Not installed"
    if (!blockingReady)
        return "Inactive"
    // Paused wins over the block count: the rules are in the kernel, but the
    // pause rule sits ahead of every one of them, so nothing is protected.
    if (info.paused === true)
        return "Paused"
    // The ordinary status path may only have root-written records: the shell
    // cannot read nftables itself, and old UDP sockets may escape an app rule.
    // A persisted marker can survive a same-boot out-of-band nft flush, so a
    // count proves a record, not a currently enforced kernel rule.
    if (blockCount > 0)
        return "Blocks recorded"
    return "Active"
}

function wordingForbidden(text) {
    var s = String(text || "").toLowerCase()
    var bad = [
        "protection active",
        "threat",
        "detected threat",
        "items to review",
        "credential protection",
        "file-access policy",
        "ebpf enforcement",
        "prevented"
    ]
    var i
    for (i = 0; i < bad.length; i++) {
        if (s.indexOf(bad[i]) !== -1)
            return bad[i]
    }
    return ""
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        STALE_MS: STALE_MS,
        BAR_STATE_LABELS: BAR_STATE_LABELS,
        barStateLabels: barStateLabels,
        emptyHealth: emptyHealth,
        copyHealth: copyHealth,
        classifyLine: classifyLine,
        ingestDecision: ingestDecision,
        noteProtocol: noteProtocol,
        applyIngest: applyIngest,
        isKnownType: isKnownType,
        validEnvelope: validEnvelope,
        validConnection: validConnection,
        validApp: validApp,
        validEndpoint: validEndpoint,
        blockShortcutAllowed: blockShortcutAllowed,
        retainSelectedId: retainSelectedId,
        acceptSearchSelection: acceptSearchSelection,
        markDaemonAvailable: markDaemonAvailable,
        markSocketUp: markSocketUp,
        markSocketDown: markSocketDown,
        enterDemo: enterDemo,
        exitDemo: exitDemo,
        derive: derive,
        barLabel: barLabel,
        barPostureLabel: barPostureLabel,
        barTooltip: barTooltip,
        formatAge: formatAge,
        canDispatchNewBlock: canDispatchNewBlock,
        canDispatchUnblock: canDispatchUnblock,
        sessionKnownIds: sessionKnownIds,
        overviewSummaryAllowed: overviewSummaryAllowed,
        activityEmptyText: activityEmptyText,
        wordingForbidden: wordingForbidden,
        statusPayload: statusPayload,
        helperOwnerCount: helperOwnerCount,
        blockedAppCount: blockedAppCount,
        heroPosture: heroPosture
    }
}
