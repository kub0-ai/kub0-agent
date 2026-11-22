// kub0 connect / fleet helpers. Pure JS so node tests can drive the state machine.

function isArray(v) {
    return Object.prototype.toString.call(v) === "[object Array]"
}

function isPlainObject(v) {
    return v !== null && typeof v === "object" && !isArray(v)
}

function emptyKub0() {
    return {
        connected: false,
        githubUsername: "",
        nodeName: "",
        lastHeartbeatOk: null,
        lastHeartbeatTs: 0,
        orgEndpoints: 0,
        nodeLimit: 0,
        selfState: "unknown",
        endpoints: [],
        endpointsUpdatedAt: 0,
        endpointsRefreshOk: null,
        denylist: [],
        denylistVersion: 0,
        netpolicies: [],
        netpolicyRefreshOk: null,
        netpolicyEnforcement: normalizeEnforcement(null),
        // networkKey -> {nodes, firstSeen}; see docs/INTEL.md "Where kub0 fits".
        prevalence: {},
        prevalenceSupported: null,
        sharingDestinations: false,
        // true: the deny-list stream is delivering; false: down, the 60 s poll
        // is the source; null: no stream (older daemon, or not connected).
        denylistLive: null,
        // The exec gate (daemon/src/execgate.rs). Independent of `connected`:
        // a local deny file can arm it with no account at all.
        execGate: normalizeExecGate(null)
    }
}

var EXEC_DECISIONS = ["blocked", "allowed_local_trust", "allowed_once", "allowed_failopen"]
var EXEC_SOURCES = ["live", "mirror", "stale", "none"]
var EXEC_COUNTERS = ["blocked", "allowedOnce", "trusted", "failopen", "hashed", "cacheHit",
    "allowlisted", "overCap", "error", "deadline", "overflow", "marks", "uncovered"]

function str(v, cap) {
    if (typeof v !== "string")
        return ""
    return cap && v.length > cap ? v.substring(0, cap) : v
}

// One recorded match. An allow-list like every other wire shape: a field the
// daemon adds is invisible until it is named here (tests/test_execgate_contract.js
// generates the fixture from the Rust struct and fails when one is dropped).
function normalizeExecDeny(d) {
    if (!isPlainObject(d) || typeof d.sha256 !== "string" || !d.sha256)
        return null
    return {
        ts: count(d.ts),
        pid: typeof d.pid === "number" && isFinite(d.pid) ? Math.floor(d.pid) : 0,
        ppid: typeof d.ppid === "number" && isFinite(d.ppid) ? Math.floor(d.ppid) : 0,
        comm: str(d.comm, 256),
        exe: str(d.exe, 4096),
        sha256: str(d.sha256, 64),
        reason: str(d.reason, 1024),
        promotedBy: str(d.promotedBy, 128),
        createdAt: str(d.createdAt, 64),
        decision: EXEC_DECISIONS.indexOf(d.decision) >= 0 ? d.decision : "blocked"
    }
}

function normalizeTrustedDigest(t) {
    if (!isPlainObject(t) || typeof t.sha256 !== "string" || !t.sha256)
        return null
    return {
        sha256: str(t.sha256, 64),
        comm: str(t.comm, 256),
        exe: str(t.exe, 4096),
        addedAt: count(t.addedAt),
        note: str(t.note, 256)
    }
}

function normalizeExecGate(g) {
    var o = isPlainObject(g) ? g : {}
    var counters = {}
    var c = isPlainObject(o.counters) ? o.counters : {}
    for (var i = 0; i < EXEC_COUNTERS.length; i++)
        counters[EXEC_COUNTERS[i]] = count(c[EXEC_COUNTERS[i]])
    return {
        enabled: o.enabled === true,
        armed: o.armed === true,
        keys: count(o.keys),
        source: EXEC_SOURCES.indexOf(o.source) >= 0 ? o.source : "none",
        observedAt: count(o.observedAt),
        counters: counters,
        denies: isArray(o.denies) ? o.denies.map(normalizeExecDeny).filter(function(d) { return d !== null }) : [],
        trusted: isArray(o.trusted) ? o.trusted.map(normalizeTrustedDigest).filter(function(t) { return t !== null }) : [],
        oncePending: count(o.oncePending),
        // When the kub0 API last returned the org list behind the keys (0: no
        // list held), and whether the daemon is still on the copy it saved
        // before it started. An older daemon sends neither.
        listReceivedAt: count(o.listReceivedAt),
        listRestored: o.listRestored === true
    }
}

function copyExecGate(g) {
    return normalizeExecGate(g)
}

function execDecisionText(decision) {
    if (decision === "blocked") return "blocked"
    if (decision === "allowed_local_trust") return "allowed (trusted on this machine)"
    if (decision === "allowed_once") return "allowed once"
    if (decision === "allowed_failopen") return "not blocked (fail-open)"
    return String(decision || "")
}

// The Settings heading: the gate's state in one line, so the section answers
// its question before the rows are read. Honest about where the state comes
// from: the panel talks to the user daemon, which mirrors the system one.
function execGateHeading(k) {
    var g = k && k.execGate ? k.execGate : normalizeExecGate(null)
    if (g.source === "none")
        return "Exec gate: not reported (system kub0d not running)"
    if (g.source === "stale")
        return "Exec gate: state is stale (system kub0d stopped reporting)"
    if (!g.enabled)
        return "Exec gate: off"
    if (!g.armed)
        return "Exec gate: loaded, idle until the first deny-list sync"
    // Armed from the list the daemon saved before it started: the keys are as
    // old as that list until a sync replaces it.
    if (g.listRestored)
        return "Exec gate: armed, " + plural(g.keys, "key", "keys") + " from the saved org list (no sync since the daemon started)"
    return "Exec gate: armed, " + plural(g.keys, "key", "keys")
}

function execGateFacts(k) {
    var g = k && k.execGate ? k.execGate : normalizeExecGate(null)
    var c = g.counters
    var rows = [
        { label: "State", value: !g.enabled ? "off" : (g.armed ? "armed" : "idle"), tone: g.enabled && g.armed ? "ok" : "" },
        { label: "Keys", value: String(g.keys), tone: "" },
        { label: "Blocked", value: String(c.blocked), tone: c.blocked > 0 ? "warn" : "" },
        { label: "Allowed once", value: String(c.allowedOnce), tone: "" },
        { label: "Trusted here", value: plural(g.trusted.length, "digest", "digests") + (c.trusted > 0 ? ", " + c.trusted + " allowed" : ""), tone: "" },
        { label: "Fail-open", value: String(c.failopen + c.deadline + c.overflow + c.error), tone: (c.failopen + c.deadline + c.overflow + c.error) > 0 ? "warn" : "" }
    ]
    if (g.oncePending > 0)
        rows.push({ label: "Pending allows", value: plural(g.oncePending, "one-shot allow", "one-shot allows"), tone: "" })
    if (g.listRestored)
        rows.push({ label: "Org list", value: "saved copy, no sync since the daemon started", tone: "warn" })
    return rows
}

// One line for a recent match in Settings: when, what, the decision, why.
function execDenyLine(d, fmt, now) {
    if (!d)
        return ""
    var parts = [clock(d.ts, fmt, now), d.comm || basename(d.exe) || d.sha256.substring(0, 12), execDecisionText(d.decision)]
    if (d.reason)
        parts.push(d.reason)
    return parts.join(" · ")
}

function trustedLine(t) {
    if (!t)
        return ""
    var name = t.comm || basename(t.exe) || ""
    var parts = [t.sha256.substring(0, 16) + "…"]
    if (name)
        parts.unshift(name)
    if (t.addedAt > 0)
        parts.push("trusted " + new Date(t.addedAt).toISOString().substring(0, 10))
    return parts.join(" · ")
}

function denylistLiveText(k) {
    if (!k || !k.connected)
        return ""
    if (k.denylistLive === true) return "Deny list: live stream connected, poll every 60 s as backup."
    if (k.denylistLive === false) return "Deny list: live stream down, polling every 60 s."
    return "Deny list: polled every 60 s."
}

function normalizePrevalence(list) {
    var out = {}
    if (!isArray(list))
        return out
    for (var i = 0; i < list.length; i++) {
        var p = list[i]
        if (!isPlainObject(p) || typeof p.networkKey !== "string" || !p.networkKey)
            continue
        if (typeof p.nodes !== "number" || !isFinite(p.nodes) || p.nodes < 0)
            continue
        out[p.networkKey] = { nodes: Math.floor(p.nodes), firstSeen: typeof p.firstSeen === "number" && isFinite(p.firstSeen) ? p.firstSeen : 0 }
    }
    return out
}

function copyPrevalence(src) {
    var out = {}
    if (!isPlainObject(src))
        return out
    for (var k in src) {
        if (isPlainObject(src[k]) && typeof src[k].nodes === "number")
            out[k] = { nodes: src[k].nodes, firstSeen: typeof src[k].firstSeen === "number" ? src[k].firstSeen : 0 }
    }
    return out
}

// One line about a destination network's reach across the org, or "" when
// nothing honest can be said. Never claims a count the server did not give.
function prevalenceText(kub0, networkKey) {
    if (!kub0 || !kub0.connected || !kub0.sharingDestinations)
        return ""
    if (kub0.prevalenceSupported === false)
        return "Org prevalence: not answered by this server"
    if (kub0.prevalenceSupported !== true)
        return "Org prevalence: waiting for a heartbeat"
    var p = networkKey && kub0.prevalence ? kub0.prevalence[networkKey] : null
    if (!p)
        return "Org prevalence: no answer yet for this network"
    if (p.nodes === 0)
        return "First in your org: no other endpoint has reported this network"
    return "Seen on " + p.nodes + (p.nodes === 1 ? " other endpoint" : " other endpoints") + " in your org"
}

function emptyConnect() {
    return {
        connectState: "idle",
        connectCode: "",
        connectUrl: "",
        connectExpiresAt: 0,
        connectInterval: 0,
        connectError: ""
    }
}

function copyKub0(src) {
    var k = emptyKub0()
    if (!src || typeof src !== "object")
        return k
    k.connected = src.connected === true
    k.githubUsername = src.githubUsername ? String(src.githubUsername) : ""
    k.nodeName = src.nodeName ? String(src.nodeName) : ""
    k.lastHeartbeatOk = src.lastHeartbeatOk === true
        ? true
        : (src.lastHeartbeatOk === false ? false : null)
    k.lastHeartbeatTs = typeof src.lastHeartbeatTs === "number" && isFinite(src.lastHeartbeatTs)
        ? src.lastHeartbeatTs
        : 0
    k.orgEndpoints = typeof src.orgEndpoints === "number" && isFinite(src.orgEndpoints)
        ? src.orgEndpoints
        : 0
    k.nodeLimit = typeof src.nodeLimit === "number" && isFinite(src.nodeLimit)
        ? src.nodeLimit
        : 0
    k.selfState = src.selfState ? String(src.selfState) : "unknown"
    k.endpoints = k.connected && isArray(src.endpoints) ? src.endpoints.map(normalizeEndpoint).filter(function(e) {return e !== null}) : []
    k.endpointsUpdatedAt = k.connected ? endpointTimestamp(src.endpointsUpdatedAt) : 0
    k.endpointsRefreshOk = k.connected ? triBool(src.endpointsRefreshOk) : null
    k.denylist = isArray(src.denylist) ? src.denylist.slice() : []
    k.denylistVersion = typeof src.denylistVersion === "number" && isFinite(src.denylistVersion)
        ? src.denylistVersion
        : 0
    k.netpolicies = k.connected && isArray(src.netpolicies) ? src.netpolicies.map(normalizeNetPolicy).filter(function(p) {return p !== null}) : []
    k.netpolicyRefreshOk = k.connected ? triBool(src.netpolicyRefreshOk) : null
    k.netpolicyEnforcement = normalizeEnforcement(k.connected || (src.netpolicyEnforcement && src.netpolicyEnforcement.state === "error") ? src.netpolicyEnforcement : null)
    k.prevalence = k.connected ? copyPrevalence(src.prevalence) : {}
    k.prevalenceSupported = k.connected ? triBool(src.prevalenceSupported) : null
    k.sharingDestinations = src.sharingDestinations === true
    k.denylistLive = k.connected ? triBool(src.denylistLive) : null
    k.execGate = copyExecGate(src.execGate)
    return k
}

function copyConnect(src) {
    var c = emptyConnect()
    if (!src || typeof src !== "object")
        return c
    c.connectState = src.connectState ? String(src.connectState) : "idle"
    c.connectCode = src.connectCode ? String(src.connectCode) : ""
    c.connectUrl = src.connectUrl ? String(src.connectUrl) : ""
    c.connectExpiresAt = typeof src.connectExpiresAt === "number" ? src.connectExpiresAt : 0
    c.connectInterval = typeof src.connectInterval === "number" ? src.connectInterval : 0
    c.connectError = src.connectError ? String(src.connectError) : ""
    return c
}

function triBool(v) {
    if (v === true)
        return true
    if (v === false)
        return false
    return null
}

function applyHelloAccount(kub0, account) {
    var k = copyKub0(kub0)
    if (!account || typeof account !== "object")
        return k
    k.connected = account.connected === true
    if (!k.connected || (account.github_username !== undefined && k.githubUsername !== String(account.github_username || ""))) {
        k.endpoints = []
        k.endpointsUpdatedAt = 0
        k.endpointsRefreshOk = null
        clearPolicyEvidence(k)
    }
    if (account.node_name !== undefined)
        k.nodeName = account.node_name ? String(account.node_name) : ""
    if (account.github_username !== undefined)
        k.githubUsername = account.github_username ? String(account.github_username) : ""
    if (account.last_heartbeat_ok !== undefined)
        k.lastHeartbeatOk = triBool(account.last_heartbeat_ok)
    return k
}

// An allow-list: a field left out here never reaches Panel.qml. `name` was
// missing, so every fleet row read "Unnamed rule" although the daemon had
// already settled a name for it (DenylistEntry::label). test_kub0.js ties
// this list to the daemon struct's fields.
function normalizeDenylistEntry(e) {
    if (!e || typeof e !== "object")
        return { name: "", comm: "", path: "", action: "", reason: "", promoted_by: "", created_at: "" }
    return {
        name: e.name ? String(e.name) : "",
        comm: e.comm ? String(e.comm) : "",
        path: e.path ? String(e.path) : "",
        action: e.action ? String(e.action) : "",
        reason: e.reason ? String(e.reason) : "",
        // snake_case as the daemon sends them (DenylistEntry has no rename).
        promoted_by: e.promoted_by ? String(e.promoted_by) : "",
        created_at: e.created_at ? String(e.created_at) : ""
    }
}

// The action as the panel labels it: the real value, never a guess. The gate
// keys only on the literal `block`, so an empty action is "Unset", not "Block".
function denylistActionText(action) {
    var a = typeof action === "string" ? action.trim().toLowerCase() : ""
    if (a === "") return "Unset"
    if (a === "block") return "Block"
    if (a === "monitor") return "Monitor"
    return a.charAt(0).toUpperCase() + a.substring(1)
}

function applyFleet(kub0, ev) {
    var k = copyKub0(kub0)
    if (!ev || typeof ev !== "object")
        return k
    k.connected = ev.connected === true
    if (!k.connected) {
        k.endpoints = []
        k.endpointsUpdatedAt = 0
        k.endpointsRefreshOk = null
    } else {
        if (ev.endpointsRefreshOk !== false && isArray(ev.endpoints)) k.endpoints = ev.endpoints.map(normalizeEndpoint).filter(function(e) {return e !== null})
        if (ev.endpointsRefreshOk !== false && ev.endpointsUpdatedAt !== undefined)
            k.endpointsUpdatedAt = endpointTimestamp(ev.endpointsUpdatedAt)
        if (ev.endpointsRefreshOk !== undefined) k.endpointsRefreshOk = triBool(ev.endpointsRefreshOk)
    }
    if (ev.orgEndpoints !== undefined)
        k.orgEndpoints = typeof ev.orgEndpoints === "number" ? ev.orgEndpoints : 0
    if (ev.nodeLimit !== undefined)
        k.nodeLimit = typeof ev.nodeLimit === "number" ? ev.nodeLimit : 0
    if (ev.selfState !== undefined)
        k.selfState = ev.selfState ? String(ev.selfState) : "unknown"
    if (ev.lastHeartbeatOk !== undefined)
        k.lastHeartbeatOk = triBool(ev.lastHeartbeatOk)
    if (ev.lastHeartbeatTs !== undefined)
        k.lastHeartbeatTs = typeof ev.lastHeartbeatTs === "number" ? ev.lastHeartbeatTs : 0
    if (ev.denylistVersion !== undefined)
        k.denylistVersion = typeof ev.denylistVersion === "number" ? ev.denylistVersion : 0
    if (isArray(ev.denylist)) {
        var i
        var list = []
        for (i = 0; i < ev.denylist.length; i++)
            list.push(normalizeDenylistEntry(ev.denylist[i]))
        k.denylist = list
    }
    if (!k.connected) {
        k.netpolicies = []
        k.netpolicyRefreshOk = null
        k.netpolicyEnforcement = normalizeEnforcement(ev.netpolicyEnforcement && ev.netpolicyEnforcement.state === "error" ? ev.netpolicyEnforcement : null)
    } else {
        if (isArray(ev.netpolicies))
            k.netpolicies = ev.netpolicies.map(normalizeNetPolicy).filter(function(p) {return p !== null})
        if (ev.netpolicyRefreshOk !== undefined) k.netpolicyRefreshOk = triBool(ev.netpolicyRefreshOk)
        if (ev.netpolicyEnforcement !== undefined)
            k.netpolicyEnforcement = normalizeEnforcement(ev.netpolicyEnforcement)
    }
    if (!k.connected) {
        k.prevalence = {}
        k.prevalenceSupported = null
    } else {
        if (isArray(ev.prevalence)) k.prevalence = normalizePrevalence(ev.prevalence)
        if (ev.prevalenceSupported !== undefined) k.prevalenceSupported = triBool(ev.prevalenceSupported)
    }
    if (ev.sharingDestinations !== undefined) k.sharingDestinations = ev.sharingDestinations === true
    if (!k.connected)
        k.denylistLive = null
    else if (ev.denylistLive !== undefined)
        k.denylistLive = triBool(ev.denylistLive)
    // Not gated on `connected`: the gate is this machine's, and the frame says
    // itself where its state came from (`source`).
    if (ev.execGate !== undefined)
        k.execGate = normalizeExecGate(ev.execGate)
    return k
}

function count(v) {
    return typeof v === "number" && isFinite(v) && v >= 0 ? Math.floor(v) : 0
}

// Org network policies are an allow-list like everything else the panel reads: a
// field the daemon sends is invisible until it is named here.
function normalizeNetPolicy(p) {
    if (!isPlainObject(p) || typeof p.id !== "string" || !p.id) return null
    var rules = isArray(p.rules) ? p.rules : []
    return {
        id: p.id,
        name: typeof p.name === "string" ? p.name : "",
        mode: p.mode === "block" ? "block" : "monitor",
        rules: rules.filter(isPlainObject).map(function(r) {
            return {
                id: typeof r.id === "string" ? r.id : "",
                kind: ["country", "intel", "ip"].indexOf(r.kind) >= 0 ? r.kind : "unknown",
                label: typeof r.label === "string" ? r.label : "",
                action: r.action === "block" ? "block" : "monitor",
                appPath: typeof r.appPath === "string" ? r.appPath : "",
                size: count(r.size),
                hits: count(r.hits),
                suppressed: count(r.suppressed),
                wouldBlock: count(r.wouldBlock),
                blocked: count(r.blocked),
                shared: count(r.shared),
                lastHitTs: count(r.lastHitTs),
                effectiveAction: r.effectiveAction === "block" ? "block" : "monitor",
                enforced: r.enforced === true,
                notEnforcedReason: typeof r.notEnforcedReason === "string" ? r.notEnforcedReason : "",
                canSnooze: r.canSnooze === true,
                snoozedUntil: count(r.snoozedUntil),
                serverSuppressed: count(r.serverSuppressed),
                serverWithheld: count(r.serverWithheld)
            }
        })
    }
}

function plural(n, one, many) {
    return n + " " + (n === 1 ? one : many)
}

var ENFORCEMENT_STATES = ["none", "monitor", "enforcing", "error"]

// Whether this endpoint enforces its org's block rules, and if not, why. An allow-list
// like the rest: only these fields reach the panel.
function normalizeEnforcement(e) {
    var o = isPlainObject(e) ? e : {}
    return {
        state: ENFORCEMENT_STATES.indexOf(o.state) >= 0 ? o.state : "unknown",
        reason: typeof o.reason === "string" ? o.reason : "",
        enforcing: o.state === "enforcing" && o.enforcing === true,
        entries: count(o.entries),
        sharedRanges: count(o.sharedRanges),
        appliedTs: count(o.appliedTs)
    }
}

// Explicit producer role, independent of tenant connection and per-app helper readiness.
function policyDaemonModeText(mode) {
    if (mode === "user") return "User daemon · system policy visibility unavailable"
    if (mode === "system") return "System daemon reported on this connection"
    return "Daemon role unknown (legacy or missing hello)"
}

// Zero means no timestamp; positive evidence must be representable by Date.
function validPolicyTimestamp(ms) {
    return typeof ms === "number" && isFinite(ms) && ms > 0 &&
        ms <= 8640000000000000 && isFinite(new Date(ms).getTime())
}

// Applied-plan evidence is not a packet-drop counter or proof of every retained rule.
function policyEnforcementText(e) {
    if (!e || ENFORCEMENT_STATES.indexOf(e.state) < 0)
        return "Policy enforcement unknown. Retained kernel rules are unverified."
    if (e.state === "enforcing" && e.enforcing)
        return "Known applied plan: " + plural(e.entries, "range", "ranges") + "." +
            (validPolicyTimestamp(e.appliedTs) ? " Applied at " + new Date(e.appliedTs).toISOString() + "." : "") +
            (e.reason ? " " + e.reason : "")
    if (e.state === "error")
        return "Policy error: " + (e.reason || "unknown error") + ". Retained kernel rules are unverified."
    if (e.state === "none") return "Daemon reports no current block plan." + (e.reason ? " " + e.reason : "")
    return e.reason || "Current plan is not reported as enforcing; retained kernel rules are unverified."
}

// Refresh evidence is separate from applied-plan evidence, even with an empty list.
function policyRefreshText(k) {
    if (!k || k.netpolicyRefreshOk !== false) return ""
    if (!isArray(k.netpolicies) || k.netpolicies.length === 0) return "Policy refresh failed. No policies to show."
    return "Policy refresh failed. Showing the last policies received." +
        (k.netpolicyEnforcement && k.netpolicyEnforcement.state === "enforcing" && k.netpolicyEnforcement.enforcing
            ? " Retaining the known applied plan." : "")
}

// The system daemon's view over the user daemon's (#61 step 2): its `status`
// (the account card: the account that heartbeats, and its fleet facts), its
// `policies` (the list, with the system daemon's snoozes and enforcement) and
// its `rules` (its deny list), read over the request connection. Endpoints and
// the exec gate stay the user daemon's.
function applySystemView(kub0, view) {
    var k = copyKub0(kub0)
    if (!view || typeof view !== "object")
        return k
    var st = view.status
    if (st && typeof st === "object") {
        var a = st.account && typeof st.account === "object" ? st.account : {}
        var f = st.fleet && typeof st.fleet === "object" ? st.fleet : {}
        k.connected = a.connected === true
        k.githubUsername = a.githubUsername ? String(a.githubUsername) : ""
        k.nodeName = a.nodeName ? String(a.nodeName) : ""
        k.lastHeartbeatOk = triBool(a.lastHeartbeatOk)
        k.lastHeartbeatTs = typeof a.lastHeartbeatTs === "number" && isFinite(a.lastHeartbeatTs) ? a.lastHeartbeatTs : 0
        k.orgEndpoints = typeof f.orgEndpoints === "number" ? f.orgEndpoints : 0
        k.nodeLimit = typeof f.nodeLimit === "number" ? f.nodeLimit : 0
        k.selfState = f.selfState ? String(f.selfState) : "unknown"
        if (typeof f.denylistVersion === "number")
            k.denylistVersion = f.denylistVersion
    }
    var pol = view.policies
    if (pol && typeof pol === "object") {
        k.netpolicies = isArray(pol.netpolicies) ? pol.netpolicies.map(normalizeNetPolicy).filter(function(p) {return p !== null}) : []
        k.netpolicyRefreshOk = triBool(pol.netpolicyRefreshOk)
        k.netpolicyEnforcement = normalizeEnforcement(pol.netpolicyEnforcement)
    }
    var rules = view.rules
    if (rules && typeof rules === "object" && isArray(rules.denylist)) {
        var list = []
        for (var i = 0; i < rules.denylist.length; i++)
            list.push(normalizeDenylistEntry(rules.denylist[i]))
        k.denylist = list
    }
    return k
}

// Reading the system daemon's own stream, its frames are the live account,
// policies and deny list, and a `status` read is older than they are. What no
// frame carries is who the account is after a login or logout made since the
// stream connected: that, and only that, is taken from the read.
function applySystemIdentity(kub0, view) {
    var k = copyKub0(kub0)
    var st = view && typeof view === "object" ? view.status : null
    var a = st && typeof st === "object" && st.account && typeof st.account === "object" ? st.account : null
    if (!a)
        return k
    k.githubUsername = a.githubUsername ? String(a.githubUsername) : ""
    k.nodeName = a.nodeName ? String(a.nodeName) : ""
    return k
}

function clearPolicyEvidence(k) {
    k.netpolicies = []
    k.netpolicyRefreshOk = null
    k.netpolicyEnforcement = normalizeEnforcement(null)
    return k
}

// `fmt` is the panel's ux object (js/Ux.js). Its `time` is set when the user
// chose how timestamps read; without it this prints HH:MM as it always has.
function clock(ms, fmt, now) {
    if (fmt && fmt.time)
        return fmt.time(ms, typeof now === "number" ? now : Date.now())
    var d = new Date(ms)
    var h = d.getHours(), m = d.getMinutes()
    return (h < 10 ? "0" : "") + h + ":" + (m < 10 ? "0" : "") + m
}

// The caption under a network-policy rule: what it covers, then what it has done on
// this device since kub0d started. Counts are connection matches, never nft drops.
function policyRuleDetail(r, fmt, now) {
    if (!r) return ""
    var parts = []
    if (r.effectiveAction === "block") parts.push(r.enforced ? "blocking" : "block (not enforced here)")
    if (r.kind === "intel") parts.push(plural(r.size, "address", "addresses"))
    else if (r.kind === "country") parts.push(plural(r.size, "country", "countries"))
    else if (r.kind === "unknown") parts.push("not supported by this kub0d")
    parts.push(r.hits === 0 ? "no matches yet" : plural(r.hits, "match", "matches") + " this session")
    if (r.blocked > 0) parts.push(r.blocked + " matches to the known applied block plan")
    else if (r.wouldBlock > 0) parts.push(r.wouldBlock + " would block")
    if (r.shared > 0) parts.push(r.shared + " on shared infrastructure (never blocked)")
    if (r.suppressed > 0) parts.push(r.suppressed + " never-block")
    if (r.serverWithheld > 0) parts.push(r.serverWithheld + " withheld (not TLP:CLEAR)")
    if (validPolicyTimestamp(r.snoozedUntil)) parts.push("snoozed until " + clock(r.snoozedUntil, fmt, now))
    if (r.effectiveAction === "block" && !r.enforced && r.notEnforcedReason) parts.push(r.notEnforcedReason)
    return parts.join(" · ")
}

// The inventory is an allow-list too: account credentials and extra API fields
// never enter the panel model.
function normalizeEndpoint(e) {
    if (!isPlainObject(e) || typeof e.nodeName !== "string" || !e.nodeName.trim()) return null
    return {
        nodeName: typeof e.nodeName === "string" ? e.nodeName : "",
        state: ["enforcing", "monitoring", "down"].indexOf(e.state) >= 0 ? e.state : "unknown",
        lastSeen: typeof e.lastSeen === "string" ? e.lastSeen : "",
        agentVer: typeof e.agentVer === "string" ? e.agentVer : "",
        blocksActive: typeof e.blocksActive === "number" && isFinite(e.blocksActive) && e.blocksActive >= 0 && Math.floor(e.blocksActive) === e.blocksActive ? e.blocksActive : null,
        kernelVersion: typeof e.kernelVersion === "string" ? e.kernelVersion : "",
        arch: typeof e.arch === "string" ? e.arch : ""
    }
}

function endpointTimestamp(value) {
    return typeof value === "number" && isFinite(value) && value >= 0 && Math.floor(value) === value ? value : 0
}

function beginConnect(connect) {
    var c = copyConnect(connect)
    if (c.connectState === "waiting")
        return c
    c.connectState = "waiting"
    c.connectCode = ""
    c.connectUrl = ""
    c.connectExpiresAt = 0
    c.connectInterval = 0
    c.connectError = ""
    return c
}

function cancelConnect(_connect) {
    return emptyConnect()
}

function applyConnectLine(connect, line, nowMs) {
    var c = copyConnect(connect)
    if (line === undefined || line === null)
        return c
    var trimmed = String(line).replace(/^\s+|\s+$/g, "")
    if (!trimmed)
        return c
    var ev
    try {
        ev = JSON.parse(trimmed)
    } catch (e) {
        return c
    }
    if (!isPlainObject(ev) || typeof ev.event !== "string")
        return c
    nowMs = typeof nowMs === "number" ? nowMs : Date.now()
    if (ev.event === "code") {
        c.connectState = "waiting"
        c.connectCode = ev.user_code ? String(ev.user_code) : ""
        c.connectUrl = ev.connect_url ? String(ev.connect_url) : ""
        var exp = typeof ev.expires_in === "number" ? ev.expires_in : 0
        c.connectExpiresAt = nowMs + exp * 1000
        c.connectInterval = typeof ev.interval === "number" ? ev.interval : 0
        c.connectError = ""
        return c
    }
    if (ev.event === "connected") {
        c.connectState = "connected"
        c.connectError = ""
        if (ev.github_username !== undefined)
            c.githubUsername = String(ev.github_username || "")
        return c
    }
    if (ev.event === "error") {
        c.connectState = "error"
        c.connectError = ev.message ? String(ev.message) : "connect failed"
        return c
    }
    return c
}

// `pkexec /usr/bin/kub0 --json login` (the system daemon's login, #61 step
// 1b) prints each partial reply as one compact JSON line and the final reply
// pretty-printed over several lines at exit. These translate it into the
// the daemon's old `connect --json` events applyConnectLine and applyConnectToKub0
// already read, so the panel has one connect state machine for both paths.

// A partial reply line as a `code` event line, or "" for anything else (an
// `expired` notice, which that `connect` never printed either, or a line of
// the final reply).
function kub0LoginPartial(line) {
    var trimmed = String(line === undefined || line === null ? "" : line).replace(/^\s+|\s+$/g, "")
    if (!trimmed || trimmed.charAt(0) !== "{" || trimmed.charAt(trimmed.length - 1) !== "}")
        return ""
    var ev
    try {
        ev = JSON.parse(trimmed)
    } catch (e) {
        return ""
    }
    if (!isPlainObject(ev) || typeof ev.code !== "string" || !ev.code)
        return ""
    return JSON.stringify({
        event: "code",
        user_code: ev.code,
        connect_url: typeof ev.url === "string" ? ev.url : "",
        expires_in: typeof ev.expiresIn === "number" ? ev.expiresIn : 0,
        interval: typeof ev.interval === "number" ? ev.interval : 0
    })
}

// The whole of stdout, stderr and the exit code, once the process ended, as
// a `connected` or an `error` event line. The final reply is the last
// top-level object, the one that starts on a line of its own.
function kub0LoginFinish(stdout, stderr, code) {
    var lines = String(stdout || "").split("\n")
    var start = -1
    for (var i = lines.length - 1; i >= 0; i--) {
        if (String(lines[i]).replace(/\s+$/, "") === "{") {
            start = i
            break
        }
    }
    var final = null
    if (start >= 0) {
        try {
            final = JSON.parse(lines.slice(start).join("\n"))
        } catch (e) {
            final = null
        }
    }
    if (Number(code) === 0 && isPlainObject(final) && typeof final.githubUsername === "string")
        return JSON.stringify({ event: "connected", github_username: final.githubUsername })
    var err = String(stderr || "").replace(/^\s+|\s+$/g, "")
    var first = err.split("\n")[0] || ""
    var m = /^kub0 login: (.*)$/.exec(first)
    var message = m ? m[1] : first
    if (!message) {
        if (Number(code) === 126 || Number(code) === 127)
            message = "authorization was refused or cancelled"
        else
            message = Number(code) === 0 ? "kub0 login printed no account" : "kub0 login exited " + code
    }
    return JSON.stringify({ event: "error", message: message })
}

function applyConnectToKub0(kub0, line) {
    var k = copyKub0(kub0)
    if (line === undefined || line === null)
        return k
    var trimmed = String(line).replace(/^\s+|\s+$/g, "")
    if (!trimmed)
        return k
    var ev
    try {
        ev = JSON.parse(trimmed)
    } catch (e) {
        return k
    }
    if (!isPlainObject(ev) || ev.event !== "connected")
        return k
    k.connected = true
    clearPolicyEvidence(k)
    k.endpoints = []
    k.endpointsUpdatedAt = 0
    k.endpointsRefreshOk = null
    if (ev.github_username !== undefined)
        k.githubUsername = ev.github_username ? String(ev.github_username) : ""
    return k
}

function basename(p) {
    var s = String(p || "")
    if (!s)
        return ""
    var i = s.lastIndexOf("/")
    return i >= 0 ? s.substring(i + 1) : s
}

function appExe(app) {
    if (!app || typeof app !== "object")
        return ""
    if (app.exe)
        return String(app.exe)
    if (app.path)
        return String(app.path)
    return ""
}

function appComm(app) {
    if (!app || typeof app !== "object")
        return ""
    if (app.comm)
        return String(app.comm)
    return ""
}

function entryMatchesApp(entry, app) {
    if (!entry || !app)
        return false
    var comm = entry.comm ? String(entry.comm) : ""
    var path = entry.path ? String(entry.path) : ""
    var exe = appExe(app)
    var exeBase = basename(exe)
    var c = appComm(app)
    var id = app.id ? String(app.id) : ""
    if (comm) {
        if (exeBase && exeBase === comm)
            return true
        if (c && c === comm)
            return true
        if (id && id === comm)
            return true
        if (id && basename(id) === comm)
            return true
    }
    if (path) {
        if (exe && exe === path)
            return true
        if (id && id === path)
            return true
    }
    return false
}

function denylistMatches(apps, denylist) {
    var out = []
    if (!isArray(apps) || !isArray(denylist) || denylist.length === 0)
        return out
    var i, j
    for (i = 0; i < apps.length; i++) {
        var app = apps[i]
        if (!app)
            continue
        for (j = 0; j < denylist.length; j++) {
            if (entryMatchesApp(denylist[j], app)) {
                out.push(app)
                break
            }
        }
    }
    return out
}

function denylistEntryHighlighted(entry, apps) {
    return denylistMatches(apps, [normalizeDenylistEntry(entry)]).length > 0
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        emptyKub0: emptyKub0,
        emptyConnect: emptyConnect,
        copyKub0: copyKub0,
        copyConnect: copyConnect,
        applyHelloAccount: applyHelloAccount,
        applyFleet: applyFleet, normalizePrevalence: normalizePrevalence, prevalenceText: prevalenceText,
        beginConnect: beginConnect,
        cancelConnect: cancelConnect,
        applyConnectLine: applyConnectLine,
        kub0LoginPartial: kub0LoginPartial,
        applySystemView: applySystemView,
        kub0LoginFinish: kub0LoginFinish,
        applyConnectToKub0: applyConnectToKub0,
        denylistMatches: denylistMatches,
        denylistEntryHighlighted: denylistEntryHighlighted,
        normalizeNetPolicy: normalizeNetPolicy,
        normalizeEnforcement: normalizeEnforcement,
        validPolicyTimestamp: validPolicyTimestamp,
        policyDaemonModeText: policyDaemonModeText,
        applySystemIdentity: applySystemIdentity,
        clearPolicyEvidence: clearPolicyEvidence,
        policyEnforcementText: policyEnforcementText,
        policyRefreshText: policyRefreshText,
        policyRuleDetail: policyRuleDetail,
        basename: basename,
        normalizeDenylistEntry: normalizeDenylistEntry,
        denylistActionText: denylistActionText,
        denylistLiveText: denylistLiveText,
        normalizeExecGate: normalizeExecGate,
        normalizeExecDeny: normalizeExecDeny,
        normalizeTrustedDigest: normalizeTrustedDigest,
        execGateHeading: execGateHeading,
        execGateFacts: execGateFacts,
        execDenyLine: execDenyLine,
        execDecisionText: execDecisionText,
        trustedLine: trustedLine
    }
}
