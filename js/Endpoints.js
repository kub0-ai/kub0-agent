// Client inventory policy: tolerate at most 60 seconds of future clock skew.
var ENDPOINT_FUTURE_SKEW_MS = 60000

function age(ms, now) {
    if (typeof ms !== "number" || !isFinite(ms) || ms <= 0 || !isFinite(new Date(ms).getTime())
        || typeof now !== "number" || !isFinite(now) || now <= 0 || !isFinite(new Date(now).getTime())) return null
    var delta = now - ms
    return delta < -ENDPOINT_FUTURE_SKEW_MS ? null : Math.max(0, delta)
}

function state(row, now) {
    if (!row) return "unknown"
    // An explicit down report does not claim a fresh observation.
    if (row.state === "down") return "down"
    if (row.state !== "enforcing" && row.state !== "monitoring") return "unknown"
    var elapsed = age(typeof row.lastSeen === "string" && row.lastSeen.trim() ? Date.parse(row.lastSeen) : NaN, now)
    if (elapsed === null) return "unknown"
    return elapsed >= 600000 ? "down" : row.state
}

// Bound ordinary age updates and QML's integer Timer interval. Only recognized
// live reports have clock-driven state transitions; unusable clocks fall back
// to the ordinary cadence rather than creating a zero-delay retry loop.
function nextTransitionDelay(rows, now) {
    var delay = 10000
    if (age(now, now) === null) return delay
    var candidates = rows || []
    candidates.forEach(function(row) {
        if (!row || (row.state !== "enforcing" && row.state !== "monitoring")) return
        var seen = typeof row.lastSeen === "string" && row.lastSeen.trim() ? Date.parse(row.lastSeen) : NaN
        if (age(seen, seen) === null) return
        var delta = now - seen
        var remaining = delta < -ENDPOINT_FUTURE_SKEW_MS
            ? -ENDPOINT_FUTURE_SKEW_MS - delta : 600000 - delta
        if (remaining > 0) delay = Math.min(delay, Math.max(1, Math.ceil(remaining)))
    })
    return delay
}

function inventoryStatus(account, rows, now, fmt) {
    if (account.connected !== true) return "Connect to kub0 to see your tenant's kub0 endpoints."
    var elapsed = age(account.endpointsUpdatedAt, now)
    // With a time style chosen the one reading says it; the default gives the
    // full date and the age together, as it always has.
    var date = elapsed === null ? "Last successful inventory date unavailable."
        : fmt && fmt.time ? "Last successful inventory: " + fmt.time(account.endpointsUpdatedAt, now) + "."
        : "Last successful inventory: " + new Date(account.endpointsUpdatedAt).toLocaleString()
            + " · " + Math.floor(elapsed / 1000) + " seconds ago."
    if (account.endpointsRefreshOk === false) return "Inventory refresh failed. " + date
    if (elapsed === null) return "Inventory freshness unknown. " + date
    return rows.length + (rows.length === 1 ? " kub0 endpoint. " : " kub0 endpoints. ") + date
}

function ownerApps(value) {
    return typeof value === "number" && isFinite(value) && value >= 0 && Math.floor(value) === value
        ? value + (value === 1 ? " app" : " apps") + " with endpoint-owner IP entries reported" : "Apps with endpoint-owner IP entries not reported"
}

function label(row, now) {
    var s = state(row, now)
    return s === "down" ? "Offline" : s === "enforcing" ? "Online · enforcing"
        : s === "monitoring" ? "Online · monitoring" : "Status unknown"
}

function filtered(rows, query, filter, now) {
    var q = String(query || "").trim().toLowerCase()
    return (rows || []).filter(function(row) {
        var s = state(row, now)
        var matches = !filter || (filter === "online" ? s === "enforcing" || s === "monitoring"
            : filter === "offline" ? s === "down" : filter === s)
        var text = [row.nodeName, row.agentVer, row.arch, row.kernelVersion].join(" ").toLowerCase()
        return matches && (!q || text.indexOf(q) >= 0)
    })
}

function toggle(current, clicked) { return current === clicked ? "" : clicked }

function time(value, fmt, now) {
    var ms = Date.parse(value)
    if (!isFinite(ms))
        return "Not reported"
    if (fmt && fmt.time)
        return fmt.time(ms, typeof now === "number" ? now : Date.now())
    return new Date(ms).toLocaleString()
}

if (typeof module !== "undefined" && module.exports)
    module.exports = { nextTransitionDelay: nextTransitionDelay, state: state, label: label, filtered: filtered, toggle: toggle, time: time, age: age, inventoryStatus: inventoryStatus, ownerApps: ownerApps }
