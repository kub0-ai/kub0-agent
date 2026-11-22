// Measured TCP payload, never socket counts or queue sizes presented as bytes.
// `fmt` is the panel's ux object (js/Ux.js). Its `bytes` is set when the user
// chose other units; without it this prints the binary form it always has.
function bytes(n, fmt) {
    if (fmt && fmt.bytes)
        return fmt.bytes(n)
    if (typeof n !== "number" || !isFinite(n) || n < 0)
        return "unknown"
    var units = ["B", "KiB", "MiB", "GiB", "TiB"]
    var u = 0
    while (n >= 1024 && u < units.length - 1) { n /= 1024; u++ }
    return (u ? n.toFixed(1) : Math.round(n)) + " " + units[u]
}

function speed(a) {
    if (!a || !a.traffic || a.traffic.txRate === null || a.traffic.rxRate === null)
        return -1
    return a.traffic.txRate + a.traffic.rxRate
}

function summary(a, current, fmt) {
    var t = a && a.traffic
    if (!t || t.measured === 0)
        return "TCP transfer unknown"
    var rate = current && t.txRate !== null && t.rxRate !== null
        ? "↑ " + bytes(t.txRate, fmt) + "/s  ↓ " + bytes(t.rxRate, fmt) + "/s"
        : (current ? "TCP rate warming up or incomplete" : "TCP rate unavailable while monitoring is stale")
    return rate + " · sampled session ↑ " + bytes(t.txBytes, fmt) + " ↓ " + bytes(t.rxBytes, fmt)
}

if (typeof module !== "undefined" && module.exports)
    module.exports = { bytes: bytes, speed: speed, summary: summary }
