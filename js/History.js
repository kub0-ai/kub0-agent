// `fmt` is the panel's ux object (js/Ux.js). Its `time` is set when the user
// chose how timestamps read; without it this prints the locale's full date.
function time(ts, fmt, now) {
    if (fmt && fmt.time)
        return fmt.time(ts, typeof now === "number" ? now : Date.now())
    return new Date(ts).toLocaleString()
}

function endpoint(c) {
    var ip = c && c.remote ? c.remote.ip : ""
    var port = c && c.remote ? c.remote.port : 0
    return (ip.indexOf(":") >= 0 ? "[" + ip + "]" : ip) + (port ? ":" + port : "")
}

function csv(entries) {
    function cell(value) {
        var s = String(value === null || value === undefined ? "" : value)
        if (/^[\s]*[=+@-]/.test(s) || /^[\t\r]/.test(s)) s = "'" + s
        return '"' + s.replace(/"/g, '""') + '"'
    }
    var out = "first_observed_ms,last_observed_ms,app,executable,protocol,destination,port,hostname,country,sampled_tx_bytes,sampled_rx_bytes,present_at_last_sample\n"
    for (var i = 0; i < entries.length; i++) {
        var e = entries[i], c = e.connection
        out += [e.firstObserved, e.lastObserved, c.app.name, c.exe || "", c.proto,
            c.remote.ip, c.remote.port, c.hostname, c.country,
            e.bytes ? e.bytes.tx : null, e.bytes ? e.bytes.rx : null, e.active]
            .map(cell).join(",") + "\n"
    }
    return out
}

if (typeof module !== "undefined" && module.exports)
    module.exports = { time: time, endpoint: endpoint, csv: csv }
