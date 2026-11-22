function endpoint(p) {
    if (!p || !p.ip) return "Unknown"
    return (p.ip.indexOf(":") >= 0 ? "[" + p.ip + "]" : p.ip) + (p.port ? ":" + p.port : "")
}
// `fmt` is the panel's ux object (js/Ux.js); see js/History.js time().
function describe(c, fmt, now) {
    if (!c) return []
    var e=c.evidence || {}, v=e.verdict, rows=[]
    function row(label,value) {rows.push({label:label,value:String(value)})}
    row("Executable",c.exe || "Unknown — not reported")
    row("Process / socket owner",(c.app && c.app.pid ? "PID " + c.app.pid : "PID unknown") + (typeof c.uid === "number" ? " · UID " + c.uid : " · UID unknown"))
    row("Owner lookup",e.ownerMethod || "Unknown")
    if (c.reason) row("Owner lookup limitation",c.reason)
    row("Destination",endpoint(c.remote))
    row("Local endpoint",endpoint(c.local))
    row("Protocol / state",String(c.proto || "unknown").toUpperCase() + " · " + (c.state || "unknown"))
    row("Observation source",e.source || "Unknown — legacy record")
    row("Source timestamp",typeof e.recordedAt !== "number" ? "Unknown"
        : fmt && fmt.time ? fmt.time(e.recordedAt, typeof now === "number" ? now : Date.now())
        : new Date(e.recordedAt).toLocaleString())
    if (v) {
        row("Reported verdict",v.action || "Unknown")
        row("Decision maker",v.provenance === "external" ? "External enforcement engine" : v.provenance || "Unknown")
        if (v.rule_id) row("Decision rule",v.rule_id)
    } else row("Reported verdict","No enforcement decision reported by this source")
    if (c.hostname) row("Hostname observation",c.hostname + (c.hostnameSource === "dns" ? "\nThe name this user's software asked DNS for: the optional collector matched the answer to this socket's own query, and the server was one of the host's configured resolvers" : c.hostnameSource === "ptr" ? "\nReverse DNS (PTR) answer for the address" : c.hostnameSource === "source" ? "\nReported by the observation source" : ""))
    if (c.country) row("Geo lookup",c.country + " · IP geolocation")
    if (typeof c.asn === "number" || c.org) row("Network (ASN)",(typeof c.asn === "number" ? "AS" + c.asn : "") + (c.org ? (typeof c.asn === "number" ? " · " : "") + c.org : "") + "\nThe registrant of the range, not the tenant of the machine")
    if (e.hash) row("Executable hash",e.hash)
    if (e.package) row("Package",e.package === "none" ? "No installed package owns this executable" : e.package)
    if (e.container) row("Container identity",e.container)
    if (e.lineage) {
        var anc=(e.lineage.ancestors || []).map(function(a) {return (a.comm || String(a.pid)) + " (" + a.pid + ")" + (a.exe ? " " + a.exe : "")})
        if (e.lineage.truncated) anc.push("… chain cut short")
        row("Process lineage",anc.length ? anc.join("\n← ") : "No parent recorded")
        if (e.lineage.cmdline) row("Command line",e.lineage.cmdline)
        if (e.lineage.cwd) row("Working directory",e.lineage.cwd)
    }
    if (c.clue) row("Inferred owner",(c.clue.label || "") + " · " + (c.clue.confidence || "unknown confidence") + "\n" + (c.clue.basis || ""))
    if (c.tag) row(c.tag.source === "user" ? "User annotation" : "Fleet annotation",c.tag.label || "")
    if (c.policy && c.policy.length) row("Org network policy",c.policy.map(function(p) {return p.label}).join("\n") + "\nMatched when first seen · monitor only, not blocked")
    if (c.indicators && c.indicators.length) row("Local indicators",c.indicators.map(function(i) {return (i.severity || "info") + " · " + i.id + (i.attack && i.attack.id ? " (" + i.attack.id + ")" : "") + "\n" + (i.basis || "")}).join("\n") + "\nComputed on this machine · a claim with its basis, not a verdict")
    row("Record identity",c.id || "Unknown")
    return rows
}
if (typeof module !== "undefined" && module.exports) module.exports={endpoint:endpoint,describe:describe}
