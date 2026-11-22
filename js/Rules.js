function destinations(app) {
    var rows = app && app.connections ? app.connections : [], out = [], seen = Object.create(null)
    for (var i=0; i<rows.length; i++) {
        var c=rows[i], ip=c.remote && c.remote.ip
        if (!ip || c.unresolved || c.state === "closed" || seen[ip]) continue
        seen[ip]=true; out.push(ip)
    }
    return out.sort()
}
function active(rules, app, now) {
    return (rules || []).filter(function(r) {return r.app === app && r.expiresAt > now})
}
function forApp(rules, helperApp) {
    return (rules || []).filter(function(r) {return r.app === helperApp})
}
if (typeof module !== "undefined" && module.exports) module.exports={destinations:destinations,active:active,forApp:forApp}
