function appRow(i) {
  var id = "fixture-" + i;
  var connId = "tcp:" + id + ":192.0.2." + ((i % 200) + 1) + ":443";
  var conn = {
    exe: "/usr/bin/fixture-probe", uid: 1000,
    evidence: {source:"procfs",recordedAt:Date.now(),verdict:null,ownerMethod:"fixture procfs observation",hash:null,container:null},
    id: connId, proto: "tcp", inode: i, app: { id: id, name: i === 0 ? "Firefox" : ("App " + i), icon: "", desktop: "", pid: 1000 + i, system: false },
    local: { ip: "192.0.2.254", port: 40000 + i }, remote: { ip: "192.0.2." + ((i % 200) + 1), port: 443 },
    state: "ESTABLISHED", country: "US", lat: 37.7, lon: -122.4, unresolved: false, newNetwork: false,
    networkKey: "192.0.2.0/24", seenAt: 100000
  };
  return {
    id: id, name: conn.app.name, icon: "", desktop: "", system: false, pids: [1000 + i],
    traffic: { id: id, txBytes: 65536, rxBytes: 4194304, txRate: 1024, rxRate: 32768, measured: 1, tcp: 1 },
    connections: [conn], unresolved: 0, lastActivity: 100000, spark: [], blocked: false, mechanism: ""
  };
}

function modelWith(n) {
  var apps = {}, ordered = [], connections = {};
  for (var i = 0; i < n; i++) {
    var a = appRow(i);
    apps[a.id] = a;
    ordered.push(a);
    connections[a.connections[0].id] = a.connections[0];
  }
  return {
    revision: 1, hello: true, coverage: "TCP + connected UDP", rdns: false,
    connections: connections, apps: apps, ordered: ordered, count: n,
    historyApps: {}, historyOrdered: [], historyCount: 0, sourceCount: n,
    pulse: false, pulseNetwork: "", awayKeys: [], digestText: "", blocked: {}, lastError: ""
  };
}

// A panel a person would recognise, for a picture of it
// (VALLUM_SCENARIO=showcase with VALLUM_SHOTS, see run-runtime.sh). No check
// reads it. Every address is from a documentation range (RFC 5737, RFC 3849)
// and every host name ends in .example.
function showcase() {
  // [app id, name, exe, blocked, up B/s, down B/s, [[ip, port, proto, country, lat, lon, host], ...]]
  var rows = [
    ["firefox", "Firefox", "/usr/lib/firefox/firefox", false, 18400, 742000, [
      ["203.0.113.10", 443, "tcp", "US", 37.77, -122.42, "cdn.media.example"],
      ["198.51.100.24", 443, "tcp", "DE", 50.11, 8.68, "static.news.example"],
      ["198.51.100.77", 443, "tcp", "NL", 52.37, 4.90, "fonts.example"],
      ["2001:db8:40::12", 443, "udp", "US", 40.71, -74.01, "video.example"]]],
    ["thunderbird", "Thunderbird", "/usr/lib/thunderbird/thunderbird", false, 900, 5200, [
      ["203.0.113.143", 993, "tcp", "IE", 53.35, -6.26, "imap.mail.example"],
      ["203.0.113.25", 465, "tcp", "IE", 53.35, -6.26, "smtp.mail.example"]]],
    ["syncthing", "Syncthing", "/usr/bin/syncthing", false, 96000, 12800, [
      ["198.51.100.201", 22000, "tcp", "CA", 43.65, -79.38, "relay-yyz.example"],
      ["192.0.2.88", 22000, "tcp", "AU", -33.87, 151.21, "relay-syd.example"]]],
    ["git", "git", "/usr/bin/git", false, 2100, 388000, [
      ["192.0.2.44", 22, "tcp", "US", 47.61, -122.33, "code.example"]]],
    ["pacman", "pacman", "/usr/bin/pacman", false, 600, 1310000, [
      ["198.51.100.5", 443, "tcp", "SE", 59.33, 18.07, "mirror.se.example"],
      ["203.0.113.80", 443, "tcp", "BR", -23.55, -46.63, "mirror.br.example"]]],
    ["mpv", "mpv", "/usr/bin/mpv", false, 1200, 2460000, [
      ["192.0.2.160", 443, "tcp", "SG", 1.35, 103.82, "stream.example"]]],
    ["ssh", "ssh", "/usr/bin/ssh", false, 340, 410, [
      ["198.51.100.130", 22, "tcp", "FR", 48.86, 2.35, "build.example"]]],
    ["metrics-agent", "metrics-agent", "/opt/vendor/metrics-agent", true, 0, 0, [
      ["203.0.113.199", 443, "tcp", "GB", 51.51, -0.13, "collect.telemetry.example"]]]
  ];
  var apps = {}, ordered = [], connections = {}, blocked = {}, inode = 1, total = 0;
  for (var i = 0; i < rows.length; i++) {
    var r = rows[i], conns = [];
    for (var j = 0; j < r[6].length; j++) {
      var d = r[6][j];
      var v6 = d[0].indexOf(":") >= 0;
      var conn = {
        exe: r[2], uid: 1000,
        evidence: {source:"procfs",recordedAt:Date.now(),verdict:null,ownerMethod:"fixture procfs observation",hash:null,container:null},
        id: d[2] + ":" + r[0] + ":" + d[0] + ":" + d[1], proto: d[2], inode: inode++,
        app: { id: r[0], name: r[1], icon: "", desktop: "", pid: 2000 + i, system: false },
        local: { ip: v6 ? "2001:db8::254" : "192.0.2.254", port: 41000 + inode }, remote: { ip: d[0], port: d[1] },
        state: "ESTABLISHED", country: d[3], lat: d[4], lon: d[5], unresolved: false, newNetwork: false,
        hostname: d[6], hostnameSource: "dns",
        networkKey: v6 ? "2001:db8:40::/48" : d[0].replace(/\.\d+$/, ".0/24"), seenAt: 100000 + inode
      };
      conns.push(conn);
      connections[conn.id] = conn;
      total += 1;
    }
    var app = {
      id: r[0], name: r[1], icon: "", desktop: "", system: false, pids: [2000 + i],
      traffic: { id: r[0], txBytes: r[4] * 240, rxBytes: r[5] * 240, txRate: r[4], rxRate: r[5], measured: conns.length, tcp: conns.length },
      connections: conns, unresolved: 0, lastActivity: 100000 + i,
      spark: [r[5] * 0.2, r[5] * 0.5, r[5] * 0.35, r[5] * 0.8, r[5] * 0.6, r[5], r[5] * 0.7, r[5] * 0.9],
      blocked: r[3], mechanism: r[3] ? "app" : ""
    };
    apps[app.id] = app;
    ordered.push(app);
    if (r[3]) blocked[app.id] = { mechanism: "app" };
  }
  return {
    revision: 1, hello: true, coverage: "TCP + connected UDP", rdns: true,
    connections: connections, apps: apps, ordered: ordered, count: total,
    historyApps: {}, historyOrdered: [], historyCount: 0, sourceCount: total,
    pulse: false, pulseNetwork: "", awayKeys: [], digestText: "", blocked: blocked, lastError: ""
  };
}

// The connections the map draws an arc to: the ones with somewhere to draw it.
function arcs(model) {
  var out = [];
  for (var k in model.connections) {
    var c = model.connections[k];
    if (c && c.country && !(c.lat === 0 && c.lon === 0))
      out.push(c);
  }
  return out;
}

var models = {
  empty: modelWith(0),
  populated: modelWith(8),
  many: modelWith(20),
  showcase: showcase()
};
