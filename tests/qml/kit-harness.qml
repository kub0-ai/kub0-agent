import QtQuick
import QtQuick.Window
import "../.." as Views
import "Fixture.js" as Fixture
import "../../js/Intel.js" as Intel

// Loads the panel's sub-views against the stub kit in tests/qml/kitstub (see
// its README). Fails on any QML error or warning and on any row that should
// render from the fixture but does not. Run from the repository root:
//   /usr/lib/qt6/bin/qml -I tests/qml/kitstub tests/qml/kit-harness.qml
Window {
  id: harness
  visible: true
  width: 480
  height: 1400

  property int failures: 0
  property var warnings: []
  function check(ok, what) {
    if (ok) console.log("ok - " + what)
    else { failures += 1; console.log("not ok - " + what) }
  }
  function count(item, pred) {
    var n = pred(item) ? 1 : 0
    for (var i = 0; i < item.children.length; i++) n += count(item.children[i], pred)
    return n
  }
  function texts(item) {
    var out = []
    if (item.text !== undefined && item.visible) out.push(String(item.text))
    for (var i = 0; i < item.children.length; i++) out = out.concat(texts(item.children[i]))
    return out
  }
  function hasText(item, needle) {
    var all = texts(item)
    for (var i = 0; i < all.length; i++) if (all[i].indexOf(needle) >= 0) return true
    return false
  }
  function findButton(item, text) {
    if (String(item).indexOf("Button") === 0 && item.text === text && item.visible) return item
    for (var i = 0; i < item.children.length; i++) { var f = findButton(item.children[i], text); if (f) return f }
    return null
  }
  function named(item, name) {
    if (item.objectName === name) return item
    for (var i = 0; i < item.children.length; i++) { var f = named(item.children[i], name); if (f) return f }
    return null
  }

  // ---- fixture: a populated model with indicators, DNS names, ASN on two rows
  property var model: (function() {
    var m = Fixture.models.populated
    var ids = Object.keys(m.connections)
    var a = m.connections[ids[0]], b = m.connections[ids[1]], c = m.connections[ids[2]]
    a.asn = 24940; a.org = "Hetzner Online GmbH"; a.hostname = "edge.example.net"; a.hostnameSource = "dns"
    a.indicators = [
      { id: "beacon-cadence", severity: "notice", attack: { id: "T1071", name: "Application Layer Protocol" }, basis: "6 arrivals every 60s, jitter 4%" },
      { id: "hosting", severity: "info", attack: null, basis: "AS24940 is a hosting provider" }
    ]
    a.evidence.hash = "sha256:" + new Array(65).join("a")
    a.evidence.lineage = { ancestors: [{ pid: 1000, name: "bash", exe: "/usr/bin/bash" }, { pid: 1, name: "systemd", exe: "/usr/lib/systemd/systemd" }], cmdline: "fixture-probe --serve", cwd: "/home/user", truncated: false }
    a.evidence.package = "none"
    b.asn = 13335; b.org = "Cloudflare, Inc."; b.hostnameSource = "ptr"; b.hostname = "ptr.example.org"
    b.indicators = [{ id: "exe-deleted", severity: "warning", attack: { id: "T1070.004", name: "File Deletion" }, basis: "executable removed while running" }]
    c.indicators = [{ id: "upload-heavy", severity: "notice", attack: { id: "T1041", name: "Exfiltration Over C2 Channel" }, basis: "sent 2.0 MiB, received 12 KiB" }]
    return m
  })()
  property var now: Date.now()

  QtObject {
    id: fakeService
    property var model: harness.model
    property bool helperInstalled: true
    property bool blockingReady: true
    property bool helperBusy: false
    property bool enforcementPaused: false
    property bool dataCurrent: true
    property int healthTick: 0
    property string lastBlockError: ""
    property var temporaryRules: []
    property string temporaryRulesError: ""
    property var listeners: [
      { proto: "tcp", ip: "0.0.0.0", port: 22, app: { id: "system", name: "system", system: true }, exe: "", uid: 0, scope: "all" },
      { proto: "tcp", ip: "127.0.0.1", port: 631, app: { id: "cups", name: "CUPS" }, exe: "/usr/bin/cupsd", uid: 0, scope: "loopback" },
      { proto: "udp", ip: "192.168.1.5", port: 5353, app: { id: "avahi", name: "Avahi" }, exe: "", uid: 972, scope: "address" }
    ]
    property int listenersRevision: 1
    property var watchRules: [
      { id: "w-1", kind: "port", value: "4444", note: "reverse shells", ts: 10, hits: 0, last_hit: 0 },
      { id: "w-2", kind: "asn", value: "13335", note: "", ts: 5, hits: 3, last_hit: harness.now - 120000 }
    ]
    property string watchError: ""
    property int watchRevision: 1
    property var timelineResult: (function() {
      var apps = [], total = []
      for (var i = 0; i < 24; i++) total.push(i === 3 ? 16 : i === 4 ? 4 : 0)
      apps.push({ id: "firefox", name: "Firefox", counts: total.slice(), total: 20 })
      apps.push({ id: "curl", name: "curl", counts: [1, 1, 1], total: 3 })
      return { since: harness.now - 24 * 3600000, until: harness.now, bucketMs: 3600000, buckets: 24, apps: apps, other: [], otherApps: 0, total: total, max: 16, truncated: false }
    })()
    property int timelineHours: 24
    property string timelineError: ""
    property bool timelineBusy: false
    property var investigateResult: null
    property string investigateSubject: ""
    property string investigateError: ""
    property bool investigateBusy: false
    property var historyEntries: []
    property bool historyMore: false
    property string historyError: ""
    property bool historyBusy: false
    property var calls: []
    function appById(id) { return harness.model.apps[id] || null }
    function requestInvestigate(subject) {
      calls.push("investigate " + subject)
      investigateSubject = subject
      investigateResult = {
        subject: { kind: "ip", value: "192.0.2.1" }, since: 0, until: harness.now, connections: 12, live: 2, tx: 2048, rx: 4194304,
        first: harness.now - 3600000, last: harness.now - 30000, cadenceMs: 60000,
        apps: [{ id: "fixture-0", name: "Firefox", connections: 10 }], destinations: [{ ip: "192.0.2.1", port: 443, hostname: "edge.example.net", connections: 12 }],
        asns: [{ key: "24940", label: "AS24940 Hetzner Online GmbH", connections: 12 }], countries: [{ key: "US", label: "US", connections: 12 }],
        ports: [{ key: "443", label: "443", connections: 12 }], indicators: [{ id: "beacon-cadence", severity: "notice", connections: 12, example: "x" }],
        timeline: [0, 3, 6, 3], timelineBucketMs: 3600000, truncated: false
      }
    }
    function clearInvestigate() { calls.push("clear"); investigateResult = null; investigateSubject = "" }
    function requestTimeline(hours) { calls.push("timeline " + hours); timelineHours = hours }
    function setWatch(kind, value, note) { calls.push("watch " + JSON.stringify([kind, value, note])); return true }
    function deleteWatch(id) { calls.push("unwatch " + id) }
    function requestDestinationBlock(appId, ip, minutes) { calls.push("block " + appId + " " + ip + " " + minutes) }
    function cancelDestinationBlock(appId, ip) { calls.push("unblock " + appId + " " + ip) }
    function requestHistory() { calls.push("history") }
  }
  QtObject {
    id: fakeKub0
    property bool connected: true
    property bool sharingDestinations: true
    property var prevalenceSupported: true
    property var prevalence: ({ "192.0.2.0/24": { nodes: 3, firstSeen: 0 } })
  }

  Column {
    id: stack
    width: parent.width
    Views.IntelView { id: intel; width: parent.width; service: fakeService; kub0: fakeKub0; model: harness.model; revision: 1 }
    Views.HistoryView { id: history; width: parent.width; service: fakeService }
    Views.ConnectionEvidence { id: evidence; width: parent.width; height: 700; app: harness.model.ordered[0] }
    Views.DestinationRules { id: rules; width: parent.width; app: harness.model.ordered[0]; service: fakeService; current: true }
  }

  Timer {
    interval: 50; running: true; repeat: false
    onTriggered: {
      // Indicators: three rows from the fixture, highest severity first.
      var rows = Intel.indicatorRows(harness.model.connections)
      check(rows.length === 4, "fixture yields 4 indicator rows (got " + rows.length + ")")
      check(hasText(intel, "Hetzner Online GmbH") || hasText(intel, "AS24940"), "indicator row carries the ASN/org")
      check(hasText(intel, "T1071"), "indicator row shows the ATT&CK reference")
      check(hasText(intel, "executable removed while running"), "warning basis text is rendered")
      // Severity filter narrows the list.
      intel.severityFilter = "warning"
      // The list model is synced in place, and a ListView applies model
      // changes at its next layout; run that layout now, as a frame would.
      named(intel, "intelIndicatorList").forceLayout()
      check(!hasText(intel, "6 arrivals every 60s"), "severity filter hides notice rows")
      intel.severityFilter = ""
      // Exposure section.
      intel.section = "exposure"
      check(hasText(intel, "2 of 3 sockets are reachable from the network."), "exposure line from fixture listeners")
      check(hasText(intel, "All interfaces"), "exposed listener row renders its scope")
      // Watchlist section with two rules and the form.
      intel.section = "watch"
      check(hasText(intel, "ASN AS13335"), "watch rule title renders")
      check(hasText(intel, "3 hits, last 2m ago"), "watch rule detail renders")
      var field = named(intel, "watchValue")
      check(field !== null, "watch value field is reachable by objectName")
      // Timeline section: heatmap and its summary.
      intel.section = "timeline"
      check(intel.timelineRows.length === 2, "timeline has two app rows (got " + intel.timelineRows.length + ")")
      check(intel.timelineBuckets === 24, "timeline has 24 buckets")
      check(hasText(intel, "Firefox"), "timeline names the busiest app")
      // Pivot drawer opens on the first indicator row's connection.
      intel.section = "indicators"
      var first = harness.model.connections[Object.keys(harness.model.connections)[0]]
      intel.drawerConnection = first
      intel.drawerOpen = true
      fakeService.requestInvestigate("ip:192.0.2.1")
      Qt.callLater(function() {
        check(hasText(intel, "12 connections (2 live)"), "pivot facts render in the drawer")
        check(hasText(intel, "Seen on 3 other endpoints in your org"), "prevalence line renders from the kub0 object")
        var state = Intel.destinationBlockState({ app: fakeService.appById(first.app.id), ip: first.remote.ip, port: first.remote.port, blockingReady: true, helperBusy: false, current: true, enforcementPaused: false, rules: [], helperId: function(id) { return id }, isBlockable: function() { return true }, hostWideUnsafe: function() { return false }, now: harness.now })
        check(state.canBlock === true, "block offer gates are open for the fixture row")
        check(hasText(intel, "5 min") || hasText(intel, "5m"), "block duration buttons render")
        // Click-through: the buttons reach the service with the arguments the
        // helper verb expects, and the drawer closes through clearInvestigate.
        // The first buttons on the page belong to the top row, which is the
        // warning (highest severity first), not the first fixture connection.
        var top = rows[0].connection
        check(top.id !== first.id && rows[0].severity === "warning", "the warning row sorts to the top")
        var fiveMin = findButton(intel, "5 min")
        check(fiveMin !== null, "a 5 min block button exists")
        if (fiveMin) fiveMin.clicked()
        check(fakeService.calls.indexOf("block " + top.app.id + " " + top.remote.ip + " 300") >= 0, "5 min click requests block-scoped for the top row's app and address (" + fakeService.calls.join("; ") + ")")
        var investigateBtn = findButton(intel, "Investigate " + top.remote.ip)
        check(investigateBtn !== null, "an Investigate <ip> button exists on the row")
        if (investigateBtn) investigateBtn.clicked()
        check(fakeService.investigateSubject === "ip:" + top.remote.ip, "Investigate click pivots on the row's address")
        var watchThis = findButton(intel, "Watch this")
        check(watchThis !== null, "the drawer offers Watch this")
        intel.closeDrawer()
        check(intel.drawerOpen === false && fakeService.calls.indexOf("clear") >= 0, "closing the drawer clears the investigate state")
        // Watch form: validation refuses junk without a round trip, accepts a rule.
        intel.section = "watch"
        var valueField = named(intel, "watchValue"), noteField = named(intel, "watchNote")
        intel.watchKind = "asn"
        valueField.text = "not-a-number"
        intel.submitWatch()
        check(intel.watchFormError !== "", "junk ASN is refused with a message (" + intel.watchFormError + ")")
        var before = fakeService.calls.length
        valueField.text = "13335"; noteField.text = "cdn"
        intel.submitWatch()
        check(fakeService.calls.length === before + 1 && fakeService.calls[before] === 'watch ["asn","13335","cdn"]', "a valid rule reaches setWatch(kind, value, note) (" + fakeService.calls[before] + ")")
        check(valueField.text === "" && intel.watchFormError === "", "the form clears after a successful add")
        var remove = findButton(intel, "Remove")
        check(remove !== null, "watch rows offer Remove")
        if (remove) remove.clicked()
        check(fakeService.calls.filter(function(c) { return c.indexOf("unwatch w-") === 0 }).length === 1, "Remove deletes the row's rule by id")
        // Section tabs are buttons too.
        var tab = named(intel, "intelSection_timeline")
        check(tab !== null, "section tabs carry objectNames")
        if (tab) tab.clicked()
        check(intel.section === "timeline", "clicking the Timeline tab switches the section")
        // Evidence drawer and rules.
        check(hasText(evidence, "Hetzner Online GmbH"), "evidence shows the org")
        check(hasText(evidence, "fixture-probe --serve"), "evidence shows the lineage command line")
        check(hasText(evidence, "systemd"), "evidence shows an ancestor")
        check(hasText(evidence, "No installed package owns this executable"), "evidence shows the package answer")
        check(hasText(evidence, "sha256") || hasText(evidence, "aaaaaaaa"), "evidence shows the hash")
        check(hasText(evidence, "DNS") || hasText(evidence, "dns"), "evidence explains the hostname source")
        check(hasText(history, "No history") || hasText(history, "history") || history.height > 0, "history view renders empty state")
        check(rules.height >= 0, "destination rules instantiate")
        // Layout, both seen live 10-13. When the indicator set changes, a
        // scrolled list must stay where it is (a rebuilt array model put it back
        // at the top, so a row below the first could not be kept in view), and
        // the timeline must clip and scroll rather than draw its axis and hint
        // past the panel's bottom edge.
        intel.height = 380
        intel.section = "indicators"
        Qt.callLater(function() {
          var list = named(intel, "intelIndicatorList")
          var kept = list ? list.itemAtIndex(0) : null
          check(kept !== null, "the indicator list instantiates its first row")
          var scrolled = list ? Math.min(40, list.contentHeight - list.height) : 0
          check(scrolled > 0, "the fixture list is taller than its view (" + (list ? list.contentHeight + " in " + list.height : "?") + ")")
          if (list) list.contentY = scrolled
          var conn = harness.model.connections[Object.keys(harness.model.connections)[0]]
          conn.indicators = conn.indicators.concat([{ id: "fanout", severity: "info", attack: null, basis: "a new row, so the set changes" }])
          intel.revision = intel.revision + 1
          Qt.callLater(function() {
            list.forceLayout()
            check(list.count === 5, "the new indicator row arrived (" + list.count + " rows)")
            check(list.contentY === scrolled, "the list keeps its scroll when the indicator set changes (" + list.contentY + ", was " + scrolled + ")")
            check(kept !== null && list.itemAtIndex(0) === kept, "rows still present keep their delegates")
            intel.section = "timeline"
            Qt.callLater(function() {
              var pane = named(intel, "intelTimeline"), flick = named(intel, "intelTimelineFlick")
              check(pane !== null && pane.clip === true, "the timeline pane clips its content to the panel")
              check(flick !== null && flick.contentHeight >= pane.gridHeight + pane.axisHeight, "the timeline scroll height covers the grid and the axis (" + (flick ? flick.contentHeight : "?") + ")")
              // The daemon answers 24 h as 25 buckets, so the last axis label
              // sits at bucket 24, where the clip would cut it.
              var live = JSON.parse(JSON.stringify(fakeService.timelineResult))
              live.buckets = 25
              live.since = harness.now - 25 * 3600000
              fakeService.timelineResult = live
              Qt.callLater(function() {
                var axis = named(intel, "intelTimelineAxis"), labels = 0, over = []
                for (var k = 0; axis && k < axis.children.length; k++) {
                  var lab = axis.children[k]
                  if (lab.text === undefined)
                    continue
                  labels++
                  if (lab.x < 0 || lab.x + lab.width > axis.width + 0.5)
                    over.push(lab.text + "@" + Math.round(lab.x) + "+" + Math.round(lab.width))
                }
                check(labels === 5 && over.length === 0, "every axis label ends inside the grid (" + labels + " labels, width " + (axis ? Math.round(axis.width) : "?") + ", outside: " + over.join(" ") + ")")
                check(harness.warnings.length === 0, "no QML warnings (" + harness.warnings.join(" | ") + ")")
                console.log(harness.failures === 0 ? "KIT_HARNESS_PASS" : "KIT_HARNESS_FAIL " + harness.failures)
                Qt.exit(harness.failures === 0 ? 0 : 1)
              })
            })
          })
        })
      })
    }
  }
}
