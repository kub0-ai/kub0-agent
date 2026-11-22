import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "ConnectionModel.js" as ConnectionModel
import "js/Health.js" as Health
import "js/Activity.js" as Activity
import "js/Kub0.js" as Kub0
import "js/Prefs.js" as Prefs
import "js/Scroll.js" as Scroll
import "js/Ux.js" as Ux
import "js/Peers.js" as Peers
import "js/Traffic.js" as Traffic
import "js/Intel.js" as Intel
import "js/Setup.js" as Setup

Panel {
  id: root
  moduleName: "ai.kub0.agent"
  manageIpc: false

  property var anchorItem: null
  property var hostWidget: null
  property var vallum: null
  property var service: null
  property var shell: null
  property var manifest: null
  property string pluginDir: ""

  property string searchQuery: ""
  property string sortKey: "name"
  property string filterKey: "all"
  property string selectedAppId: ""
  property bool searchOpen: false
  property bool confirmIps: false
  property string pendingBlockApp: ""
  property string panelView: "overview"
  property string viewBeforeSettings: "overview"
  property bool destinationPopupOpen: false
  property var evidenceApp: null

  readonly property var viewOrder: ["overview", "apps", "intel", "history", "endpoints"]

  // Preferences live on the service, which outlives this panel. Reading them
  // through a binding means an edit made here is reflected immediately and a
  // reopened panel picks up whatever is on disk.
  readonly property var prefs: liveVallum && liveVallum.prefs
    ? liveVallum.prefs : Prefs.defaults()
  readonly property bool confirmBlocks: prefs.confirmBlocks === true
  readonly property bool showWorldMap: prefs.showWorldMap === true
  // Font sizes and the gap multiplier for this panel and its sub-views: the
  // kit's sizes times the textSize and density preferences (js/Ux.js). Every
  // text here reads root.ux.<size>; every gap is Style.space(N * root.ux.gap).
  // It also carries the timeStyle and byteUnits preferences as `time` and
  // `bytes`, which every formatter in js/ takes as its optional last argument.
  readonly property var ux: Ux.metrics(Style.font, prefs.textSize, prefs.density, prefs.timeStyle, prefs.byteUnits)
  // Handed to every WheelStep in the panel and its sub-views.
  readonly property string scrollSpeed: prefs.scrollSpeed || "normal"
  readonly property bool scrollMomentum: prefs.scrollMomentum !== false

  // Destination sharing as the service has it: the system daemon's setting
  // when the panel reads that daemon, else the panel's own preference.
  readonly property bool sharingDestinations: liveVallum && liveVallum.sharingDestinations !== undefined
    ? liveVallum.sharingDestinations === true : prefs.shareDestinations === true

  function setSharing(on) {
    if (liveVallum && typeof liveVallum.setSharing === "function")
      liveVallum.setSharing(on)
    else
      setPref("shareDestinations", on === true)
  }

  function setPref(key, value) {
    if (liveVallum && typeof liveVallum.setPref === "function")
      liveVallum.setPref(key, value)
  }

  // ---------------------------------------------------- spacing rhythm
  //
  // This panel used to spend 22 of its 38 spacing values on a single number.
  // A flat scale gives a section header, a list row and a caption identical
  // separation, so nothing groups and the eye has no hierarchy to follow —
  // which reads as "cramped" even when the total density is fine.
  //
  // Four tiers, applied by MEANING rather than by how much room is left:
  // things that belong together sit closer than things that do not, and the
  // gap ABOVE a heading is larger than the gap below it, so the heading
  // attaches to the content it introduces instead of floating between blocks.
  readonly property int padTight: Style.space(4 * root.ux.gap)     // a label and its own caption
  readonly property int padGroup: Style.space(10 * root.ux.gap)    // sibling rows within one group
  readonly property int padSection: Style.space(20 * root.ux.gap)  // between groups
  readonly property int padEdge: Style.space(14 * root.ux.gap)     // content to panel edge

  readonly property var barIdentity: hostWidget || root
  readonly property var liveBar: bar || (shell && shell.bar ? shell.bar : null)
  readonly property var liveVallum: vallum || service || (hostWidget && hostWidget.vallum ? hostWidget.vallum : null)
  readonly property color fg: liveBar && liveBar.foreground !== undefined
    ? liveBar.foreground : Commons.Color.foreground
  readonly property color accent: Commons.Color.accent
  // Three state colours, named once. They existed only as an inline
  // `liveBar.urgent ?: "#e25c5c"` repeated at four call sites, so anything that
  // was not an error had no colour at all and every state read the same weight.
  // Each defers to the bar's theme when it publishes one, and falls back to a
  // literal otherwise — same shape as the urgent expression it replaces.
  readonly property color badColor: liveBar && liveBar.urgent ? liveBar.urgent : Commons.Color.urgent
  // Attention, not failure: "helper not installed" is a thing to fix, not a
  // thing that is broken, and painting it the same red as a failed heartbeat
  // spends the alarm colour until it stops meaning anything.
  readonly property color warnColor: liveBar && liveBar.warning ? liveBar.warning : Commons.Color.accent
  readonly property color okColor: accent
  readonly property string fontFamily: liveBar && liveBar.fontFamily
    ? liveBar.fontFamily : Style.font.family
  // The panel is kept loaded while closed (BarWidget's Loader), and every
  // derived list, count and map arc below is keyed on these counters. Read
  // straight through, they re-ran all of it two or three times a second on
  // the shell's UI thread for a panel nobody could see. While closed they
  // hold at -1; opening moves them to the live value, which recomputes
  // everything once, fresh.
  readonly property int modelRev: opened && liveVallum ? liveVallum.modelRevision : -1
  readonly property string monitoring: liveVallum ? String(liveVallum.monitoring || "") : "unavailable"
  readonly property bool dataCurrent: liveVallum ? liveVallum.dataCurrent === true : false
  readonly property bool snapshotReady: liveVallum ? liveVallum.snapshotReady === true : false
  readonly property bool isDemo: monitoring === "demo"
  readonly property int healthTick: opened && liveVallum ? (liveVallum.healthTick || 0) : -1
  readonly property string observationAgeText: {
    var _t = healthTick
    if (!liveVallum)
      return ""
    if (liveVallum.observationAgeText)
      return String(liveVallum.observationAgeText)
    var ms = liveVallum.observationAgeMs
    if (typeof ms !== "number" || ms <= 0)
      return ""
    return Health.formatAge(ms)
  }
  readonly property var apps: {
    var _r = modelRev
    var _s = sortKey
    var _f = filterKey
    if (!liveVallum)
      return []
    var m = liveVallum.model
    return blockedFirst(ConnectionModel.filterApps(ConnectionModel.orderRows(m.ordered || [], _s), searchQuery, _f))
  }
  readonly property int liveCount: {
    var _r = modelRev
    return liveVallum && liveVallum.model ? (liveVallum.model.count || 0) : 0
  }
  readonly property int liveApps: {
    var _r = modelRev
    return liveVallum && liveVallum.model && liveVallum.model.ordered ? liveVallum.model.ordered.length : 0
  }
  readonly property int historyCount: {
    var _r = modelRev
    return liveVallum && liveVallum.model ? (liveVallum.model.historyCount || 0) : 0
  }
  readonly property var historyApps: {
    var _r = modelRev
    if (!liveVallum)
      return []
    return liveVallum.model.historyOrdered || []
  }
  readonly property int activityRev: opened && liveVallum ? (liveVallum.activityRevision || 0) : -1
  readonly property var activityEntries: {
    var _r = activityRev
    return liveVallum && liveVallum.activityEntries ? liveVallum.activityEntries : []
  }
  readonly property var sessionBlocks: {
    var _r = modelRev
    if (!liveVallum || !liveVallum.model || !liveVallum.model.blocked)
      return []
    var out = []
    var b = liveVallum.model.blocked
    for (var k in b) {
      if (b[k])
        out.push({ id: k, mechanism: b[k].mechanism || "" })
    }
    return out
  }
  readonly property int kub0Rev: liveVallum ? (liveVallum.kub0Revision || 0) : 0
  readonly property var kub0: {
    var _k = kub0Rev
    if (liveVallum && liveVallum.kub0)
      return liveVallum.kub0
    return Kub0.emptyKub0()
  }
  readonly property bool kub0Connected: {
    var _k = kub0Rev
    var k = root.kub0
    if (k && k.connected === true)
      return true
    return liveVallum && liveVallum.connectState === "connected"
  }
  readonly property string connectState: liveVallum ? String(liveVallum.connectState || "idle") : "idle"
  readonly property string connectCode: liveVallum ? String(liveVallum.connectCode || "") : ""
  readonly property string connectUrl: liveVallum ? String(liveVallum.connectUrl || "") : ""
  readonly property var connectExpiresAt: liveVallum ? (liveVallum.connectExpiresAt || 0) : 0
  readonly property string connectError: liveVallum ? String(liveVallum.connectError || "") : ""
  readonly property bool helperInstalled: liveVallum ? liveVallum.helperInstalled === true : false
  readonly property bool polkitAgentPresent: liveVallum ? liveVallum.polkitAgentPresent === true : false
  readonly property bool blockingToolsReady: liveVallum ? liveVallum.blockingToolsReady === true : false
  readonly property bool enforcementPaused: liveVallum ? liveVallum.enforcementPaused === true : false
  readonly property var hostBlocks: {
    var _r = modelRev
    if (!liveVallum || !liveVallum.model || !liveVallum.model.blocked)
      return []
    var out = []
    var b = liveVallum.model.blocked
    for (var k in b) {
      if (!b[k])
        continue
      var app = liveVallum.appById ? liveVallum.appById(k) : null
      out.push({
        id: k,
        name: (app && app.name) ? app.name : k,
        mechanism: b[k].mechanism || ""
      })
    }
    return out
  }
  // Every rule of every org network policy, flattened for one Repeater. Each rule's
  // label already names its policy (netpolicy::rule_label in the daemon).
  readonly property var kub0Enforcement: {
    var k = root.kub0
    return k ? k.netpolicyEnforcement : null
  }
  readonly property var kub0NetRules: {
    var out = []
    var k = root.kub0
    var ps = k && k.netpolicies ? k.netpolicies : []
    for (var i = 0; i < ps.length; i++) {
      var rs = ps[i].rules || []
      for (var j = 0; j < rs.length; j++)
        out.push(rs[j])
    }
    return out
  }
  readonly property var denylistMatchApps: {
    var _r = modelRev
    var _k = kub0Rev
    var apps = liveVallum && liveVallum.model && liveVallum.model.ordered
      ? liveVallum.model.ordered
      : []
    var list = root.kub0 && root.kub0.denylist ? root.kub0.denylist : []
    return Kub0.denylistMatches(apps, list)
  }
  readonly property var arcs: {
    var _r = modelRev
    if (!dataCurrent)
      return []
    return liveVallum && liveVallum.drawableArcs ? liveVallum.drawableArcs() : []
  }
  readonly property string digest: liveVallum ? (liveVallum.digestText || "") : ""
  readonly property string coverage: liveVallum ? liveVallum.coverage : "TCP + connected UDP"
  readonly property bool blockingReady: liveVallum ? liveVallum.blockingReady === true : false
  // Helper-reported blockingReady (status JSON), not the UI composite above.
  readonly property bool helperStatusFailed: liveVallum ? liveVallum.helperStatusFailed === true : true
  readonly property int helperBlockCount: liveVallum && typeof liveVallum.helperBlockCount === "number"
    ? liveVallum.helperBlockCount : 0
  readonly property int liveBlockCount: {
    var _r = modelRev
    var helperN = helperBlockCount
    var sessionN = sessionBlocks.length
    return sessionN > helperN ? sessionN : helperN
  }
  readonly property string heroMeta: {
    var s = Health.heroPosture({
      helperInstalled: helperInstalled,
      helperStatusFailed: helperStatusFailed,
      blockingReady: blockingToolsReady,
      paused: enforcementPaused,
      blockCount: liveBlockCount
    })
    if (s === "Paused")
      return "Paused"
    if (s === "Blocks recorded")
      return "Blocks recorded"
    if (s === "Active")
      return "Active"
    if (s === "Inactive")
      return "Inactive"
    return "Not installed"
  }
  readonly property string heroDetail: {
    var _r = modelRev
    // The meta line already says PAUSED; a "Blocking" chip beside it would
    // contradict it, so the chip steps aside while a pause rule is live.
    if (enforcementPaused)
      return ""
    return blockingToolsReady ? "Blocking" : "Monitor only"
  }
  // Which peer is being named right now, keyed by networkKey so the editor
  // survives a snapshot arriving mid-type: the daemon rebroadcasts the whole
  // connection list on every tag, and an index-keyed editor would jump rows.
  property string namingKey: ""
  property string namingDraft: ""
  // Whether the peer being named already carries a name, which is what makes
  // "Clear" worth offering. Captured at beginNaming: the editor lives outside
  // the peer Repeater, so it cannot read the peer's modelData.
  property bool namingHadTag: false
  property string namingKind: "service"
  readonly property string blockHint: liveVallum ? (liveVallum.blockHint || "") : ""
  readonly property bool needsHelperInstall: liveVallum ? liveVallum.needsHelperInstall === true : false
  readonly property bool needsBlockingPackages: liveVallum ? liveVallum.needsBlockingPackages === true : false
  readonly property bool helperInstallPending: liveVallum ? liveVallum.helperInstallPending === true : false
  readonly property bool needsDaemonBuild: liveVallum
    ? (liveVallum.daemonStatus === "missing" && liveVallum.usingFallback !== true)
    : false
  // What stands between this panel and a daemon it can read ("install",
  // "relogin", "group", "unreachable", or "" when nothing does), and the notice
  // for a panel and a daemon of different versions (null when they match).
  readonly property string setupStage: liveVallum ? String(liveVallum.setupStage || "") : ""
  readonly property var versionSkew: liveVallum && liveVallum.versionSkew ? liveVallum.versionSkew : null
  readonly property string panelVersion: liveVallum ? String(liveVallum.panelVersion || "") : ""
  readonly property string hoverLabel: map.hoverArc ? hoverText(map.hoverArc) : ""
  readonly property string pendingIpsApp: liveVallum ? (liveVallum.pendingIpsApp || "") : ""
  readonly property string lastBlockError: liveVallum ? (liveVallum.lastBlockError || "") : ""
  readonly property bool offerBinds: liveVallum ? liveVallum.offerBinds === true : false
  readonly property string offerNote: liveVallum ? (liveVallum.offerNote || "") : ""
  property int selectedIndex: -1
  readonly property string appsHeaderText: {
    var _r = modelRev
    return "Apps  " + liveBlockCount + " with block records of " + liveApps
  }
  readonly property var topCountries: {
    var _r = modelRev
    var counts = {}
    var cons = liveVallum && liveVallum.model && liveVallum.model.connections
      ? liveVallum.model.connections
      : {}
    var k
    for (k in cons) {
      var c = cons[k]
      if (!c || !c.country)
        continue
      if (!ConnectionModel.isLive(c))
        continue
      var cc = String(c.country)
      counts[cc] = (counts[cc] || 0) + 1
    }
    var arr = []
    for (k in counts)
      arr.push({ country: k, n: counts[k] })
    arr.sort(function (a, b) {
      if (b.n !== a.n)
        return b.n - a.n
      return String(a.country).localeCompare(String(b.country))
    })
    if (arr.length > 5)
      arr = arr.slice(0, 5)
    return arr
  }
  // What the Top destinations Repeater is built from: codes only, reassigned
  // only when the top five or their order actually change. Built from
  // topCountries directly, every connection that moved a count handed the
  // Repeater a new array, which destroys and recreates every row -- and a
  // click whose press and release straddle that lands on a MouseArea that no
  // longer exists, so it does nothing. Counts are read live per row instead.
  property var topCountryCodes: []
  readonly property var topCountryCounts: {
    var out = {}
    var cs = topCountries || []
    for (var i = 0; i < cs.length; i++)
      out[cs[i].country] = cs[i].n
    return out
  }
  onTopCountriesChanged: {
    var codes = (topCountries || []).map(function (c) { return c.country })
    if (codes.join(",") !== topCountryCodes.join(","))
      topCountryCodes = codes
  }
  readonly property var activityDigest: {
    var _r = activityRev
    var _q = searchQuery
    return Activity.digestEntries(activityEntries, _q, 4, root.ux, Date.now())
  }

  // Keyboard cursor over Overview action rows. PanelKeyCatcher steals Tab /
  // Enter / Space (Keys.BeforeItem) unless we handle those signals here, so
  // this is the focus, not Qt's tab chain.
  //
  // It names the row, not its position. The row list grows and shrinks with
  // live data (0-5 countries, the setup row, actionable activity), so an
  // index pointed at a different row the moment a country appeared, and
  // Enter then did something else. Checking a name is also free, where every
  // row's highlight used to rebuild the whole id list to compare positions.
  property string overviewFocusId: ""
  property string overviewReveal: ""

  onServiceChanged: {
    if (service && !vallum)
      vallum = service
    if (service && service.pluginDir)
      pluginDir = service.pluginDir
  }

  // What the ListView actually renders. `apps` is the source; this is synced
  // from it in place and never rebound. See the ListView comment for why
  // binding a fresh JS array straight to `model` was the scroll bug.
  ListModel {
    id: appModel
    // One `app` role per row, holding the plain JS object the model layer
    // already builds. dynamicRoles is what lets a role hold an object and its
    // arrays (connections, spark) rather than ListModel flattening them.
    dynamicRoles: true
  }

  // True while the user is pointing at, typing into, scrolling, or
  // keyboard-navigating the list.
  //
  // Structural changes—insert, remove, move—are held back while this is true.
  // Hover is a commitment signal: the row under the pointer carries a block
  // toggle, so a row that moves out from under a click already in flight fires
  // a privileged action on the wrong application. The same misfire happens if
  // the list reorders under a wheel/flick or while the user is walking the
  // highlight with the keyboard, so those also hold for 1500 ms after the last
  // contentY or Up/Down/PageUp/PageDown/Home/End event. Value updates are NOT
  // held, so counts, flags and sparklines keep running while the geometry
  // stays put.
  //
  // A user-initiated sort/filter change is not a background sample: it is the
  // user asking for a new order, so applySortFilter clears pendingResync and
  // reconciles immediately.
  property bool listHold: false
  property bool userResync: false
  property bool syncingRows: false
  readonly property bool listEngaged: (listHover ? listHover.hovered : false) || searchOpen || listHold
  property bool pendingResync: false
  // The query the rows last reconciled against. Typing is a user-initiated
  // filter change, like applySortFilter, but it reaches syncRows through the
  // `apps` binding as if it were a background sample, and a focused field
  // sets searchOpen, so listEngaged holds it back. The rows then kept every
  // app until the field lost focus while the chips counted the matches, and
  // Up/Down walked the stale rows. A query that moved since the last sync
  // reconciles now. (A signal handler on searchQuery cannot do it: it can
  // run before `apps` re-evaluates and reconcile against the old list.)
  property string syncedQuery: ""

  Timer {
    id: listHoldTimer
    interval: 1500
    repeat: false
    onTriggered: root.listHold = false
  }

  Timer {
    id: enforcementScrollTimer
    interval: 16
    repeat: false
    onTriggered: {
      if (typeof panelFlick === "undefined" || !panelFlick)
        return
      if (typeof enforcementHead === "undefined" || !enforcementHead)
        return
      var maxY = Math.max(0, panelFlick.contentHeight - panelFlick.height)
      panelFlick.contentY = Math.max(0, Math.min(enforcementHead.y, maxY))
    }
  }

  function bumpListHold() {
    listHold = true
    listHoldTimer.restart()
  }

  function blockedFirst(rows) {
    if (!rows || !rows.length)
      return rows || []
    var blocked = []
    var rest = []
    var i
    for (i = 0; i < rows.length; i++) {
      if (rows[i] && rows[i].blocked === true)
        blocked.push(rows[i])
      else
        rest.push(rows[i])
    }
    return blocked.concat(rest)
  }

  onListEngagedChanged: {
    if (!listEngaged) {
      if (pendingResync)
        syncRows()
    }
  }

  // Hand the model a FRESH object every time, never the one it already holds.
  //
  // setProperty with an identical reference does not fire the delegate's
  // appDataChanged, so nothing bound to appData.* re-evaluates — while
  // appModel.get(i) happily reports the new value. The two disagree, and only
  // the bindings are what the user sees.
  //
  // That is not theoretical. ConnectionModel.setBlocked deliberately mutates
  // the existing app object so a privileged click registers immediately instead
  // of waiting for the next daemon sample; syncRows then handed that same
  // object straight back. The ToggleSwitch stayed visually OFF while the model
  // read blocked=true — so the user's second click, resolved against the model,
  // sent UNBLOCK. Click twice, silently undo the block. The tick path has the
  // same shape: sampleSparklines pushes onto the same spark array, so the
  // sparkline froze at its last full-rebuild paint.
  //
  // A new identity per sample costs one shallow copy per row (tens of rows,
  // twice a second) and makes the whole class unreachable regardless of who
  // mutates what. Pinned by tests/test_row_sync.qml.
  function rowFor(a) {
    var out = {}
    for (var k in a)
      out[k] = a[k]
    return out
  }

  function syncRows() {
    syncingRows = true
    var src = apps || []
    var i, j, cur

    var structural = appModel.count !== src.length
    if (!structural) {
      for (i = 0; i < src.length; i++) {
        if (appModel.get(i).app.id !== src[i].id) {
          structural = true
          break
        }
      }
    }

    if (structural && listEngaged && !userResync && searchQuery === syncedQuery) {
      pendingResync = true
      var byId = {}
      for (i = 0; i < src.length; i++)
        byId[src[i].id] = src[i]
      for (i = 0; i < appModel.count; i++) {
        cur = appModel.get(i).app
        if (byId[cur.id])
          appModel.setProperty(i, "app", rowFor(byId[cur.id]))
      }
      syncingRows = false
      return
    }
    pendingResync = false
    syncedQuery = searchQuery

    if (!structural) {
      for (i = 0; i < src.length; i++)
        appModel.setProperty(i, "app", rowFor(src[i]))
      syncingRows = false
      return
    }

    // Reconcile keyed by id, so a row that did not change keeps its delegate —
    // and with it the panel's scroll offset, the hover state, and the
    // sparkline's paint. Quadratic, over a list that is tens of rows.
    var want = {}
    for (i = 0; i < src.length; i++)
      want[src[i].id] = true
    for (i = appModel.count - 1; i >= 0; i--) {
      if (!want[appModel.get(i).app.id])
        appModel.remove(i)
    }
    for (i = 0; i < src.length; i++) {
      var at = -1
      for (j = i; j < appModel.count; j++) {
        if (appModel.get(j).app.id === src[i].id) {
          at = j
          break
        }
      }
      if (at === -1)
        appModel.insert(i, { app: rowFor(src[i]) })
      else {
        if (at !== i)
          appModel.move(at, i, 1)
        appModel.setProperty(i, "app", rowFor(src[i]))
      }
    }
    syncingRows = false
  }

  function filterChipCount(key) {
    if (!liveVallum || !liveVallum.model)
      return 0
    return ConnectionModel.filterApps(liveVallum.model.ordered || [], searchQuery, key).length
  }

  function applySortFilter(nextSort, nextFilter) {
    userResync = true
    sortKey = nextSort
    filterKey = nextFilter
    pendingResync = false
    syncRows()
    userResync = false
    selectedAppId = Health.retainSelectedId(selectedAppId, visibleAppIds())
    syncSelectionToRendered()
  }

  // The s/f shortcuts persist their result. A sort you picked and then lost on
  // the next open is the same complaint as a list that resets under you, and
  // the Settings screen would disagree with the live view until the next edit.
  function cycleSort() {
    var keys = Prefs.SORT_KEYS
    var i = keys.indexOf(sortKey)
    if (i < 0)
      i = 0
    var next = keys[(i + 1) % keys.length]
    setPref("sortKey", next)
    applySortFilter(next, filterKey)
  }

  function cycleFilter() {
    var keys = Prefs.FILTER_KEYS
    var i = keys.indexOf(filterKey)
    if (i < 0)
      i = 0
    var next = keys[(i + 1) % keys.length]
    setPref("filterKey", next)
    applySortFilter(sortKey, next)
  }

  function pageStep() {
    if (!appList || appList.height <= 0)
      return 5
    return Math.max(1, Math.floor(appList.height / Style.space(40)) - 1)
  }

  function syncSelectionToRendered() {
    var i
    var n = renderedLen()
    for (i = 0; i < n; i++) {
      var a = renderedAppAt(i)
      if (a && a.id === selectedAppId) {
        selectedIndex = i
        return
      }
    }
    if (selectedIndex >= n)
      selectedIndex = Math.max(0, n - 1)
  }

  onAppsChanged: {
    syncRows()
    selectedAppId = Health.retainSelectedId(selectedAppId, visibleAppIds())
    syncSelectionToRendered()
  }

  Component.onCompleted: syncRows()

  function idInApps(id) {
    var i
    var n = renderedLen()
    for (i = 0; i < n; i++) {
      var a = renderedAppAt(i)
      if (a && a.id === id)
        return true
    }
    return false
  }

  function open(payloadJson) {
    var _p = payloadJson
    if (service && !vallum)
      vallum = service
    if (liveVallum && liveVallum.markLooked)
      liveVallum.markLooked()
    searchQuery = ""
    searchOpen = false
    cancelIps()
    if (!selectedAppId) {
      var first = null
      if (typeof appModel !== "undefined" && appModel && typeof appModel.get === "function" && appModel.count)
        first = appModel.get(0) && appModel.get(0).app
      else if (apps && apps.length)
        first = apps[0]
      if (first)
        selectedAppId = first.id
    }
    root.controller.show()
  }

  function close(arg) {
    var _a = arg
    cancelIps()
    searchOpen = false
    if (liveVallum && liveVallum.markClosed)
      liveVallum.markClosed()
    root.controller.hide()
  }

  function closeForPopoutSwitch() {
    popoutSwitchClosing = true
    close()
    Qt.callLater(function() { popoutSwitchClosing = false })
  }

  function toggle(arg) {
    if (root.opened)
      root.close()
    else
      root.open(arg && String(arg).length ? arg : "{}")
  }

  function ping(arg) {
    return "ok"
  }

  // Apply preferences at open, and remember the view at close.
  //
  // Sort and filter are applied through applySortFilter rather than assigned,
  // because they feed the rendered model and the selection has to be
  // re-resolved against it — assigning the properties alone leaves the
  // selection pointing at a row that is no longer where it was.
  onOpenedChanged: {
    root.evidenceApp = null
    root.destinationPopupOpen = false
    if (root.opened) {
      var p = root.prefs
      root.panelView = Prefs.openingView(p)
      if (p.sortKey !== root.sortKey || p.filterKey !== root.filterKey)
        root.applySortFilter(p.sortKey, p.filterKey)
    } else if (root.prefs.startupView === "last") {
      root.setPref("lastView", root.panelView)
    }
  }

  function switchPanel(direction) {
    if (root.liveBar && typeof root.liveBar.switchPanelFrom === "function")
      return root.liveBar.switchPanelFrom(root.barIdentity, direction)
    return false
  }

  function hoverText(c) {
    if (!c)
      return ""
    var app = c.app && c.app.name ? c.app.name : "?"
    var ip = c.remote && c.remote.ip ? c.remote.ip : ""
    var port = c.remote && c.remote.port ? c.remote.port : ""
    var flag = c.country ? c.country : ""
    return app + " → " + ip + (port ? ":" + port : "") + (flag ? ", " + flag : "")
  }

  // Both of these index the RENDERED list, not `apps`.
  //
  // While a structural resync is deferred (listEngaged), `apps` and what is on
  // screen legitimately disagree. Resolving a selection against `apps` would
  // then highlight one row and block a different application — the worst
  // possible outcome for a privileged toggle. The row the user can see is the
  // only honest answer to "which one is selected".
  //
  // Node tests extract these functions without a QML ListModel, so they fall
  // back to `apps` only when `appModel` is absent.
  function renderedLen() {
    if (typeof appModel !== "undefined" && appModel && typeof appModel.count === "number")
      return appModel.count
    return (apps && apps.length) ? apps.length : 0
  }

  function renderedAppAt(i) {
    if (typeof appModel !== "undefined" && appModel && typeof appModel.get === "function") {
      var row = appModel.get(i)
      return row && row.app ? row.app : null
    }
    return (apps && apps[i]) ? apps[i] : null
  }

  function selectedApp() {
    if (!selectedAppId)
      return null
    var i
    var n = renderedLen()
    for (i = 0; i < n; i++) {
      var a = renderedAppAt(i)
      if (a && a.id === selectedAppId)
        return a
    }
    if (liveVallum && liveVallum.appById)
      return liveVallum.appById(selectedAppId)
    return null
  }

  // One query drives both views' lists, but each view shows its own field,
  // and only while searchOpen. So a query typed in Apps went on filtering
  // Overview's "Recent activity" ("Nothing matches.") with no field on screen
  // to show why, or to clear it. A search belongs to the view it was typed in.
  onPanelViewChanged: {
    searchOpen = false
    searchQuery = ""
  }

  function selectView(name) {
    root.evidenceApp = null
    if (viewOrder.indexOf(name) < 0)
      return
    if (panelView === "settings")
      viewBeforeSettings = name
    if (panelView !== name)
      searchOpen = false
    panelView = name
    if (name !== "overview") {
      overviewFocusId = ""
      overviewReveal = ""
    }
    if (typeof overviewFlick !== "undefined" && overviewFlick)
      overviewFlick.contentY = 0
    if (typeof panelFlick !== "undefined" && panelFlick)
      panelFlick.contentY = 0
  }

  function toggleSettings() {
    if (panelView === "settings")
      panelView = viewOrder.indexOf(viewBeforeSettings) >= 0 ? viewBeforeSettings : "overview"
    else {
      viewBeforeSettings = viewOrder.indexOf(panelView) >= 0 ? panelView : "overview"
      searchOpen = false
      overviewFocusId = ""
      panelView = "settings"
    }
    if (typeof overviewFlick !== "undefined" && overviewFlick)
      overviewFlick.contentY = 0
    if (typeof panelFlick !== "undefined" && panelFlick)
      panelFlick.contentY = 0
  }

  // Indicator counts over the current rows, for the Overview line. Keyed on
  // modelRev like every other derived list so a closed panel computes nothing.
  readonly property var intelCounts: {
    var _r = modelRev
    if (!liveVallum || !liveVallum.model)
      return { warning: 0, notice: 0, info: 0, total: 0 }
    return Intel.summarize(Intel.indicatorRows(liveVallum.model.connections || {}))
  }
  readonly property int intelWarningCount: intelCounts.warning
  readonly property int intelListenerCount: {
    var _r = opened && liveVallum ? liveVallum.listenersRevision : -1
    if (!liveVallum || !liveVallum.listeners)
      return 0
    var n = 0
    var l = liveVallum.listeners
    for (var i = 0; i < l.length; i++)
      if (l[i] && l[i].scope !== "loopback")
        n += 1
    return n
  }

  function intelPostureText() {
    var c = intelCounts
    var parts = []
    if (c.warning > 0)
      parts.push(c.warning === 1 ? "1 warning" : c.warning + " warnings")
    if (c.notice > 0)
      parts.push(c.notice === 1 ? "1 notice" : c.notice + " notices")
    var head = parts.length ? parts.join(", ") + " on current connections" : "No indicators on current connections"
    var n = intelListenerCount
    var tail = n === 0 ? "" : (n === 1 ? "; 1 socket reachable from the network" : "; " + n + " sockets reachable from the network")
    return head + tail
  }

  function enforcementPostureText() {
    var n = liveBlockCount
    if (enforcementPaused) {
      if (n <= 0)
        return "Enforcement is paused on this host"
      return n === 1
        ? "Enforcement is paused: 1 app's block applies when you turn it back on"
        : ("Enforcement is paused: " + n + " apps' blocks apply when you turn it back on")
    }
    if (n <= 0)
      return "No apps have a recorded block on this host"
    return n === 1
      ? "1 app has a recorded block on this host"
      : (n + " apps have a recorded block on this host")
  }

  function overviewActionIds() {
    var ids = ["connections", "blocked", "enforcement", "intel"]
    if (setupStage !== "install" && (needsHelperInstall || needsBlockingPackages))
      ids.push("setup")
    var cs = topCountries || []
    var i
    for (i = 0; i < cs.length; i++)
      ids.push("country:" + cs[i].country)
    ids.push("activitySearch")
    var dig = activityDigest || []
    for (i = 0; i < dig.length; i++) {
      if (dig[i] && dig[i].appId)
        ids.push("activity:" + dig[i].id)
    }
    // No "appsHeader" tail any more. The ring walks the things this view can
    // act on; switching view is the header's job and the arrow keys'.
    return ids
  }

  function overviewFocused(id) {
    return overviewFocusId !== "" && overviewFocusId === id
  }

  function focusOverviewId(id) {
    if (overviewActionIds().indexOf(id) >= 0)
      overviewFocusId = id
  }

  function moveOverviewFocus(dy) {
    var ids = overviewActionIds()
    if (!ids.length)
      return false
    // A focused row that has since gone (a country dropped out) restarts
    // from the end the key points away from, as with no focus at all.
    var i = ids.indexOf(overviewFocusId)
    if (i < 0)
      i = dy > 0 ? 0 : ids.length - 1
    else
      i += dy
    if (i < 0 || i >= ids.length)
      return false
    overviewFocusId = ids[i]
    return true
  }

  function connectionRevealLines() {
    var _r = modelRev
    var out = []
    if (!liveVallum || !liveVallum.model)
      return out
    var cons = liveVallum.model.connections || {}
    var k
    for (k in cons) {
      var c = cons[k]
      if (!c || !ConnectionModel.isLive(c))
        continue
      var app = c.app && c.app.name ? String(c.app.name) : "?"
      var ip = c.remote && c.remote.ip ? String(c.remote.ip) : ""
      var port = c.remote && c.remote.port ? (":" + c.remote.port) : ""
      var flag = c.country ? String(c.country) : ""
      out.push(app + " → " + ip + port + (flag ? ", " + flag : ""))
      if (out.length >= 4)
        break
    }
    if (out.length === 0)
      out.push("No live connections right now.")
    return out
  }

  function countryRevealLines(cc) {
    var _r = modelRev
    var out = []
    if (!liveVallum || !liveVallum.model)
      return out
    var want = String(cc)
    var cons = liveVallum.model.connections || {}
    var k
    for (k in cons) {
      var c = cons[k]
      if (!c || String(c.country || "") !== want || !ConnectionModel.isLive(c))
        continue
      var app = c.app && c.app.name ? String(c.app.name) : "?"
      var ip = c.remote && c.remote.ip ? String(c.remote.ip) : ""
      var port = c.remote && c.remote.port ? (":" + c.remote.port) : ""
      out.push(app + " → " + ip + port)
      if (out.length >= 4)
        break
    }
    if (out.length === 0)
      out.push("No live connections in " + want + " right now.")
    return out
  }

  function openBlockedList() {
    searchQuery = ""
    searchOpen = false
    applySortFilter(sortKey, "blocked")
    selectView("apps")
  }

  function openEnforcementSection() {
    if (panelView !== "settings") {
      viewBeforeSettings = viewOrder.indexOf(panelView) >= 0 ? panelView : "overview"
      searchOpen = false
      overviewFocusId = ""
      overviewReveal = ""
      panelView = "settings"
    }
    enforcementScrollTimer.restart()
  }

  function activateOverviewFocus() {
    if (overviewActionIds().indexOf(overviewFocusId) < 0)
      return
    activateOverviewId(overviewFocusId)
  }

  function activateOverviewId(id) {
    focusOverviewId(id)
    if (id === "connections") {
      overviewReveal = overviewReveal === "connections" ? "" : "connections"
      return
    }
    if (id === "blocked") {
      openBlockedList()
      return
    }
    if (id === "enforcement") {
      openEnforcementSection()
      return
    }
    if (id === "setup") {
      toggleSettings()
      return
    }
    if (id === "intel") {
      selectView("intel")
      return
    }
    if (id === "activitySearch") {
      searchOpen = true
      Qt.callLater(function() {
        if (activitySearchField)
          activitySearchField.forceActiveFocus()
      })
      return
    }
    if (id.indexOf("country:") === 0) {
      overviewReveal = overviewReveal === id ? "" : id
      return
    }
    if (id.indexOf("activity:") === 0) {
      var key = id.slice(9)
      var row = null
      for (var n = 0; n < (activityDigest || []).length; n++) {
        if (activityDigest[n].id === key)
          row = activityDigest[n]
      }
      if (row && row.appId) {
        searchQuery = ""
        searchOpen = false
        applySortFilter(sortKey, "all")
        selectedAppId = row.appId
        selectView("apps")
      }
    }
  }

  function moveView(dx) {
    // Reach the same views as the header; Settings stays on its own control.
    if (dx === 0 || panelView === "settings")
      return
    var index = Math.max(0, viewOrder.indexOf(panelView))
    selectView(viewOrder[Math.max(0, Math.min(viewOrder.length - 1, index + (dx > 0 ? 1 : -1)))])
  }

  function moveSelection(dy) {
    var useModel = typeof appModel !== "undefined" && appModel && typeof appModel.get === "function"
    var n = useModel ? appModel.count : ((apps && apps.length) ? apps.length : 0)
    if (n === 0)
      return // keep the current id when the filtered list is empty
    var i = selectedIndex
    if (i < 0)
      i = 0
    i = Math.max(0, Math.min(n - 1, i + dy))
    var target = null
    if (useModel) {
      var row = appModel.get(i)
      target = row && row.app ? row.app : null
    } else {
      target = apps[i]
    }
    if (!target)
      return
    selectedAppId = target.id
    selectedIndex = i
    if (appList)
      appList.positionViewAtIndex(i, ListView.Contain)
  }

  function acceptSearch() {
    var target = Health.acceptSearchSelection(selectedAppId, visibleAppIds())
    selectedAppId = target
  }

  function canStartBlock(a) {
    return !!(a && ConnectionModel.isBlockable(a) && blockingReady && dataCurrent && !a.blocked)
  }

  function canUnblock(a) {
    var id = a && a.id ? a.id : selectedAppId
    if (!id || !blockingReady || !liveVallum || !liveVallum.model || !liveVallum.model.blocked)
      return false
    return !!(liveVallum.model.blocked && Object.prototype.hasOwnProperty.call(liveVallum.model.blocked, id) && liveVallum.model.blocked[id])
  }

  function sessionKnownIds() {
    var out = []
    var i
    for (i = 0; i < sessionBlocks.length; i++) {
      if (sessionBlocks[i] && sessionBlocks[i].id)
        out.push(sessionBlocks[i].id)
    }
    return out
  }

  function visibleAppIds() {
    var out = []
    var i, a, row
    var useModel = typeof appModel !== "undefined" && appModel && typeof appModel.get === "function"
    var n = useModel ? appModel.count : ((apps && apps.length) ? apps.length : 0)
    for (i = 0; i < n; i++) {
      if (useModel) {
        row = appModel.get(i)
        a = row && row.app ? row.app : null
      } else {
        a = apps[i]
      }
      if (a && a.id)
        out.push(a.id)
    }
    return out
  }

  function toggleSelectedBlock() {
    if (!liveVallum || (panelView !== "apps" && panelView !== "overview"))
      return
    var id = selectedAppId
    // The four sections share one scroll, so the shortcut cannot key off a
    // hidden tab id. Health.blockShortcutAllowed still decides, with the
    // apps-list rule tried first (confirm-guarded) and the blocked-list
    // unblock rule as fallback.
    if (Health.blockShortcutAllowed("apps", id, visibleAppIds(), sessionKnownIds())) {
      var a = selectedApp()
      if (canUnblock(a) || canStartBlock(a))
        requestBlockGuarded(id)
      return
    }
    if (Health.blockShortcutAllowed("protection", id, visibleAppIds(), sessionKnownIds())) {
      if (canUnblock({ id: id }))
        liveVallum.requestBlock(id)
    }
  }

  // Every block/unblock from the UI funnels through here.
  //
  // The confirmation guards ONLY the blocking direction. Confirming an unblock
  // would put a speed bump on the way back out of a block, which is the same
  // trapdoor shape as a block that deletes its own unblock control — the exit
  // from a restrictive state must always be cheaper than the entrance.
  function requestBlockGuarded(id) {
    if (!liveVallum || !id)
      return
    var already = canUnblock({ id: id })
    if (already || !confirmBlocks) {
      liveVallum.requestBlock(id)
      return
    }
    pendingBlockApp = id
  }

  function blockConfirmName() {
    var a = liveVallum && liveVallum.appById ? liveVallum.appById(pendingBlockApp) : null
    return (a && a.name) ? a.name : pendingBlockApp
  }

  // The executables the block moves. A name is whatever joined the row; this
  // is what actually runs. ConfirmDialog renders PlainText, so a path is safe.
  function blockConfirmPrograms() {
    var a = liveVallum && liveVallum.appById ? liveVallum.appById(pendingBlockApp) : null
    var line = ConnectionModel.blockProgramsLine(a)
    return line ? line + "\n\n" : ""
  }

  function confirmPendingBlock() {
    var id = pendingBlockApp
    pendingBlockApp = ""
    if (liveVallum && id)
      liveVallum.requestBlock(id)
  }

  function cancelPendingBlock() {
    pendingBlockApp = ""
  }

  function confirmIpsBlock() {
    if (!liveVallum || !pendingIpsApp) {
      confirmIps = false
      return
    }
    var id = pendingIpsApp
    if (!ConnectionModel.isBlockable(liveVallum.appById ? liveVallum.appById(id) : { id: id })) {
      confirmIps = false
      liveVallum.pendingIpsApp = ""
      return
    }
    liveVallum.requestBlockIps(id)
    confirmIps = false
    if (liveVallum.pendingIpsApp)
      liveVallum.pendingIpsApp = ""
  }

  function cancelIps() {
    confirmIps = false
    if (liveVallum)
      liveVallum.pendingIpsApp = ""
  }

  function monitoringHeadline() {
    if (!liveVallum)
      return "Waiting for the kub0 service"
    if (isDemo)
      return "DEMO—replay fixture, not this machine"
    if (monitoring === "current")
      return liveCount === 0 ? "Receiving updates—idle" : "Receiving updates"
    if (monitoring === "stale")
      return observationAgeText
        ? ("Last-known data, " + observationAgeText + "—not live")
        : "Last-known data—not live"
    if (monitoring === "awaiting_snapshot")
      return observationAgeText
        ? ("Waiting for a snapshot—last-known " + observationAgeText)
        : "Waiting for an authoritative snapshot"
    if (monitoring === "connecting")
      return observationAgeText
        ? ("Connecting—last-known " + observationAgeText)
        : "Connecting to kub0d"
    if (monitoring === "unavailable" || liveVallum.daemonStatus === "missing")
      return observationAgeText
        ? ("kub0d is not available—last-known " + observationAgeText)
        : "kub0d is not available"
    return String(liveVallum.barLabel || monitoring)
  }

  function coverageText() {
    return "Sampler coverage: " + coverage + ". Unconnected UDP, including most QUIC, is listed as unresolved and is not drawn. Receiving updates is not full capture and is not automatic protection."
  }

  function connectCountdown() {
    var _t = healthTick
    var exp = connectExpiresAt
    if (!exp)
      return ""
    var left = Math.max(0, Math.floor((exp - Date.now()) / 1000))
    var m = Math.floor(left / 60)
    var s = left % 60
    return m + ":" + (s < 10 ? "0" : "") + s
  }

  function heartbeatAgeText() {
    var _t = healthTick
    var ts = root.kub0 && root.kub0.lastHeartbeatTs ? root.kub0.lastHeartbeatTs : 0
    if (!ts)
      return "never"
    return Health.formatAge(Math.max(0, Date.now() - ts))
  }

  // Settings state is a set of independent facts, so it is rendered as rows of
  // label + value, not as one middot-joined sentence. A middot run forces the eye
  // to parse a sentence to find one value, gives no column to scan down, has
  // nowhere to hang a state colour, and reads as an inert menu. Each helper returns [{label, value, tone}]; tone is
  // "ok" | "bad" | "warn" | "" and only ever colours the VALUE, so the labels stay
  // a quiet column. A fact with no value yields "—" rather than being dropped:
  // "we do not know" is itself worth a row.
  function helperFacts() {
    return [
      { label: "Helper", value: root.helperInstalled ? "installed" : "not installed",
        tone: root.helperInstalled ? "ok" : "warn" },
      { label: "Polkit agent", value: root.polkitAgentPresent ? "present" : "missing",
        tone: root.polkitAgentPresent ? "ok" : "warn" },
      { label: "nft + conntrack", value: root.blockingToolsReady ? "ready" : "missing",
        tone: root.blockingToolsReady ? "ok" : "warn" }
    ]
  }

  // factRows: each Settings fact list is a fresh array on every evaluation,
  // and the heartbeat row's "12s ago" re-evaluates it every health tick. As a
  // Repeater model that destroyed and rebuilt every row several times a
  // second. The Repeaters now count rows and each row binds to its own entry,
  // so values update in place and rows only change when the count does.
  readonly property var endpointFactRows: endpointFacts()
  readonly property var helperFactRows: helperFacts()
  readonly property var fleetFactRows: fleetFacts()
  readonly property var execGateFactRows: Kub0.execGateFacts(root.kub0)
  // Newest five matches and the trusted list, for the Settings exec-gate section.
  readonly property var execGateRecent: root.kub0 && root.kub0.execGate && root.kub0.execGate.denies
    ? root.kub0.execGate.denies.slice(0, 5) : []
  readonly property var execGateTrusted: root.kub0 && root.kub0.execGate && root.kub0.execGate.trusted
    ? root.kub0.execGate.trusted : []
  readonly property var keyboardFactRows: keyboardFacts()

  function endpointFacts() {
    var k = root.kub0
    var ok = k && k.lastHeartbeatOk === true
    var failed = k && k.lastHeartbeatOk === false
    var org = k && typeof k.orgEndpoints === "number" ? k.orgEndpoints : 0
    var limit = k && typeof k.nodeLimit === "number" ? k.nodeLimit : 0
    return [
      { label: "Account", value: (k && k.githubUsername) ? "@" + k.githubUsername : "—", tone: "" },
      { label: "Node", value: (k && k.nodeName) ? k.nodeName : "—", tone: "" },
      { label: "Heartbeat",
        value: ok ? root.heartbeatAgeText() + " ago"
             : (failed ? "failed " + root.heartbeatAgeText() + " ago" : "never"),
        tone: ok ? "ok" : (failed ? "bad" : "warn") },
      { label: "Devices in tenant", value: limit > 0 ? org + " of " + limit : String(org), tone: "" },
      { label: "Tenant-reported endpoint", value: (k && k.selfState) ? k.selfState : "—",
        tone: (k && (k.selfState === "monitoring" || k.selfState === "enforcing")) ? "ok" : "" }
    ]
  }

  // The key is the label, what it does is the value. Same shape as every other
  // fact list here, so the eye learns one pattern and reuses it.
  function keyboardFacts() {
    return [
      // Left/Right drives the header switcher (moveView). It was undocumented
      // here while the views had no visible switcher at all; now that the
      // segments are pinned in the header, the key that moves them is listed.
      { label: "←, →, h, l", value: "switch between Overview, Apps, Intel, History, and Endpoints", tone: "" },
      { label: "Tab, j, k", value: "move between Overview rows", tone: "" },
      // Scoped deliberately: onActivateRequested only acts when the view is
      // Overview, so an unqualified "activate the focused row" promised a key
      // that does nothing on Apps and on Settings.
      { label: "Enter, Space", value: "activate the focused Overview row", tone: "" },
      { label: "/", value: "search activity on Overview, apps on Apps, indicators on Intel", tone: "" },
      { label: "s", value: "cycle sort", tone: "" },
      { label: "f", value: "cycle filter", tone: "" },
      { label: "b", value: "block or unblock, when that control is shown", tone: "" },
      { label: "r", value: "refresh digest", tone: "" },
      { label: "i", value: "install, when a setup action is visible", tone: "" },
      { label: "Esc", value: "close dialogs, then the panel", tone: "" }
    ]
  }

  function fleetFacts() {
    var k = root.kub0
    var n = k && k.denylist ? k.denylist.length : 0
    var v = k && typeof k.denylistVersion === "number" ? k.denylistVersion : 0
    var m = root.denylistMatchApps ? root.denylistMatchApps.length : 0
    return [
      { label: "Rules", value: n === 1 ? "1 rule" : n + " rules", tone: "" },
      { label: "Version", value: v > 0 ? String(v) : "—", tone: "" },
      // The only row here that is about THIS machine, so it is the one that gets
      // a colour: a rule matching something you are running is the finding.
      { label: "Match this host",
        value: m === 0 ? "none" : (m === 1 ? "1 app" : m + " apps"),
        tone: m > 0 ? "warn" : "" }
    ]
  }

  // Live state in the heading, so a section answers its own question before you
  // read its rows. A header that only names the section makes the reader scan
  // the body to find out whether anything is wrong — which is most of what made
  // this screen feel like a menu rather than a status display.
  function endpointHeading() {
    if (!root.kub0Connected)
      return "kub0 endpoint: not connected"
    var k = root.kub0
    if (k && k.lastHeartbeatOk === false)
      return "kub0 endpoint: heartbeat failing"
    return "kub0 endpoint: connected"
  }

  function enforcementHeading() {
    if (!root.helperInstalled)
      return "Per-app helper: not installed"
    if (!root.blockingToolsReady)
      return "Per-app helper: tools missing"
    return root.blockingReady ? "Per-app helper: ready" : "Per-app helper: not ready"
  }

  function fleetHeading() {
    if (!root.kub0Connected)
      return "Fleet policy: not connected"
    var m = root.denylistMatchApps ? root.denylistMatchApps.length : 0
    var n = root.kub0 && root.kub0.denylist ? root.kub0.denylist.length : 0
    if (m > 0)
      return "Fleet policy: " + m + " match this host"
    return "Fleet policy: " + n + (n === 1 ? " rule" : " rules")
  }

  // The implementation facts the policy name deliberately drops. Comma-joined:
  // a row of middots reads as a menu, and this is one sentence about one rule.
  function fleetPolicyDetail(entry) {
    if (!entry)
      return ""
    var parts = []
    var matcher = (entry.comm || "") + (entry.comm && entry.path ? " " : "") + (entry.path || "")
    if (matcher)
      parts.push("matches " + matcher)
    // The real action, never a guess: the gate keys only on `block`.
    parts.push("action " + Kub0.denylistActionText(entry.action))
    if (entry.reason)
      parts.push(entry.reason)
    if (entry.promoted_by)
      parts.push("promoted by " + entry.promoted_by)
    if (entry.created_at && entry.created_at.length >= 10)
      parts.push(entry.created_at.substring(0, 10))
    return parts.join(", ")
  }

  function denylistRowHighlighted(entry) {
    var apps = liveVallum && liveVallum.model && liveVallum.model.ordered
      ? liveVallum.model.ordered
      : []
    return Kub0.denylistEntryHighlighted(entry, apps)
  }

  onPendingIpsAppChanged: {
    if (pendingIpsApp) {
      confirmIps = true
      Qt.callLater(function() {
        if (confirmDialog)
          confirmDialog.forceActiveFocus()
      })
    } else {
      confirmIps = false
      if (keyCatcher && !searchOpen)
        keyCatcher.forceActiveFocus()
    }
  }

  onPendingBlockAppChanged: {
    if (pendingBlockApp) {
      Qt.callLater(function() {
        if (blockConfirmDialog)
          blockConfirmDialog.forceActiveFocus()
      })
    } else if (keyCatcher && !searchOpen && !confirmIps) {
      keyCatcher.forceActiveFocus()
    }
  }

  onBlockingReadyChanged: {
    if (confirmIps && !blockingReady)
      cancelIps()
    // A confirmation that outlives its precondition is worse than no dialog:
    // confirming it would dispatch a block the daemon can no longer perform,
    // and the failure surfaces far from the click.
    if (pendingBlockApp && !blockingReady)
      cancelPendingBlock()
  }

  onDataCurrentChanged: {
    if (confirmIps && !dataCurrent)
      cancelIps()
    if (pendingBlockApp && !dataCurrent)
      cancelPendingBlock()
  }

  Item {
    id: summonAnchor
    width: 1
    height: 1
    visible: false
  }

  // One fact, one row: a quiet fixed label column you can scan straight down,
  // and a value that carries the state colour. Deliberately NOT interactive —
  // these state a fact and have nothing to activate, and giving an inert row a
  // hover and a focus stop teaches the keyboard ring to stop on things that do
  // nothing. Rows that DO act stay OverviewRow.
  component FactRow: Item {
    property string label: ""
    property string value: ""
    property string tone: ""
    // Missing is a fact. Rendering nothing would silently drop the row and make
    // "unknown" indistinguishable from "not applicable here".
    readonly property string shownValue: value && value.length > 0 ? value : "—"
    width: parent ? parent.width : 0
    implicitHeight: Math.max(labelText.implicitHeight, valueText.implicitHeight)
    Text {
      id: labelText
      anchors.left: parent.left
      anchors.top: parent.top
      width: Math.min(parent.width * 0.42, Style.space(150))
      text: label
      textFormat: Text.PlainText
      color: Qt.darker(root.fg, 1.6)
      font.family: root.fontFamily
      font.pixelSize: root.ux.bodySmall
      elide: Text.ElideRight
    }
    Text {
      id: valueText
      anchors.left: labelText.right
      anchors.leftMargin: Style.space(8)
      anchors.right: parent.right
      anchors.top: parent.top
      text: shownValue
      textFormat: Text.PlainText
      color: tone === "ok" ? root.okColor
           : tone === "bad" ? root.badColor
           : tone === "warn" ? root.warnColor
           : root.fg
      font.family: root.fontFamily
      font.pixelSize: root.ux.bodySmall
      wrapMode: Text.WordWrap
    }
  }

  component OverviewRow: Rectangle {
    id: ovr
    property string actionId: ""
    property string label: ""
    property string stat: ""
    property string accessibleName: label
    property int pixelSize: root.ux.body
    property bool bold: false
    property color labelColor: root.fg
    property bool wrap: true
    signal activated()

    width: parent ? parent.width : 0
    implicitWidth: ovr.stat !== "" ? ovrStatCol.implicitWidth : ovrLabel.implicitWidth
    implicitHeight: ovr.stat !== "" ? ovrStatCol.implicitHeight : ovrLabel.implicitHeight
    height: implicitHeight
    radius: Style.cornerRadius
    color: (ovrMouse.containsMouse || root.overviewFocused(ovr.actionId))
      ? Style.hoverFillFor(root.fg, root.accent) : "transparent"

    Accessible.role: Accessible.Button
    Accessible.name: ovr.accessibleName
    Accessible.onPressAction: ovr.activated()

    Text {
      id: ovrLabel
      visible: ovr.stat === ""
      width: parent.width
      text: ovr.label
      textFormat: Text.PlainText
      color: ovr.labelColor
      font.family: root.fontFamily
      font.pixelSize: ovr.pixelSize
      font.bold: ovr.bold
      wrapMode: ovr.wrap ? Text.WordWrap : Text.NoWrap
      elide: ovr.wrap ? Text.ElideNone : Text.ElideRight
    }
    Column {
      id: ovrStatCol
      visible: ovr.stat !== ""
      width: parent.width
      Text {
        text: ovr.stat
        textFormat: Text.PlainText
        color: ovr.labelColor
        font.family: root.fontFamily
        font.pixelSize: root.ux.display
        font.bold: true
      }
      Text {
        text: ovr.label
        textFormat: Text.PlainText
        color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.62)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
      }
    }
    MouseArea {
      id: ovrMouse
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onClicked: ovr.activated()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: root.anchorItem ? root.anchorItem : summonAnchor
    owner: root.barIdentity
    bar: root.liveBar
    centerOnBar: !root.anchorItem
    open: root.opened
    focusTarget: root.pendingBlockApp !== ""
      ? blockConfirmDialog
      : (root.confirmIps ? confirmDialog : keyCatcher)
    // The panelWidth and panelHeight preferences. The kit fits both to the
    // screen, which is what makes "Full screen" a plain large number.
    contentWidth: panel.fittedContentWidth(Style.space(Ux.panelWidthUnits(root.prefs.panelWidth)))
    contentHeight: panel.fittedContentHeight(Style.space(Ux.panelHeightUnits(root.prefs.panelHeight)))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      // `namingKey` belongs here for the same reason `searchOpen` does: while a
      // text field holds focus the catcher must let keys through to it. The kit
      // spells this out (Ui/PanelKeyCatcher.qml:28, "set `blocked:
      // editor.activeFocus`") and naming was the one editor left off the list —
      // so Return reached onActivateRequested, which does nothing on Apps, and
      // the typed name was discarded; Escape reached onCloseRequested and shut
      // the whole panel instead of cancelling the rename.
      blocked: root.searchOpen || root.confirmIps
        || root.destinationPopupOpen
        || root.evidenceApp !== null
        || root.pendingBlockApp !== "" || root.namingKey !== ""
        || (root.panelView === "history" && historyView.searchFocused)
        || (root.panelView === "intel" && intelView.searchFocused)
        || (root.panelView === "endpoints" && endpointsView.searchFocused)

      onMoveRequested: function(dx, dy) {
        if (root.confirmIps)
          return
        if (dx !== 0)
          root.moveView(dx)
        if (dy !== 0 && root.panelView === "apps") {
          root.moveSelection(dy)
          root.bumpListHold()
        } else if (dy !== 0 && root.panelView === "overview" && !root.searchOpen) {
          root.moveOverviewFocus(dy)
        }
      }
      onActivateRequested: function() {
        if (root.panelView === "overview" && !root.searchOpen)
          root.activateOverviewFocus()
      }
      onCloseRequested: {
        if (root.pendingBlockApp)
          root.cancelPendingBlock()
        else if (root.confirmIps)
          root.cancelIps()
        else if (root.panelView === "intel" && intelView.drawerOpen)
          intelView.closeDrawer()
        else if (root.panelView === "intel" && intelView.severityFilter)
          intelView.severityFilter = ""
        else if (root.panelView === "endpoints" && endpointsView.selectedName)
          endpointsView.selectedName = ""
        else if (root.panelView === "endpoints" && endpointsView.stateFilter)
          endpointsView.stateFilter = ""
        else if (root.searchOpen) {
          root.searchOpen = false
          root.searchQuery = ""
        } else {
          root.close()
        }
      }
      onTabRequested: function(direction) {
        if (root.pendingBlockApp)
          root.cancelPendingBlock()
        if (root.confirmIps)
          root.cancelIps()
        if (root.panelView === "overview" && !root.searchOpen && root.moveOverviewFocus(direction))
          return
        root.switchPanel(direction)
      }
      onTextKey: function(t) {
        if (root.confirmIps || root.pendingBlockApp)
          return
        if ((t === "b" || t === "B") && (root.panelView === "apps" || root.panelView === "overview")) {
          root.toggleSelectedBlock()
        } else if ((t === "s" || t === "S") && root.panelView === "apps") {
          root.cycleSort()
        } else if ((t === "f" || t === "F") && root.panelView === "apps") {
          root.cycleFilter()
        } else if (t === "/") {
          if (root.panelView === "history") {
            historyView.focusSearch()
          } else if (root.panelView === "intel") {
            intelView.focusSearch()
          } else if (root.panelView === "endpoints") {
            endpointsView.focusSearch()
          } else if (root.panelView === "overview") {
            root.searchOpen = true
            Qt.callLater(function() {
              if (activitySearchField)
                activitySearchField.forceActiveFocus()
            })
          } else {
            root.selectView("apps")
            root.searchOpen = true
            Qt.callLater(function() {
              if (searchField)
                searchField.forceActiveFocus()
            })
          }
        } else if (t === "r" || t === "R") {
          if (root.liveVallum && root.liveVallum.markLooked)
            root.liveVallum.markLooked()
        } else if (t === "i" || t === "I") {
          if (root.setupStage === "install")
            root.launchReleaseInstall()
          else if (root.needsHelperInstall)
            root.launchHelperInstall()
          else if (root.needsDaemonBuild)
            root.launchDaemonBuild()
          else if (root.needsBlockingPackages)
            root.launchPackageInstall()
        }
      }

      Item {
        anchors.fill: parent
        anchors.margins: root.padEdge

        Column {
          id: headerCol
          anchors.top: parent.top
          anchors.left: parent.left
          anchors.right: parent.right
          spacing: root.padGroup
          readonly property bool enforcementOn: root.blockingToolsReady && !root.enforcementPaused
          readonly property color heroFg: root.fg
          readonly property string heroFont: root.fontFamily
          readonly property bool settingsOpen: root.panelView === "settings"
          function toggleEnforcement() {
            console.log("kub0: power switch clicked; helper=" + root.helperInstalled
              + " tools=" + root.blockingToolsReady + " paused=" + root.enforcementPaused)
            if (!root.helperInstalled)
              root.launchHelperInstall()
            else if (!root.blockingToolsReady)
              root.launchPackageInstall()
            else if (root.liveVallum && typeof root.liveVallum.setEnforcementPaused === "function")
              root.liveVallum.setEnforcementPaused(!root.enforcementPaused)
          }
          function toggleSettings() { root.toggleSettings() }

          PanelHero {
            id: hero
            width: parent.width
            title: "kub0"
            meta: root.heroMeta
            detail: root.heroDetail
            foreground: root.fg
            fontFamily: root.fontFamily
            trailingControl: Component {
              RowLayout {
                spacing: Style.space(8 * root.ux.gap)
                Button {
                  fontSize: root.ux.body
                  // U+F0493 md-cog. This was U+F0093 md-flask — one hex digit
                  // apart in the Material block, and a flask renders cleanly
                  // enough that it reads as "some icon" rather than the wrong
                  // one. Resolve a glyph against the font's cmap, not by eye.
                  iconText: "󰒓"
                  tooltipText: "Settings"
                  foreground: headerCol.heroFg
                  fontFamily: headerCol.heroFont
                  // These three are NOT a divergence from the kit — they are
                  // the house idiom for a hero trailing icon, and omarchy's own
                  // network panel sets exactly the same three on its trailing
                  // icon buttons (Ui-relative: plugins/panels/network/Panel.qml
                  // :1118-1120, :1134-1136). They were briefly removed here on
                  // the theory that the kit default was the correct value; at
                  // the kit's 14px the gear reads lighter than the 22px
                  // ToggleSwitch beside it and than every reference panel's
                  // trailing icon. The glyph above was the real defect.
                  iconSize: root.ux.subtitle * 1.5
                  horizontalPadding: Style.space(5)
                  verticalPadding: Style.space(2 * root.ux.gap)
                  selected: headerCol.settingsOpen
                  Layout.alignment: Qt.AlignVCenter
                  onClicked: headerCol.toggleSettings()
                }
                ToggleSwitch {
                  id: powerSwitch
                  checked: headerCol.enforcementOn
                  busy: root.liveVallum ? root.liveVallum.helperBusy === true : false
                  foreground: headerCol.heroFg
                  Layout.alignment: Qt.AlignVCenter
                  onToggled: headerCol.toggleEnforcement()
                  PanelToolTip {
                    visible: powerSwitch.containsMouse
                    text: headerCol.enforcementOn ? "Enforcement on" : "Enforcement off"
                    fontFamily: headerCol.heroFont
                  }
                }
              }
            }
          }

          Text {
            visible: root.digest !== "" && root.panelView !== "settings"
            width: parent.width
            text: root.digest
            color: Qt.darker(root.fg, 1.4)
            font.family: root.fontFamily
            font.pixelSize: root.ux.bodySmall
            wrapMode: Text.WordWrap
          }

          // Navigation does not scroll.
          //
          // Reaching the app list used to mean scrolling the whole overview
          // -- world map, facts, activity, map attribution -- to reach a
          // section header pinned to the very bottom, while the route back
          // sat at the top of the next view. One destination was two clicks
          // of wheel away and the other was free. These two segments put both
          // one click from anywhere and replace both of those headers.
          //
          // The labels are deliberately the bare view names and not
          // `appsHeaderText`: that string carries live counts and rewrites
          // itself twice a second, so a segment wearing it would resize -- and
          // shove its neighbour sideways -- on every daemon sample. The count
          // stays on the Apps view's own header, inside the scroll.
          //
          // Settings is not a third segment. `viewBeforeSettings` and
          // `toggleSettings()` already model it as a mode you return from, and
          // the gear in the hero is its control; it lights up there instead.
          Row {
            spacing: Style.space(6 * root.ux.gap)

            Button {
              fontSize: root.ux.body
              text: "Overview"
              selected: root.panelView === "overview"
              foreground: headerCol.heroFg
              fontFamily: headerCol.heroFont
              onClicked: root.selectView("overview")
            }
            Button {
              fontSize: root.ux.body
              text: "Apps"
              selected: root.panelView === "apps"
              foreground: headerCol.heroFg
              fontFamily: headerCol.heroFont
              onClicked: root.selectView("apps")
            }
            Button {
              fontSize: root.ux.body
              text: "Intel"
              objectName: "intelTab"
              selected: root.panelView === "intel"
              foreground: headerCol.heroFg
              fontFamily: headerCol.heroFont
              onClicked: root.selectView("intel")
            }
            Button {
              fontSize: root.ux.body
              text: "History"
              selected: root.panelView === "history"
              foreground: headerCol.heroFg
              fontFamily: headerCol.heroFont
              onClicked: root.selectView("history")
            }
            Button {
              fontSize: root.ux.body
              text: "Endpoints"
              objectName: "endpointsTab"
              selected: root.panelView === "endpoints"
              foreground: headerCol.heroFg
              fontFamily: headerCol.heroFont
              onClicked: root.selectView("endpoints")
            }
          }

          // Fences the header from the scrolling content, the way every
          // reference panel does (agents:523, tailscale:531 -- a PanelSeparator
          // between PanelHero and the first PanelSectionHeader).
          //
          // Ours differs in one deliberate way: the hero is pinned above the
          // Flickable rather than scrolling inside it, so the protection
          // posture stays on screen while you read the connection list. That
          // is why this rule lives at the bottom of headerCol and not at the
          // top of mainCol -- it has to sit on the fixed side of the boundary.
          PanelSeparator { width: parent.width }
        }

        Item {
          id: viewHost
          anchors.top: headerCol.bottom
          anchors.bottom: parent.bottom
          anchors.left: parent.left
          anchors.right: parent.right
          anchors.topMargin: Style.space(8 * root.ux.gap)

          Shortcut {
            sequence: "PgDown"
            enabled: root.opened && root.panelView === "apps" && !root.searchOpen && !root.confirmIps
              && root.namingKey === ""
            onActivated: {
              root.moveSelection(root.pageStep())
              root.bumpListHold()
            }
          }
          Shortcut {
            sequence: "PgUp"
            enabled: root.opened && root.panelView === "apps" && !root.searchOpen && !root.confirmIps
              && root.namingKey === ""
            onActivated: {
              root.moveSelection(-root.pageStep())
              root.bumpListHold()
            }
          }
          Shortcut {
            sequence: "Home"
            enabled: root.opened && root.panelView === "apps" && !root.searchOpen && !root.confirmIps
              && root.namingKey === ""
            onActivated: {
              root.moveSelection(-root.renderedLen())
              root.bumpListHold()
            }
          }
          Shortcut {
            sequence: "End"
            enabled: root.opened && root.panelView === "apps" && !root.searchOpen && !root.confirmIps
              && root.namingKey === ""
            onActivated: {
              root.moveSelection(root.renderedLen())
              root.bumpListHold()
            }
          }

          // Two views, switched by clicking their PanelSectionHeader.
          // Overview is the default: map first, then a compact summary.
          // Apps is the only long list — its ListView fills the remaining
          // height and scrolls internally so the panel is not one unbounded
          // Flickable of every inventory row.

          Flickable {
            id: overviewFlick
            anchors.fill: parent
            visible: root.panelView === "overview"
            contentWidth: width
            contentHeight: overviewCol.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            interactive: contentHeight > height
            flickableDirection: Flickable.VerticalFlick
            onContentYChanged: {
              if (!root.syncingRows)
                root.bumpListHold()
            }
            WheelStep { flick: overviewFlick; speed: root.scrollSpeed; momentum: root.scrollMomentum }

            Column {
              id: overviewCol
              width: overviewFlick.width
              spacing: root.padGroup

              PanelSectionHeader {
                fontSize: root.ux.caption
                id: overviewHead
                width: parent.width
                text: "Overview"
                foreground: root.fg
                fontFamily: root.fontFamily
              }

              // First run. `omarchy plugin add` puts the panel here and
              // nothing else: no daemon, so nothing to show. This says what
              // is missing and offers the one step that fixes it.
              Column {
                id: firstRun
                visible: root.setupStage !== ""
                width: parent.width
                spacing: root.padTight
                Text {
                  width: parent.width
                  text: root.setupTitle()
                  textFormat: Text.PlainText
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  text: root.setupBody()
                  textFormat: Text.PlainText
                  color: Qt.darker(root.fg, 1.3)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                  wrapMode: Text.WordWrap
                }
                // A Flow, so the second button wraps under the first on a
                // narrow panel or at a large text size.
                Flow {
                  visible: root.setupStage === "install"
                  width: parent.width
                  spacing: root.padTight
                  Button {
                    fontSize: root.ux.body
                    text: "Install kub0"
                    enabled: !root.helperInstallPending
                    foreground: root.fg
                    fontFamily: root.fontFamily
                    bordered: true
                    focusable: true
                    onClicked: root.launchReleaseInstall()
                  }
                  Button {
                    fontSize: root.ux.body
                    text: "Build from source"
                    enabled: !root.helperInstallPending
                    foreground: root.fg
                    fontFamily: root.fontFamily
                    bordered: true
                    focusable: true
                    onClicked: root.launchDaemonBuild()
                  }
                }
              }

              // The panel and the daemon are installed separately. When they
              // differ, say which is behind and the command that fixes it.
              Text {
                visible: root.versionSkew !== null
                width: parent.width
                text: root.versionSkew ? (root.versionSkew.summary + " " + root.versionSkew.fix + ".") : ""
                textFormat: Text.PlainText
                color: root.warnColor
                font.family: root.fontFamily
                font.pixelSize: root.ux.bodySmall
                wrapMode: Text.WordWrap
              }

              WorldMap {
                id: map
                visible: root.showWorldMap
                width: parent.width
                height: visible ? Style.space(200) : 0
                pluginDir: root.pluginDir || (root.liveVallum ? root.liveVallum.pluginDir : "")
                worldDataPath: root.liveVallum ? root.liveVallum.worldDataPath : ""
                arcs: root.arcs
                animating: root.opened
                origin: root.liveVallum && root.liveVallum.origin ? root.liveVallum.origin : ({ lat: 48, lon: 10 })
                landColor: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.16)
                borderColor: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.28)
                oceanColor: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.04)
                accentColor: root.accent
                extraHidden: {
                  var _r = root.modelRev
                  if (!root.dataCurrent || !root.liveVallum || !root.liveVallum.model)
                    return 0
                  var n = 0
                  var cons = root.liveVallum.model.connections || {}
                  for (var k in cons) {
                    if (cons[k] && !cons[k].unresolved && cons[k].country && ConnectionModel.isLive(cons[k]))
                      n++
                  }
                  return Math.max(0, n - root.arcs.length)
                }
              }

              Text {
                visible: map.visible && map.extraHidden > 0
                text: "+" + map.extraHidden + " more not drawn"
                font.family: root.fontFamily
                font.pixelSize: root.ux.bodySmall
                color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.62)
                width: parent.width
              }

              Text {
                width: parent.width
                visible: root.hoverLabel !== "" && root.showWorldMap
                text: root.hoverLabel
                textFormat: Text.PlainText
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: root.ux.bodySmall
                elide: Text.ElideRight
              }

              Text {
                width: parent.width
                text: root.monitoringHeadline()
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: root.ux.body
                wrapMode: Text.WordWrap
              }

              Text {
                width: parent.width
                visible: root.isDemo
                text: "DEMO fixture, not this machine."
                color: root.fg
                font.family: root.fontFamily
                font.pixelSize: root.ux.bodySmall
                wrapMode: Text.WordWrap
              }

              Row {
                width: parent.width
                spacing: Style.space(12 * root.ux.gap)
                OverviewRow {
                  actionId: "connections"
                  width: (parent.width - parent.spacing) / 2
                  wrap: false
                  stat: String(root.liveCount)
                  label: root.liveCount === 1 ? "connection" : "connections"
                  accessibleName: stat + " " + label + ", show connection details"
                  onActivated: root.activateOverviewId("connections")
                }
                OverviewRow {
                  actionId: "blocked"
                  width: (parent.width - parent.spacing) / 2
                  wrap: false
                  stat: String(root.liveBlockCount)
                  // Records, not "apps blocked": the count comes from the
                  // helper's markers, which this panel cannot verify against
                  // the kernel.
                  label: root.liveBlockCount === 1 ? "block record" : "block records"
                  accessibleName: stat + " " + label + ", open the block list"
                  onActivated: root.activateOverviewId("blocked")
                }
              }

              Column {
                width: parent.width
                spacing: root.padTight
                visible: root.overviewReveal === "connections"
                Repeater {
                  model: {
                    var _r = root.modelRev
                    return root.overviewReveal === "connections" ? root.connectionRevealLines() : []
                  }
                  delegate: Text {
                    required property var modelData
                    width: overviewCol.width
                    text: modelData
                    textFormat: Text.PlainText
                    color: Qt.darker(root.fg, 1.35)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                    wrapMode: Text.WordWrap
                  }
                }
              }

              OverviewRow {
                actionId: "enforcement"
                label: root.enforcementPostureText()
                accessibleName: label + ", open enforcement in Settings"
                onActivated: root.activateOverviewId("enforcement")
              }

              // What the Intel view would show, one line, so the landing view
              // says when something is worth a look. Counts come from the same
              // rows the Intel tab lists; the row opens that tab.
              OverviewRow {
                actionId: "intel"
                label: root.intelPostureText()
                labelColor: root.intelWarningCount > 0 ? root.badColor : root.fg
                accessibleName: label + ", open Intel"
                onActivated: root.activateOverviewId("intel")
              }

              OverviewRow {
                visible: root.setupStage !== "install" && (root.needsHelperInstall || root.needsBlockingPackages)
                height: visible ? implicitHeight : 0
                actionId: "setup"
                label: "Setup actions are in Settings."
                pixelSize: root.ux.bodySmall
                labelColor: Qt.darker(root.fg, 1.35)
                accessibleName: "Setup actions are in Settings"
                onActivated: root.activateOverviewId("setup")
              }

              Column {
                width: parent.width
                spacing: root.padTight
                Text {
                  text: "Top destinations"
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  font.bold: true
                }
                Text {
                  width: parent.width
                  visible: root.topCountries.length === 0
                  text: "No destination countries yet."
                  color: Qt.darker(root.fg, 1.5)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                  wrapMode: Text.WordWrap
                }
                Repeater {
                  model: root.topCountryCodes
                  delegate: Column {
                    id: destItem
                    required property var modelData
                    readonly property string countryCode: modelData
                    readonly property int n: root.topCountryCounts[countryCode] || 0
                    readonly property string actionId: "country:" + countryCode
                    width: overviewCol.width
                    spacing: 0

                    Rectangle {
                      readonly property string rowActionId: parent.actionId
                      width: parent.width
                      height: destRow.implicitHeight
                      radius: Style.cornerRadius
                      color: (destMouse.containsMouse || root.overviewFocused(rowActionId))
                        ? Style.hoverFillFor(root.fg, root.accent) : "transparent"
                      Accessible.role: Accessible.Button
                      Accessible.name: "Destination " + destItem.countryCode + ", " + destItem.n + (destItem.n === 1 ? " connection" : " connections")
                      Accessible.onPressAction: root.activateOverviewId(rowActionId)
                      Row {
                        id: destRow
                        width: parent.width
                        spacing: Style.space(8 * root.ux.gap)
                        FlagIcon {
                          country: destItem.countryCode
                          pluginDir: root.pluginDir
                          width: 14
                          height: 10
                          anchors.verticalCenter: parent.verticalCenter
                          fallbackFill: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.22)
                          textColor: root.fg
                        }
                        Text {
                          text: destItem.countryCode + "  " + destItem.n
                          textFormat: Text.PlainText
                          color: root.fg
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.bodySmall
                          anchors.verticalCenter: parent.verticalCenter
                        }
                      }
                      MouseArea {
                        id: destMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.activateOverviewId(parent.rowActionId)
                      }
                    }
                    Repeater {
                      model: {
                        var _r = root.modelRev
                        return root.overviewReveal === parent.actionId ? root.countryRevealLines(parent.countryCode) : []
                      }
                      delegate: Text {
                        required property var modelData
                        width: overviewCol.width
                        text: modelData
                        textFormat: Text.PlainText
                        color: Qt.darker(root.fg, 1.35)
                        font.family: root.fontFamily
                        font.pixelSize: root.ux.caption
                        wrapMode: Text.WordWrap
                      }
                    }
                  }
                }
              }

              Column {
                width: parent.width
                spacing: root.padTight
                OverviewRow {
                  actionId: "activitySearch"
                  label: "Recent activity"
                  pixelSize: root.ux.caption
                  bold: true
                  labelColor: Qt.darker(root.fg, 1.4)
                  accessibleName: "Recent activity, search the timeline"
                  onActivated: root.activateOverviewId("activitySearch")
                }
                Row {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  visible: root.searchOpen && root.panelView === "overview"
                  Text {
                    text: "/"
                    color: root.accent
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.body
                    anchors.verticalCenter: parent.verticalCenter
                  }
                  TextField {
                    font.pixelSize: root.ux.body
                    id: activitySearchField
                    width: parent.width - Style.space(24)
                    foreground: root.fg
                    font.family: root.fontFamily
                    verticalPadding: Style.space(2 * root.ux.gap)
                    placeholderText: "search apps, ids, detail"
                    text: root.searchQuery
                    onTextChanged: root.searchQuery = text
                    Keys.onPressed: function(event) {
                      if (event.key === Qt.Key_Escape) {
                        root.searchOpen = false
                        root.searchQuery = ""
                        keyCatcher.forceActiveFocus()
                        event.accepted = true
                      }
                    }
                  }
                }
                Text {
                  width: parent.width
                  visible: root.activityDigest.length === 0
                  text: root.searchQuery ? "Nothing matches." : "Nothing recorded yet."
                  color: Qt.darker(root.fg, 1.5)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                  wrapMode: Text.WordWrap
                }
                Repeater {
                  model: root.activityDigest
                  delegate: Item {
                    required property var modelData
                    required property int index
                    readonly property string actionId: "activity:" + (modelData ? modelData.id : index)
                    readonly property bool actionable: !!(modelData && modelData.appId)
                    width: overviewCol.width
                    height: actLine.implicitHeight

                    Rectangle {
                      anchors.fill: parent
                      radius: Style.cornerRadius
                      visible: parent.actionable
                      color: (actMouse.containsMouse || root.overviewFocused(parent.actionId))
                        ? Style.hoverFillFor(root.fg, root.accent) : "transparent"
                      Accessible.role: Accessible.Button
                      Accessible.name: parent.actionable ? ((modelData.line || "") + ", open app") : ""
                      Accessible.ignored: !parent.actionable
                      Accessible.onPressAction: if (parent.actionable) root.activateOverviewId(parent.actionId)
                    }
                    Text {
                      id: actLine
                      width: parent.width
                      text: modelData && modelData.line ? modelData.line : ""
                      textFormat: Text.PlainText
                      color: Qt.darker(root.fg, 1.25)
                      font.family: root.fontFamily
                      font.pixelSize: root.ux.caption
                      elide: Text.ElideRight
                    }
                    MouseArea {
                      id: actMouse
                      anchors.fill: parent
                      enabled: parent.actionable
                      hoverEnabled: parent.actionable
                      cursorShape: parent.actionable ? Qt.PointingHandCursor : Qt.ArrowCursor
                      onClicked: if (parent.actionable) root.activateOverviewId(parent.actionId)
                    }
                  }
                }
              }

              Text {
                width: parent.width
                visible: root.showWorldMap
                text: "IP geolocation by DB-IP (CC-BY-4.0). Map: Natural Earth 110m."
                color: Qt.darker(root.fg, 1.8)
                font.family: root.fontFamily
                font.pixelSize: root.ux.caption
                wrapMode: Text.WordWrap
              }

              // The "Apps" section header that used to close this column, and
              // the rule that fenced it off, are gone: the pinned segments in
              // the header reach the same view from any scroll position.
            }
          }

          Item {
            id: appsPane
            anchors.fill: parent
            visible: root.panelView === "apps"

            Column {
              id: appsTop
              anchors.top: parent.top
              anchors.left: parent.left
              anchors.right: parent.right
              spacing: root.padGroup

              // The "Overview" header that used to open this column, and its
              // rule, are gone for the same reason as the "Apps" header at the
              // foot of the overview: the header segments are the one route.
              // What stays is this view's own live count, which is content.
              PanelSectionHeader {
                fontSize: root.ux.caption
                id: appsHead
                width: parent.width
                text: root.appsHeaderText
                foreground: root.fg
                fontFamily: root.fontFamily
              }

              Column {
                id: appsHeader
                width: parent.width
                spacing: Style.space(8 * root.ux.gap)
                  Text {
                    width: parent.width
                    visible: !root.dataCurrent
                    text: root.isDemo
                      ? "DEMO fixture rows. New blocks are disabled. This is not a live sampler."
                      : (root.observationAgeText
                        ? ("Last-known apps, " + root.observationAgeText + ". New blocks off until monitoring is current. Removing a block this session remembers still works.")
                        : "Last-known apps. New blocks off until monitoring is current. Removing a block this session remembers still works.")
                    color: Qt.darker(root.fg, 1.35)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }

                  Row {
                    width: parent.width
                    spacing: Style.space(8 * root.ux.gap)
                    Text {
                      text: "/"
                      color: root.accent
                      font.family: root.fontFamily
                      font.pixelSize: root.ux.body
                      anchors.verticalCenter: parent.verticalCenter
                    }
                    TextField {
                      font.pixelSize: root.ux.body
                      id: searchField
                      width: parent.width - Style.space(24)
                      foreground: root.fg
                      font.family: root.fontFamily
                      placeholderText: "search apps, IPs, countries"
                      text: root.searchQuery
                      onTextChanged: root.searchQuery = text
                      onActiveFocusChanged: root.searchOpen = activeFocus
                      Keys.onPressed: function(event) {
                        if (event.key === Qt.Key_Escape) {
                          root.searchOpen = false
                          root.searchQuery = ""
                          keyCatcher.forceActiveFocus()
                          event.accepted = true
                        } else if (event.key === Qt.Key_Down) {
                          root.moveSelection(1)
                          root.bumpListHold()
                          event.accepted = true
                        } else if (event.key === Qt.Key_Up) {
                          root.moveSelection(-1)
                          root.bumpListHold()
                          event.accepted = true
                        } else if (event.key === Qt.Key_PageDown) {
                          root.moveSelection(root.pageStep())
                          root.bumpListHold()
                          event.accepted = true
                        } else if (event.key === Qt.Key_PageUp) {
                          root.moveSelection(-root.pageStep())
                          root.bumpListHold()
                          event.accepted = true
                        } else if (event.key === Qt.Key_Home) {
                          root.moveSelection(-root.renderedLen())
                          root.bumpListHold()
                          event.accepted = true
                        } else if (event.key === Qt.Key_End) {
                          root.moveSelection(root.renderedLen())
                          root.bumpListHold()
                          event.accepted = true
                        } else if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                          root.acceptSearch()
                          root.searchOpen = false
                          keyCatcher.forceActiveFocus()
                          event.accepted = true
                        }
                      }
                    }
                  }

                  Row {
                    width: parent.width
                    spacing: Style.space(6 * root.ux.gap)
                    Repeater {
                      model: [
                        { id: "name", label: "Name" },
                        { id: "activity", label: "Activity" },
                        { id: "connections", label: "Connections" },
                        { id: "bandwidth", label: "Bandwidth" },
                        { id: "blocked", label: "Blocked first" }
                      ]
                      delegate: Rectangle {
                        required property var modelData
                        readonly property bool active: root.sortKey === modelData.id
                        width: sortChipLabel.implicitWidth + Style.space(16)
                        height: sortChipLabel.implicitHeight + Style.space(10 * root.ux.gap)
                        radius: Style.cornerRadius
                        color: active
                          ? Style.selectedFillFor(root.fg, root.accent)
                          : (sortChipMouse.containsMouse ? Style.hoverFillFor(root.fg, root.accent) : "transparent")

                        Text {
                          id: sortChipLabel
                          anchors.centerIn: parent
                          text: modelData.label
                          color: parent.active ? root.fg : Qt.darker(root.fg, 1.5)
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.caption
                          font.bold: parent.active
                        }

                        MouseArea {
                          id: sortChipMouse
                          anchors.fill: parent
                          hoverEnabled: true
                          cursorShape: Qt.PointingHandCursor
                          onClicked: {
                            // Saved like the `s` key and the Settings dropdown,
                            // or the next open puts the old order back.
                            root.setPref("sortKey", modelData.id)
                            root.applySortFilter(modelData.id, root.filterKey)
                          }
                        }
                      }
                    }
                  }

                  Row {
                    width: parent.width
                    spacing: Style.space(6 * root.ux.gap)
                    Repeater {
                      model: [
                        { id: "all", label: "All" },
                        { id: "live", label: "Live" },
                        { id: "blocked", label: "Blocked" },
                        { id: "unknown", label: "Unknown" }
                      ]
                      delegate: Rectangle {
                        required property var modelData
                        readonly property bool active: root.filterKey === modelData.id
                        width: filterChipLabel.implicitWidth + Style.space(16)
                        height: filterChipLabel.implicitHeight + Style.space(10 * root.ux.gap)
                        radius: Style.cornerRadius
                        color: active
                          ? Style.selectedFillFor(root.fg, root.accent)
                          : (filterChipMouse.containsMouse ? Style.hoverFillFor(root.fg, root.accent) : "transparent")

                        Text {
                          id: filterChipLabel
                          anchors.centerIn: parent
                          text: {
                            var _r = root.modelRev
                            var _q = root.searchQuery
                            return modelData.label + " " + root.filterChipCount(modelData.id)
                          }
                          color: parent.active ? root.fg : Qt.darker(root.fg, 1.5)
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.caption
                          font.bold: parent.active
                        }

                        MouseArea {
                          id: filterChipMouse
                          anchors.fill: parent
                          hoverEnabled: true
                          cursorShape: Qt.PointingHandCursor
                          onClicked: {
                            root.setPref("filterKey", modelData.id)
                            root.applySortFilter(root.sortKey, modelData.id)
                          }
                        }
                      }
                    }
                  }

                  Text {
                    visible: appModel.count === 0
                    width: parent.width
                    text: root.searchQuery
                      ? "Nothing matches."
                      : (root.dataCurrent
                        ? "No outbound conversations right now."
                        : (root.isDemo ? "DEMO fixture has no app rows yet." : "No last-known app rows."))
                    color: Qt.darker(root.fg, 1.5)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }
              }

            }

            Item {
              id: appsListHost
              anchors.top: appsTop.bottom
              anchors.bottom: parent.bottom
              anchors.left: parent.left
              anchors.right: parent.right
              anchors.topMargin: root.padGroup

                ListView {
                  id: appList
                  anchors.fill: parent
                  interactive: true
                  clip: true
                  spacing: Style.space(6 * root.ux.gap)
                  boundsBehavior: Flickable.StopAtBounds
                  // It is backed by a ListModel synced in place (root.syncRows) rather
                  // than bound straight to `root.apps`. That matters for two reasons,
                  // and the second one is why the previous fix here did not hold.
                  //
                  // `root.apps` is a fresh JS array on every daemon sample, twice a
                  // second. QML does not diff a JS array model: a new array identity
                  // destroys and recreates every delegate. contentHeight then reads 0
                  // mid-rebuild, this row collapses, and the panel jumps. A height
                  // guard used to hold the last good height across that dip. It
                  // worked on the geometry and left the cause running.
                  //
                  // Syncing in place keeps delegates alive, so contentHeight never
                  // dips, the guard is unnecessary, and rows can animate.
                  model: appModel
                  currentIndex: root.selectedIndex
                  onContentYChanged: {
                    if (!root.syncingRows)
                      root.bumpListHold()
                  }

                  HoverHandler { id: listHover }
                  WheelStep { flick: appList; speed: root.scrollSpeed; momentum: root.scrollMomentum }

                  Keys.onPressed: function(event) {
                    if (event.key === Qt.Key_PageDown) {
                      root.moveSelection(root.pageStep())
                      root.bumpListHold()
                      event.accepted = true
                    } else if (event.key === Qt.Key_PageUp) {
                      root.moveSelection(-root.pageStep())
                      root.bumpListHold()
                      event.accepted = true
                    } else if (event.key === Qt.Key_Home) {
                      root.moveSelection(-root.renderedLen())
                      root.bumpListHold()
                      event.accepted = true
                    } else if (event.key === Qt.Key_End) {
                      root.moveSelection(root.renderedLen())
                      root.bumpListHold()
                      event.accepted = true
                    } else if (event.key === Qt.Key_Down || event.key === Qt.Key_Up) {
                      root.bumpListHold()
                    }
                  }

                  displaced: Transition {
                    NumberAnimation { properties: "y"; duration: 140; easing.type: Easing.OutCubic }
                  }
                  add: Transition {
                    NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 140 }
                  }

                  delegate: Rectangle {
                    id: row
                    required property var model
                    required property int index
                    readonly property var appData: row.model.app
                    onAppDataChanged: sparkCanvas.requestPaint()
                    width: ListView.view.width
                    // The row carries a privileged control and is the surface the
                    // pointer spends most of its time on, so it gets a real hit
                    // target rather than the minimum the text needs.
                    height: rowInner.implicitHeight + Style.space(18 * root.ux.gap)
                    radius: Style.cornerRadius
                    opacity: row.appData && row.appData.dormant ? 0.62 : 1
                    color: row.appData && row.appData.id === root.selectedAppId
                      ? Style.selectedFillFor(root.fg, root.accent)
                      : (rowMouse.containsMouse ? Style.hoverFillFor(root.fg, root.accent) : "transparent")

                    MouseArea {
                      id: rowMouse
                      anchors.fill: parent
                      hoverEnabled: true
                      onClicked: {
                        root.selectedAppId = row.appData.id
                        root.selectedIndex = index
                      }
                    }

                    Row {
                      id: rowInner
                      anchors.left: parent.left
                      anchors.right: parent.right
                      anchors.verticalCenter: parent.verticalCenter
                      anchors.leftMargin: Style.space(8)
                      anchors.rightMargin: Style.space(8)
                      spacing: Style.space(8 * root.ux.gap)

                      Image {
                        width: Style.space(22)
                        height: Style.space(22)
                        fillMode: Image.PreserveAspectFit
                        asynchronous: true
                        source: root.liveVallum && root.liveVallum.appIcon ? root.liveVallum.appIcon(row.appData) : ""
                        visible: status === Image.Ready
                        anchors.verticalCenter: parent.verticalCenter
                      }

                      Text {
                        width: Style.space(22)
                        height: Style.space(22)
                        visible: parent.children[0].status !== Image.Ready
                        text: (row.appData.name || "?").charAt(0).toUpperCase()
                        textFormat: Text.PlainText
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: root.ux.body
                        font.bold: true
                        horizontalAlignment: Text.AlignHCenter
                        verticalAlignment: Text.AlignVCenter
                        anchors.verticalCenter: parent.verticalCenter
                      }

                      Column {
                        width: parent.width - Style.space(150)
                        spacing: Style.space(3 * root.ux.gap)
                        anchors.verticalCenter: parent.verticalCenter
                        Row {
                          width: parent.width
                          Text {
                            width: parent.width - Style.space(48)
                            text: row.appData.name || row.appData.id
                            textFormat: Text.PlainText
                            color: root.fg
                            font.family: root.fontFamily
                            font.pixelSize: root.ux.body
                            font.bold: row.appData.id === root.selectedAppId
                            elide: Text.ElideRight
                            anchors.verticalCenter: parent.verticalCenter
                          }
                          Canvas {
                            id: sparkCanvas
                            width: Style.space(48)
                            height: 10
                            visible: root.dataCurrent
                            anchors.verticalCenter: parent.verticalCenter
                            readonly property var sparkData: row.appData.spark || []
                            onPaint: {
                              var ctx = getContext("2d")
                              ctx.clearRect(0, 0, width, height)
                              var spark = sparkCanvas.sparkData
                              if (spark.length < 2)
                                return
                              var max = 1
                              var i
                              for (i = 0; i < spark.length; i++)
                                if (spark[i] > max) max = spark[i]
                              ctx.beginPath()
                              for (i = 0; i < spark.length; i++) {
                                var x = i / (spark.length - 1) * width
                                var y = height - (spark[i] / max) * (height - 1) - 0.5
                                if (i === 0) ctx.moveTo(x, y)
                                else ctx.lineTo(x, y)
                              }
                              ctx.strokeStyle = root.cssAccent()
                              ctx.lineWidth = 1.2
                              ctx.stroke()
                            }
                            Component.onCompleted: requestPaint()
                          }
                        }
                        Row {
                          width: parent.width
                          spacing: Style.space(6 * root.ux.gap)
                          Repeater {
                            model: uniqueCountries(row.appData)
                            FlagIcon {
                              required property var modelData
                              country: modelData
                              pluginDir: root.pluginDir
                              width: 14
                              height: 10
                              fallbackFill: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.22)
                              textColor: root.fg
                            }
                          }
                          Text {
                            text: {
                              var conn = connSummary(row.appData)
                              if (row.appData.id === root.selectedAppId)
                                return conn
                              var peers = Peers.summary(row.appData)
                              return peers ? conn + " · " + peers : conn
                            }
                            textFormat: Text.PlainText
                            color: Qt.darker(root.fg, 1.5)
                            font.family: root.fontFamily
                            font.pixelSize: root.ux.bodySmall
                            elide: Text.ElideRight
                            width: Math.max(0, parent.width - x)
                          }
                        }
                        // Expanded: a row per peer with the evidence behind its
                        // name and a way to correct it. The clue engine has been
                        // guessing since PR #8 landed and nothing on screen
                        // could take the answer — this is where a guess becomes
                        // a fact.
                        Column {
                          width: parent.width
                          visible: row.appData.id === root.selectedAppId
                          spacing: Style.space(4 * root.ux.gap)
                          Repeater {
                            model: root.connPeers(row.appData)
                            delegate: Column {
                              id: peerRow
                              required property var modelData
                              readonly property bool naming:
                                modelData.networkKey.length > 0
                                && modelData.networkKey === root.namingKey
                              width: parent.width
                              spacing: Style.space(2 * root.ux.gap)
                              Row {
                                width: parent.width
                                spacing: Style.space(6 * root.ux.gap)
                                Text {
                                  text: modelData.count > 1
                                    ? modelData.name + " ×" + modelData.count
                                    : modelData.name
                                  textFormat: Text.PlainText
                                  color: root.fg
                                  font.family: root.fontFamily
                                  font.pixelSize: root.ux.caption
                                  // A name the user gave is theirs; it should not
                                  // sit in the same weight as a machine guess.
                                  font.bold: modelData.tagLabel.length > 0
                                  elide: Text.ElideRight
                                }
                                Text {
                                  visible: modelData.networkKey.length > 0 && !peerRow.naming
                                  text: root.peerActionLabel(modelData)
                                  textFormat: Text.PlainText
                                  color: root.accent
                                  font.family: root.fontFamily
                                  font.pixelSize: root.ux.caption
                                  font.underline: nameHover.hovered
                                  HoverHandler {
                                    id: nameHover
                                    cursorShape: Qt.PointingHandCursor
                                  }
                                  TapHandler {
                                    onTapped: root.beginNaming(modelData)
                                  }
                                }
                              }
                              Text {
                                width: parent.width
                                visible: text.length > 0 && !peerRow.naming
                                text: root.peerEvidence(modelData)
                                textFormat: Text.PlainText
                                color: Qt.darker(root.fg, 1.6)
                                font.family: root.fontFamily
                                font.pixelSize: root.ux.caption
                                wrapMode: Text.WordWrap
                              }
                            }
                          }
                          // The naming editor lives here, beside the Repeater
                          // rather than in its delegate. The Repeater rebuilds
                          // every delegate whenever any peer's details move (a
                          // connection count, a new peer), which on a busy app
                          // is most samples. A field inside it died with them:
                          // focus fell out mid-word, and the rest of the name
                          // went to the panel's shortcuts instead. This row
                          // belongs to the app row, which survives updates.
                          // tests/test_naming_focus.qml
                          Row {
                            id: nameEditor
                            readonly property bool editing:
                              root.namingKey !== "" && row.appData.id === root.selectedAppId
                            width: parent.width
                            visible: editing
                            // Focus follows the STATE, not creation --
                            // Component.onCompleted would grab focus from the
                            // search box the moment an app is selected.
                            onEditingChanged: if (editing) nameField.forceActiveFocus()
                            spacing: Style.space(6 * root.ux.gap)
                            TextField {
                              font.pixelSize: root.ux.body
                              id: nameField
                              width: parent.width * 0.5
                              foreground: root.fg
                              font.family: root.fontFamily
                              verticalPadding: Style.space(2 * root.ux.gap)
                              text: root.namingDraft
                              placeholderText: "What is this?"
                              // 64 is the daemon's own cap (TAG_LABEL_MAX).
                              // Clamped here so a too-long name is impossible
                              // to type, rather than silently dropped by a
                              // daemon that logs the refusal and moves on.
                              // Done in the handler, not via maximumLength,
                              // because this TextField is the shell's own
                              // component and that property is not part of
                              // the API the rest of this file uses.
                              onTextChanged: {
                                if (text.length > 64)
                                  text = text.substring(0, 64)
                                root.namingDraft = text
                              }
                              onAccepted: root.applyNaming()
                              Keys.onEscapePressed: root.cancelNaming()
                            }
                            Button {
                              fontSize: root.ux.body
                              text: "Save"
                              foreground: root.fg
                              fontFamily: root.fontFamily
                              bordered: true
                              onClicked: root.applyNaming()
                            }
                            Button {
                              fontSize: root.ux.body
                              // Empty label is the daemon's delete. Offering
                              // it only when there is something to clear
                              // keeps "take this back" discoverable without
                              // putting a destructive verb on every row.
                              visible: root.namingHadTag
                              text: "Clear"
                              foreground: root.fg
                              fontFamily: root.fontFamily
                              bordered: true
                              onClicked: {
                                root.namingDraft = ""
                                root.applyNaming()
                              }
                            }
                            Button {
                              fontSize: root.ux.body
                              text: "Cancel"
                              foreground: root.fg
                              fontFamily: root.fontFamily
                              bordered: true
                              onClicked: root.cancelNaming()
                            }
                          }
                        }
                        Text {
                          // Where the last name went, when it did not reach
                          // both daemons (#61 step 2: tags go to both).
                          readonly property string notice: liveVallum && liveVallum.tagNotice ? String(liveVallum.tagNotice) : ""
                          width: parent.width
                          visible: row.appData.id === root.selectedAppId && notice !== ""
                          text: notice
                          color: Qt.darker(root.fg, 1.4)
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.caption
                          wrapMode: Text.WordWrap
                        }
                        Text {
                          width: parent.width
                          text: blockStateLabel(row.appData)
                          color: Qt.darker(root.fg, 1.4)
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.caption
                          wrapMode: Text.WordWrap
                        }
                        Text {
                          width: parent.width
                          visible: row.appData.id === root.selectedAppId && selectedBlockDetail(row.appData) !== ""
                          text: selectedBlockDetail(row.appData)
                          color: Qt.darker(root.fg, 1.45)
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.caption
                          wrapMode: Text.WordWrap
                        }
                        Text {
                          width: parent.width
                          text: Traffic.summary(row.appData, root.dataCurrent, root.ux)
                          color: Qt.darker(root.fg, 1.4)
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.caption
                          wrapMode: Text.WordWrap
                        }
                        DestinationRules {
                          width: parent.width
                          visible: row.appData.id === root.selectedAppId && !row.appData.system && (row.appData.pids.length > 0 || row.appData.hasTemporaryRule === true)
                          app: row.appData
                          service: root.liveVallum
                          current: root.dataCurrent
                          foreground: root.fg
                          fontFamily: root.fontFamily
                          ux: root.ux
                          onEditingChanged: root.destinationPopupOpen = editing
                        }
                        Button {
                          fontSize: root.ux.body
                          text: "Connection evidence"
                          foreground: root.fg
                          fontFamily: root.fontFamily
                          visible: row.appData.id === root.selectedAppId && row.appData.connections.length > 0
                          onClicked: root.evidenceApp = row.appData
                        }
                      }

                      Button {
                        fontSize: root.ux.body
                        text: row.appData.blocked
                          ? (row.appData.mechanism === "endpoints" ? "Unblock endpoints" : "Unblock app")
                          : "Block app"
                        enabled: root.canUnblock(row.appData) || root.canStartBlock(row.appData)
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        bordered: true
                        focusable: true
                        anchors.verticalCenter: parent.verticalCenter
                        tooltipText: row.appData.blocked
                          ? (row.appData.mechanism === "endpoints"
                              ? "Remove the host-wide endpoint block remembered for this app"
                              : "Unblock this app's process tree")
                          : "Block this app's running processes. Unavailable while monitoring is not current."
                        onClicked: {
                          root.selectedAppId = row.appData.id
                          root.selectedIndex = index
                          root.requestBlockGuarded(row.appData.id)
                        }
                      }
                    }
                  }
                }

            }
          }

          IntelView {
            id: intelView
            anchors.fill: parent
            visible: root.panelView === "intel"
            service: root.opened ? root.liveVallum : null
            kub0: root.opened ? root.kub0 : Kub0.emptyKub0()
            model: root.liveVallum ? root.liveVallum.model : null
            revision: root.modelRev
            foreground: root.fg
            accent: root.accent
            badColor: root.badColor
            warnColor: root.warnColor
            fontFamily: root.fontFamily
            scrollSpeed: root.scrollSpeed
            scrollMomentum: root.scrollMomentum
            ux: root.ux
            onViewEvidence: function(c) {root.evidenceApp = {name:c.app.name,connections:[c]}}
          }

          HistoryView {
            id: historyView
            anchors.fill: parent
            visible: root.panelView === "history"
            service: root.opened ? root.liveVallum : null
            foreground: root.fg
            accent: root.accent
            badColor: root.badColor
            fontFamily: root.fontFamily
            scrollSpeed: root.scrollSpeed
            scrollMomentum: root.scrollMomentum
            ux: root.ux
            onViewEvidence: function(c) {root.evidenceApp = {name:c.app.name,connections:[c]}}
          }

          EndpointsView {
            id: endpointsView
            anchors.fill: parent
            visible: root.panelView === "endpoints"
            account: root.opened ? root.kub0 : Kub0.emptyKub0()
            foreground: root.fg
            accent: root.accent
            fontFamily: root.fontFamily
            scrollSpeed: root.scrollSpeed
            scrollMomentum: root.scrollMomentum
            ux: root.ux
          }

          ConnectionEvidence {
            anchors.fill: parent
            visible: (root.panelView === "apps" || root.panelView === "history" || root.panelView === "intel") && root.evidenceApp !== null
            z: 10
            app: root.evidenceApp
            foreground: root.fg
            fontFamily: root.fontFamily
            scrollSpeed: root.scrollSpeed
            scrollMomentum: root.scrollMomentum
            ux: root.ux
            onClosed: root.evidenceApp = null
          }

          Flickable {
            id: panelFlick
            anchors.fill: parent
            visible: root.panelView === "settings"
            contentWidth: width
            contentHeight: settingsCol.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            interactive: contentHeight > height
            flickableDirection: Flickable.VerticalFlick
            WheelStep { flick: panelFlick; speed: root.scrollSpeed; momentum: root.scrollMomentum }

            Column {
              id: settingsCol
              width: panelFlick.width
              spacing: root.padGroup

                Text {
                  width: parent.width
                  text: "When the panel opens"
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }

                Dropdown {
                  width: Math.min(parent.width, Style.space(260))
                  label: "Start on"
                  value: root.prefs.startupView
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  options: [
                    { value: "overview", label: "Overview" },
                    { value: "apps", label: "Apps" },
                    { value: "intel", label: "Intel" },
                    { value: "history", label: "History" },
                    { value: "endpoints", label: "Endpoints" },
                    { value: "last", label: "Whatever I had open last" }
                  ]
                  onChanged: function(v) { root.setPref("startupView", v) }
                }

                Text {
                  width: parent.width
                  text: "Apps list"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }

                Dropdown {
                  width: Math.min(parent.width, Style.space(260))
                  label: "Sort by"
                  value: root.prefs.sortKey
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  options: [
                    { value: "name", label: "Name" },
                    { value: "activity", label: "Most recent activity" },
                    { value: "connections", label: "Most connections" },
                    { value: "bandwidth", label: "Most TCP bandwidth" },
                    { value: "blocked", label: "Blocked first" }
                  ]
                  onChanged: function(v) {
                    root.setPref("sortKey", v)
                    root.applySortFilter(v, root.filterKey)
                  }
                }

                Text {
                  width: parent.width
                  visible: root.prefs.sortKey === "activity"
                  text: "Sorting by activity reorders rows while you are pointing at them. The block control sits on those rows."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }

                Dropdown {
                  width: Math.min(parent.width, Style.space(260))
                  label: "Show"
                  value: root.prefs.filterKey
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  options: [
                    { value: "all", label: "Everything" },
                    { value: "live", label: "Only apps with live connections" },
                    { value: "blocked", label: "Only blocked apps" },
                    { value: "unknown", label: "Only unattributed connections" }
                  ]
                  onChanged: function(v) {
                    root.setPref("filterKey", v)
                    root.applySortFilter(root.sortKey, v)
                  }
                }

                Text {
                  width: parent.width
                  text: "Blocking"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }

                Row {
                  width: parent.width
                  spacing: Style.space(10 * root.ux.gap)
                  ToggleSwitch {
                    id: confirmToggle
                    anchors.verticalCenter: parent.verticalCenter
                    checked: root.prefs.confirmBlocks
                    foreground: root.fg
                    accent: root.accent
                    onToggled: root.setPref("confirmBlocks", !root.prefs.confirmBlocks)
                  }
                  Column {
                    width: parent.width - confirmToggle.width - Style.space(10)
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(2 * root.ux.gap)
                    Text {
                      width: parent.width
                      text: "Ask before blocking an app"
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: root.ux.bodySmall
                      wrapMode: Text.WordWrap
                    }
                    Text {
                      width: parent.width
                      text: "A block is a kernel firewall rule, dispatched from one click on a row that can move under the pointer. Unblocking is never confirmed."
                      color: Qt.darker(root.fg, 1.4)
                      font.family: root.fontFamily
                      font.pixelSize: root.ux.caption
                      wrapMode: Text.WordWrap
                    }
                  }
                }

                Text {
                  width: parent.width
                  text: "Optional capture"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Row {
                  width: parent.width
                  spacing: Style.space(10 * root.ux.gap)
                  ToggleSwitch {
                    id: captureToggle
                    objectName: "captureToggle"
                    anchors.verticalCenter: parent.verticalCenter
                    checked: root.prefs.captureEnabled === true
                    foreground: root.fg
                    accent: root.accent
                    onToggled: root.setPref("captureEnabled", !root.prefs.captureEnabled)
                  }
                  Text {
                    width: parent.width - captureToggle.width - Style.space(10)
                    text: "Record brief connect and unconnected UDP attempts in your user slice. Apps moved to kub0 scopes are excluded. Requires the optional Linux collector and administrator authorization. Restarts the monitor when changed."
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }
                }
                Text {
                  width: parent.width
                  readonly property var capture: root.liveVallum && root.liveVallum.captureStatus ? root.liveVallum.captureStatus : ({ state: "off", detail: "Optional capture is off" })
                  text: "Capture: " + capture.state + " · " + capture.detail + "\nLost: kernel " + (capture.kernelDropped || 0) + ", collector output " + (capture.collectorDropped || 0) + ", reader queue " + (capture.userspaceDropped || 0) + "; invalid frames " + (capture.invalid || 0) + ". Attempts do not establish a successful connection, verdict, or byte count."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  text: "Intel"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Row {
                  width: parent.width
                  spacing: Style.space(10 * root.ux.gap)
                  ToggleSwitch {
                    id: notifyIntelToggle
                    objectName: "notifyIntelToggle"
                    anchors.verticalCenter: parent.verticalCenter
                    checked: root.prefs.notifyIntel === true
                    foreground: root.fg
                    accent: root.accent
                    onToggled: root.setPref("notifyIntel", !root.prefs.notifyIntel)
                  }
                  Text {
                    width: parent.width - notifyIntelToggle.width - Style.space(10)
                    text: "Send a desktop notification when a connection matches one of your watch rules or raises a warning-level indicator. Notices and info stay in the Intel view."
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }
                }
                Row {
                  width: parent.width
                  spacing: Style.space(10 * root.ux.gap)
                  ToggleSwitch {
                    id: shareDestinationsToggle
                    objectName: "shareDestinationsToggle"
                    anchors.verticalCenter: parent.verticalCenter
                    checked: root.sharingDestinations
                    foreground: root.fg
                    accent: root.accent
                    onToggled: root.setSharing(!root.sharingDestinations)
                  }
                  Text {
                    width: parent.width - shareDestinationsToggle.width - Style.space(10)
                    text: "Share destination networks with your kub0 org to see how many other endpoints reached the same place. Sends the /24 or /48 network key of each new public destination on the heartbeat, never an address or an app, and only while connected. Off, nothing from the Intel view leaves this machine. " + (root.liveVallum && root.liveVallum.sharingIsSystems === true ? "This is the system daemon's setting (kub0 share on|off): turning it on asks for an administrator, and it holds across restarts." : "Restarts the monitor when changed.") + " A server that does not answer prevalence is reported as such."
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }
                }
                Text {
                  width: parent.width
                  text: "Display"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }

                Row {
                  width: parent.width
                  spacing: Style.space(10 * root.ux.gap)
                  ToggleSwitch {
                    id: mapToggle
                    anchors.verticalCenter: parent.verticalCenter
                    checked: root.prefs.showWorldMap
                    foreground: root.fg
                    accent: root.accent
                    onToggled: root.setPref("showWorldMap", !root.prefs.showWorldMap)
                  }
                  Text {
                    width: parent.width - mapToggle.width - Style.space(10)
                    anchors.verticalCenter: parent.verticalCenter
                    text: "Show the world map"
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }
                }

                Text {
                  width: parent.width
                  text: "Text and spacing"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Text {
                  width: parent.width
                  text: "Text size"
                  color: Qt.darker(root.fg, 1.2)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                }
                ButtonGroup {
                  objectName: "textSizeChoice"
                  options: Ux.TEXT_SIZES
                  value: root.prefs.textSize
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: root.ux.bodySmall
                  onChanged: function(v) { root.setPref("textSize", v) }
                }
                Text {
                  width: parent.width
                  text: "Spacing"
                  color: Qt.darker(root.fg, 1.2)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                }
                ButtonGroup {
                  objectName: "densityChoice"
                  options: Ux.DENSITIES
                  value: root.prefs.density
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: root.ux.bodySmall
                  onChanged: function(v) { root.setPref("density", v) }
                }
                Text {
                  width: parent.width
                  text: "On top of the shell's own text size. Both apply at once, to every view of this panel."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  text: "Panel size"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Text {
                  width: parent.width
                  text: "Width"
                  color: Qt.darker(root.fg, 1.2)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                }
                ButtonGroup {
                  objectName: "panelWidthChoice"
                  options: Ux.PANEL_WIDTHS
                  value: root.prefs.panelWidth
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: root.ux.bodySmall
                  onChanged: function(v) { root.setPref("panelWidth", v) }
                }
                Text {
                  width: parent.width
                  text: "Height"
                  color: Qt.darker(root.fg, 1.2)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                }
                ButtonGroup {
                  objectName: "panelHeightChoice"
                  options: Ux.PANEL_HEIGHTS
                  value: root.prefs.panelHeight
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: root.ux.bodySmall
                  onChanged: function(v) { root.setPref("panelHeight", v) }
                }
                Text {
                  width: parent.width
                  text: "The panel never opens larger than the screen has room for."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  text: "Time and units"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Text {
                  width: parent.width
                  text: "Times"
                  color: Qt.darker(root.fg, 1.2)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                }
                ButtonGroup {
                  objectName: "timeStyleChoice"
                  options: Ux.TIME_STYLES
                  value: root.prefs.timeStyle
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: root.ux.bodySmall
                  onChanged: function(v) { root.setPref("timeStyle", v) }
                }
                Text {
                  width: parent.width
                  text: "Mixed is the panel's own: how long ago for what is live, a full date for what is logged. The other two say every timestamp the same way."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  text: "Sizes and speeds"
                  color: Qt.darker(root.fg, 1.2)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                }
                ButtonGroup {
                  objectName: "byteUnitsChoice"
                  options: Ux.BYTE_UNITS
                  value: root.prefs.byteUnits
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: root.ux.bodySmall
                  onChanged: function(v) { root.setPref("byteUnits", v) }
                }
                Text {
                  width: parent.width
                  text: "KiB and MiB count in 1024s; kB and MB count in 1000s, as most download speeds are quoted."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  text: "Scrolling"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }

                // One click per choice, all four on show. ButtonGroup only
                // emits `changed` and never writes `value`, so this binding
                // survives a pick and follows "Reset to defaults".
                ButtonGroup {
                  objectName: "scrollSpeedChoice"
                  options: Scroll.SPEEDS
                  value: root.scrollSpeed
                  foreground: root.fg
                  accent: root.accent
                  fontFamily: root.fontFamily
                  fontSize: root.ux.bodySmall
                  onChanged: function(v) { root.setPref("scrollSpeed", v) }
                }

                Text {
                  width: parent.width
                  text: "How far a touchpad swipe or a wheel notch moves a list, in every view. It applies at once: scroll this page to try it."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }

                Row {
                  width: parent.width
                  spacing: Style.space(10 * root.ux.gap)
                  ToggleSwitch {
                    id: momentumToggle
                    objectName: "scrollMomentumToggle"
                    anchors.verticalCenter: parent.verticalCenter
                    checked: root.scrollMomentum
                    foreground: root.fg
                    accent: root.accent
                    onToggled: root.setPref("scrollMomentum", !root.scrollMomentum)
                  }
                  Column {
                    width: parent.width - momentumToggle.width - Style.space(10)
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: Style.space(2 * root.ux.gap)
                    Text {
                      width: parent.width
                      text: "Keep moving after a swipe"
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: root.ux.bodySmall
                      wrapMode: Text.WordWrap
                    }
                    Text {
                      width: parent.width
                      text: "A list carries on when you lift your fingers and slows to a stop. A faster swipe travels further."
                      color: Qt.darker(root.fg, 1.4)
                      font.family: root.fontFamily
                      font.pixelSize: root.ux.caption
                      wrapMode: Text.WordWrap
                    }
                  }
                }

                PanelSeparator { width: parent.width }

                Text {
                  width: parent.width
                  text: root.endpointHeading()
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Column {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  visible: root.connectState !== "waiting" && root.connectState !== "error" && !root.kub0Connected
                  Text {
                    width: parent.width
                    text: "Monitoring works without an account. Connecting registers this endpoint in your kub0 tenant and delivers your organisation's rules."
                    color: Qt.darker(root.fg, 1.35)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }
                  Button {
                    fontSize: root.ux.body
                    text: "Connect this endpoint"
                    foreground: root.fg
                    fontFamily: root.fontFamily
                    bordered: true
                    focusable: true
                    onClicked: {
                      if (root.liveVallum && typeof root.liveVallum.requestConnect === "function")
                        root.liveVallum.requestConnect()
                    }
                  }
                }
                Column {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  visible: root.connectState === "waiting"
                  TextEdit {
                    width: parent.width
                    text: root.connectCode
                    readOnly: true
                    selectByMouse: true
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.body * 1.4
                    font.bold: true
                    wrapMode: TextEdit.NoWrap
                    textFormat: TextEdit.PlainText
                  }
                  Row {
                    spacing: Style.space(8 * root.ux.gap)
                    Button {
                      fontSize: root.ux.body
                      text: "Open kub0.ai/connect"
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      bordered: true
                      focusable: true
                      enabled: root.connectUrl !== ""
                      onClicked: {
                        if (root.liveVallum && typeof root.liveVallum.openConnectUrl === "function")
                          root.liveVallum.openConnectUrl()
                      }
                    }
                    Button {
                      fontSize: root.ux.body
                      text: "Cancel"
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      bordered: true
                      focusable: true
                      onClicked: {
                        if (root.liveVallum && typeof root.liveVallum.cancelConnect === "function")
                          root.liveVallum.cancelConnect()
                      }
                    }
                  }
                  Text {
                    width: parent.width
                    text: root.connectCountdown() ? ("expires in " + root.connectCountdown()) : ""
                    color: Qt.darker(root.fg, 1.4)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                  }
                }
                Column {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  visible: root.connectState !== "waiting" && root.kub0Connected
                  Column {
                    width: parent.width
                    spacing: Style.space(3 * root.ux.gap)
                    Repeater {
                      // A count, not the rows: see factRows.
                      model: root.endpointFactRows.length
                      delegate: FactRow {
                        required property int index
                        readonly property var fact: root.endpointFactRows[index] || ({})
                        label: fact.label || ""
                        value: fact.value || ""
                        tone: fact.tone || ""
                      }
                    }
                  }
                  Flow {
                    width: parent.width
                    spacing: Style.space(8 * root.ux.gap)
                    Button {
                      fontSize: root.ux.body
                      text: "Tenant endpoints"
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      bordered: true
                      focusable: true
                      onClicked: root.selectView("endpoints")
                    }
                    Button {
                      fontSize: root.ux.body
                      text: "View inventory on kub0.ai"
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      bordered: true
                      focusable: true
                      onClicked: {
                        if (root.liveVallum && typeof root.liveVallum.openInventoryUrl === "function")
                          root.liveVallum.openInventoryUrl()
                      }
                    }
                    Button {
                      fontSize: root.ux.body
                      text: "Disconnect"
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      bordered: true
                      focusable: true
                      onClicked: {
                        if (root.liveVallum && typeof root.liveVallum.requestDisconnect === "function")
                          root.liveVallum.requestDisconnect()
                      }
                    }
                  }
                }
                Column {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  visible: root.connectState === "error"
                  Text {
                    width: parent.width
                    text: root.connectError || "connect failed"
                    textFormat: Text.PlainText
                    color: root.badColor
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    wrapMode: Text.WordWrap
                  }
                  Button {
                    fontSize: root.ux.body
                    text: "Try again"
                    foreground: root.fg
                    fontFamily: root.fontFamily
                    bordered: true
                    focusable: true
                    onClicked: {
                      if (root.liveVallum && typeof root.liveVallum.requestConnect === "function")
                        root.liveVallum.requestConnect()
                    }
                  }
                }

                Text {
                  width: parent.width
                  text: "Optional root system protection: " + (root.liveVallum ? root.liveVallum.systemProtectionText || "unavailable" : "unavailable")
                  wrapMode: Text.WordWrap
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                }
                Text {
                  id: enforcementHead
                  width: parent.width
                  text: root.enforcementHeading()
                  // Air ABOVE a heading, not below it: the gap separates this
                  // group from the previous one, while the heading stays tight
                  // to the content it introduces.
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Column {
                  width: parent.width
                  spacing: Style.space(3 * root.ux.gap)
                  Repeater {
                    // A count, not the rows: see factRows.
                    model: root.helperFactRows.length
                    delegate: FactRow {
                      required property int index
                      readonly property var fact: root.helperFactRows[index] || ({})
                      label: fact.label || ""
                      value: fact.value || ""
                      tone: fact.tone || ""
                    }
                  }
                }
                Text {
                  width: parent.width
                  text: "Block records are stored on this machine. This panel cannot verify the current kernel rules."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  text: root.hostBlocks.length === 0
                    ? "No block records on this host."
                    : (root.hostBlocks.length + (root.hostBlocks.length === 1
                      ? " app has a block record. Allow or block from Apps."
                      : " apps have block records. Allow or block from Apps."))
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                  wrapMode: Text.WordWrap
                }
                Text {
                  width: parent.width
                  visible: root.lastBlockError !== "" && !root.confirmIps
                  text: root.lastBlockError
                  // Helper errors quote /proc cgroup paths verbatim, and a
                  // user process can name its cgroup; AutoText would render
                  // a tag in one as markup.
                  textFormat: Text.PlainText
                  color: root.badColor
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                  wrapMode: Text.WordWrap
                }
                Button {
                  fontSize: root.ux.body
                  visible: root.needsHelperInstall
                  text: "Install helper"
                  enabled: !root.helperInstallPending
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  bordered: true
                  focusable: true
                  onClicked: root.launchHelperInstall()
                }
                Button {
                  fontSize: root.ux.body
                  visible: root.setupStage === "install"
                  text: "Install kub0"
                  enabled: !root.helperInstallPending
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  bordered: true
                  focusable: true
                  onClicked: root.launchReleaseInstall()
                }
                Button {
                  fontSize: root.ux.body
                  visible: root.needsDaemonBuild
                  text: "Build kub0d"
                  enabled: !root.helperInstallPending
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  bordered: true
                  focusable: true
                  onClicked: root.launchDaemonBuild()
                }
                Button {
                  fontSize: root.ux.body
                  visible: root.needsBlockingPackages
                  text: "Install packages"
                  enabled: !root.helperInstallPending
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  bordered: true
                  focusable: true
                  onClicked: root.launchPackageInstall()
                }
                Rectangle {
                  visible: root.offerBinds
                  width: parent.width
                  height: bindCol.implicitHeight + Style.space(16 * root.ux.gap)
                  radius: Style.cornerRadius
                  color: Style.hoverFillFor(root.fg, root.accent)
                  border.color: Qt.rgba(root.fg.r, root.fg.g, root.fg.b, 0.2)
                  border.width: 1
                  Column {
                    id: bindCol
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    anchors.margins: Style.space(10 * root.ux.gap)
                    spacing: Style.space(8 * root.ux.gap)
                    Text {
                      width: parent.width
                      text: root.offerNote
                        ? root.offerNote
                        : "No hotkey yet. Setting one opens this panel—the shell picks a free combination."
                      color: root.fg
                      font.family: root.fontFamily
                      font.pixelSize: root.ux.bodySmall
                      wrapMode: Text.WordWrap
                    }
                    Button {
                      fontSize: root.ux.body
                      text: "Set hotkey"
                      foreground: root.fg
                      fontFamily: root.fontFamily
                      bordered: true
                      focusable: true
                      tooltipText: "Write a free chord to ~/.config/hypr/bindings.lua (never on first load)"
                      onClicked: {
                        if (root.liveVallum && typeof root.liveVallum.installBinds === "function")
                          root.liveVallum.installBinds("")
                      }
                    }
                  }
                }

                // The exec gate is this machine's: the system kub0d refuses an
                // exec whose sha256 is on the org deny list (or a local deny
                // file). The panel talks to the user daemon, which mirrors the
                // system daemon's state file, so the heading says where the
                // state came from and when it went stale.
                Text {
                  width: parent.width
                  objectName: "execGateHeading"
                  text: Kub0.execGateHeading(root.kub0)
                  textFormat: Text.PlainText
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Column {
                  width: parent.width
                  spacing: Style.space(3 * root.ux.gap)
                  Repeater {
                    // A count, not the rows: see factRows.
                    model: root.execGateFactRows.length
                    delegate: FactRow {
                      required property int index
                      readonly property var fact: root.execGateFactRows[index] || ({})
                      label: fact.label || ""
                      value: fact.value || ""
                      tone: fact.tone || ""
                    }
                  }
                }
                Text {
                  width: parent.width
                  text: "A blocked exec fails with EPERM and raises a desktop notification with Allow once and Trust on this machine. Both go through the privileged helper and ask for your password."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }
                Column {
                  width: parent.width
                  spacing: Style.space(3 * root.ux.gap)
                  visible: root.execGateRecent.length > 0
                  Text {
                    width: parent.width
                    text: "Recent matches"
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    font.bold: true
                  }
                  Repeater {
                    model: root.execGateRecent
                    delegate: Column {
                      required property var modelData
                      width: settingsCol.width
                      spacing: Style.space(1 * root.ux.gap)
                      Text {
                        width: parent.width
                        text: Kub0.execDenyLine(modelData, root.ux, Date.now())
                        textFormat: Text.PlainText
                        color: modelData.decision === "blocked" || modelData.decision === "allowed_failopen"
                          ? root.warnColor : root.fg
                        font.family: root.fontFamily
                        font.pixelSize: root.ux.bodySmall
                        elide: Text.ElideRight
                      }
                      Text {
                        width: parent.width
                        // The owner's own path on the owner's own machine.
                        text: modelData.exe
                        visible: text.length > 0
                        textFormat: Text.PlainText
                        color: Qt.darker(root.fg, 1.4)
                        font.family: root.fontFamily
                        font.pixelSize: root.ux.caption
                        elide: Text.ElideMiddle
                      }
                    }
                  }
                }
                Column {
                  width: parent.width
                  spacing: Style.space(4 * root.ux.gap)
                  visible: root.execGateTrusted.length > 0
                  Text {
                    width: parent.width
                    text: "Trusted on this machine"
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    font.bold: true
                  }
                  Text {
                    width: parent.width
                    text: "These digests stay on the org list but are never refused here. Remove one to put it back under the gate."
                    color: Qt.darker(root.fg, 1.4)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                    wrapMode: Text.WordWrap
                  }
                  Repeater {
                    model: root.execGateTrusted
                    delegate: Row {
                      required property var modelData
                      width: settingsCol.width
                      spacing: Style.space(8 * root.ux.gap)
                      Text {
                        width: parent.width - removeTrust.width - Style.space(8)
                        anchors.verticalCenter: parent.verticalCenter
                        text: Kub0.trustedLine(modelData)
                        textFormat: Text.PlainText
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: root.ux.bodySmall
                        elide: Text.ElideMiddle
                      }
                      Button {
                        fontSize: root.ux.body
                        id: removeTrust
                        anchors.verticalCenter: parent.verticalCenter
                        text: "Remove"
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        bordered: true
                        focusable: true
                        enabled: !!root.liveVallum && root.helperInstalled && !root.helperBusy
                        tooltipText: "Put this digest back under the exec gate (asks for your password)"
                        onClicked: {
                          if (root.liveVallum && typeof root.liveVallum.execGateUntrust === "function")
                            root.liveVallum.execGateUntrust(modelData.sha256)
                        }
                      }
                    }
                  }
                }

                Text {
                  width: parent.width
                  text: root.fleetHeading()
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Text {
                  width: parent.width
                  visible: !root.kub0Connected
                  text: "Connect to receive your organisation's deny-list."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.bodySmall
                  wrapMode: Text.WordWrap
                }
                Column {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  visible: root.kub0Connected
                  Column {
                    width: parent.width
                    spacing: Style.space(3 * root.ux.gap)
                    Repeater {
                      // A count, not the rows: see factRows.
                      model: root.fleetFactRows.length
                      delegate: FactRow {
                        required property int index
                        readonly property var fact: root.fleetFactRows[index] || ({})
                        label: fact.label || ""
                        value: fact.value || ""
                        tone: fact.tone || ""
                      }
                    }
                  }
                  Text {
                    width: parent.width
                    text: "Exec gate: fanotify, keyed on detonated-sample sha256, system mode only; status shown above."
                    color: Qt.darker(root.fg, 1.4)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                    wrapMode: Text.WordWrap
                  }
                  Text {
                    width: parent.width
                    text: Kub0.denylistLiveText(root.kub0)
                    visible: text.length > 0
                    color: Qt.darker(root.fg, 1.4)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                    wrapMode: Text.WordWrap
                  }
                  Repeater {
                    model: root.kub0 && root.kub0.denylist ? root.kub0.denylist : []
                    delegate: Rectangle {
                      required property var modelData
                      width: settingsCol.width
                      height: denyRow.implicitHeight + Style.space(8 * root.ux.gap)
                      radius: Style.cornerRadius
                      color: root.denylistRowHighlighted(modelData)
                        ? Style.selectedFillFor(root.fg, root.accent)
                        : "transparent"
                      // What the policy is FOR on the first line, what it matches
                      // on the second. The old single row led with comm||path --
                      // the matcher -- so a list of rules read as a list of
                      // process names and answered a question nobody was asking.
                      Column {
                        id: denyRow
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: Style.space(2 * root.ux.gap)
                        Text {
                          width: parent.width
                          // The daemon settles this, including the fallback for a
                          // rule the org never named — see DenylistEntry::label.
                          text: modelData.name || "Unnamed rule"
                          textFormat: Text.PlainText
                          color: root.fg
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.bodySmall
                          elide: Text.ElideRight
                        }
                        Text {
                          width: parent.width
                          text: root.fleetPolicyDetail(modelData)
                          visible: text.length > 0
                          textFormat: Text.PlainText
                          color: Qt.darker(root.fg, 1.4)
                          font.family: root.fontFamily
                          font.pixelSize: root.ux.caption
                          elide: Text.ElideRight
                        }
                      }
                    }
                  }
                }
                // Role and current policy evidence belong to the daemon, not the tenant.
                Column {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  Text {
                    objectName: "policyDaemonRole"
                    width: parent.width
                    textFormat: Text.PlainText
                    text: Kub0.policyDaemonModeText(root.liveVallum ? root.liveVallum.policyDaemonMode : "unknown")
                    color: Qt.darker(root.fg, 1.4)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                    wrapMode: Text.WordWrap
                  }
                  // Daemon policy evidence is separate from per-app helper readiness.
                  Text {
                    width: parent.width
                    visible: true
                    text: "Network policies"
                    topPadding: Style.space(4 * root.ux.gap)
                    color: root.fg
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.bodySmall
                    font.bold: true
                  }
                  Text {
                    width: parent.width
                    objectName: "policyEnforcementStatus"
                    textFormat: Text.PlainText
                    visible: text.length > 0
                    text: Kub0.policyEnforcementText(root.kub0Enforcement)
                    color: Qt.darker(root.fg, 1.4)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                    wrapMode: Text.WordWrap
                  }
                  Text {
                    width: parent.width
                    textFormat: Text.PlainText
                    text: Kub0.policyRefreshText(root.kub0)
                    visible: text.length > 0
                    color: Qt.darker(root.fg, 1.4)
                    font.family: root.fontFamily
                    font.pixelSize: root.ux.caption
                    wrapMode: Text.WordWrap
                  }
                }
                Column {
                  width: parent.width
                  spacing: Style.space(8 * root.ux.gap)
                  visible: root.kub0Connected
                  Repeater {
                    model: root.kub0NetRules
                    delegate: Column {
                      required property var modelData
                      width: settingsCol.width
                      spacing: Style.space(2 * root.ux.gap)
                      Text {
                        width: parent.width
                        text: modelData.label || "Unnamed rule"
                        textFormat: Text.PlainText
                        color: root.fg
                        font.family: root.fontFamily
                        font.pixelSize: root.ux.bodySmall
                        elide: Text.ElideRight
                      }
                      Text {
                        width: parent.width
                        text: Kub0.policyRuleDetail(modelData, root.ux, Date.now())
                        textFormat: Text.PlainText
                        color: Qt.darker(root.fg, 1.4)
                        font.family: root.fontFamily
                        font.pixelSize: root.ux.caption
                        wrapMode: Text.WordWrap
                      }
                      // Only where the org's policy allows it (user_can_snooze).
                      Button {
                        fontSize: root.ux.body
                        visible: modelData.canSnooze === true
                        text: modelData.snoozedUntil > 0 ? "Resume rule" : "Snooze for 1 hour"
                        foreground: root.fg
                        fontFamily: root.fontFamily
                        enabled: !!root.liveVallum
                        onClicked: modelData.snoozedUntil > 0
                          ? root.liveVallum.resumePolicyRule(modelData.id)
                          : root.liveVallum.snoozePolicyRule(modelData.id, 3600)
                      }
                    }
                  }
                }

                // A keymap is the most label/value thing on the screen, and it was
                // the worst offender: nine bindings middot-joined into one
                // paragraph, so finding "which key sorts" meant reading all nine.
                Text {
                  width: parent.width
                  text: "Keyboard"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }
                Column {
                  width: parent.width
                  spacing: Style.space(3 * root.ux.gap)
                  Repeater {
                    // A count, not the rows: see factRows.
                    model: root.keyboardFactRows.length
                    delegate: FactRow {
                      required property int index
                      readonly property var fact: root.keyboardFactRows[index] || ({})
                      label: fact.label || ""
                      value: fact.value || ""
                      tone: fact.tone || ""
                    }
                  }
                }


                PanelSeparator { width: parent.width }

                Text {
                  width: parent.width
                  text: "Where this is stored"
                  topPadding: root.padSection - settingsCol.spacing
                  color: root.fg
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.body
                  font.bold: true
                }

                Text {
                  width: parent.width
                  text: root.liveVallum && root.liveVallum.prefsPath
                    ? root.liveVallum.prefsPath
                    : "~/.config/kub0/ui.json"
                  textFormat: Text.PlainText
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WrapAnywhere
                }

                Text {
                  width: parent.width
                  visible: root.liveVallum && root.liveVallum.prefsError
                  text: root.liveVallum
                    ? "Last read failed (" + root.liveVallum.prefsError + "). Defaults were restored and written back."
                    : ""
                  color: root.badColor
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }

                Text {
                  width: parent.width
                  text: "Blocks are not settings and are not stored here—they are kernel rules. Manage them under Apps."
                  color: Qt.darker(root.fg, 1.4)
                  font.family: root.fontFamily
                  font.pixelSize: root.ux.caption
                  wrapMode: Text.WordWrap
                }

                Button {
                  fontSize: root.ux.body
                  text: "Reset to defaults"
                  foreground: root.fg
                  fontFamily: root.fontFamily
                  bordered: true
                  focusable: true
                  tooltipText: "Restores every preference on this screen. Does not touch any block."
                  onClicked: {
                    if (root.liveVallum && typeof root.liveVallum.resetPrefs === "function") {
                      root.liveVallum.resetPrefs()
                      var d = Prefs.defaults()
                      root.applySortFilter(d.sortKey, d.filterKey)
                    }
                  }
                }

            }
          }
        }

        ConfirmDialog {
          id: blockConfirmDialog
          anchors.fill: parent
          z: 21
          opened: root.pendingBlockApp !== ""
          focus: opened
          activeFocusOnTab: true
          message: "Block " + root.blockConfirmName() + "?\n\n" + root.blockConfirmPrograms() + "This installs a kernel firewall rule. The app loses outbound network until you unblock it from this panel."
          cancelText: "Cancel"
          confirmText: "Block"
          foreground: root.fg
          fontFamily: root.fontFamily
          onCanceled: root.cancelPendingBlock()
          onConfirmed: root.confirmPendingBlock()
          Keys.onPressed: function(event) {
            if (handleKey(event))
              event.accepted = true
          }
        }

        ConfirmDialog {
          id: confirmDialog
          anchors.fill: parent
          z: 20
          opened: root.confirmIps
          focus: opened
          activeFocusOnTab: true
          message: root.confirmIpsMessage()
          cancelText: "Cancel"
          confirmText: "Block IPs"
          foreground: root.fg
          fontFamily: root.fontFamily
          onCanceled: root.cancelIps()
          onConfirmed: root.confirmIpsBlock()
          Keys.onPressed: function(event) {
            if (handleKey(event))
              event.accepted = true
          }
        }
      }
    }
  }

  function uniqueCountries(app) {
    var seen = {}
    var out = []
    var cs = (app && app.connections) || []
    for (var i = 0; i < cs.length; i++) {
      var cc = cs[i].country
      if (cc && !seen[cc]) {
        seen[cc] = true
        out.push(cc)
      }
      if (out.length >= 4)
        break
    }
    return out
  }

  function connSummary(app) {
    var n = (app && app.connections) ? app.connections.length : 0
    var u = app && app.unresolved ? app.unresolved : 0
    if (app && app.dormant)
      return "block recorded · no traffic"
    var s = n + (n === 1 ? " connection" : " connections")
    if (u)
      s += " · " + u + " UDP unresolved"
    return s
  }

  /// The best name the daemon has for one peer, in provenance order.
  ///
  /// A user tag beats a machine clue beats reverse DNS beats the address,
  /// because the user is the authority on their own network and an address is
  /// what we show when we have failed to find an answer.
  ///
  /// Weak clues are deliberately NOT promoted here. `Weak` means the daemon
  /// inferred the label from a port or an address range rather than looking it
  /// up, and a summary line has no room to say "probably". Showing a hunch in
  /// the same typeface as a fact is how a naming feature starts lying; the
  /// weak guess still reaches the user, with its basis attached, wherever the
  /// row can afford to explain itself.
  // The naming rules live in js/Peers.js so they can be asserted -- see the
  // header there. Panel.qml only decides where they are drawn.
  function connPeerName(c) { return Peers.peerName(c) }
  function connDetail(app) { return Peers.summary(app) }
  function connPeers(app) { return Peers.peers(app) }
  function peerEvidence(p) { return Peers.peerEvidence(p) }
  function peerActionLabel(p) { return Peers.peerActionLabel(p) }

  function beginNaming(p) {
    if (!p || !p.networkKey)
      return
    root.namingKey = p.networkKey
    root.namingDraft = Peers.namingSeed(p)
    root.namingHadTag = !!(p.tagLabel && p.tagLabel.length > 0)
    root.namingKind = p.kind || "service"
  }

  // The editor belongs to the selected row. Selecting another app hides it,
  // and a naming state left behind would keep the shortcuts switched off.
  onSelectedAppIdChanged: if (namingKey !== "") cancelNaming()

  function cancelNaming() {
    var wasNaming = root.namingKey !== ""
    root.namingKey = ""
    root.namingDraft = ""
    root.namingHadTag = false
    // The field is about to hide; without this, focus stays on an invisible
    // item and the panel's keys stop working until something is clicked.
    if (wasNaming)
      keyCatcher.forceActiveFocus()
  }

  /// Send the name to the daemon. An empty label DELETES the tag -- that is the
  /// daemon's own contract (parse_tag_cmd), and it is the only way a user can
  /// take back a name they regret.
  function applyNaming() {
    var key = root.namingKey
    if (!key)
      return
    if (liveVallum && typeof liveVallum.tagNetwork === "function")
      liveVallum.tagNetwork(key, root.namingDraft.trim(), root.namingKind)
    cancelNaming()
  }

  function confirmIpsMessage() {
    var id = root.pendingIpsApp || "this app"
    var err = root.lastBlockError ? " " + root.lastBlockError + "." : ""
    return "Blocking this app's running processes failed for " + id + "." + err
      + " Block listed destination IPs host-wide for every app, not only this process tree?"
  }

  function blockStateLabel(app) {
    if (app && app.blocked) {
      if (app.mechanism === "endpoints")
        return "Destination block remembered this session"
      return "App block remembered this session"
    }
    if (root.isDemo)
      return "Demo—new block off"
    if (!root.dataCurrent)
      return "New block off"
    if (!root.blockingReady)
      return "Helper unavailable"
    if (!ConnectionModel.isBlockable(app))
      return "Not blockable"
    return "No block remembered this session"
  }

  function selectedBlockDetail(app) {
    if (app && app.blocked) {
      if (app.mechanism === "endpoints")
        return "Destination addresses blocked for the whole machine, as remembered this session. Unblock removes them. This is what this session remembers, not a readout of the kernel."
      return "This app's running processes are blocked, as remembered this session. Unblock removes it. This is what this session remembers, not a readout of the kernel."
    }
    if (root.canStartBlock(app))
      return "Block app stops this app's running processes. No block listed here means this session remembers none, not that the kernel has none."
    return ""
  }

  function cssAccent() {
    return "rgba(" + Math.round(root.accent.r * 255) + "," + Math.round(root.accent.g * 255) + "," + Math.round(root.accent.b * 255) + ",0.9)"
  }

  function launchHelperInstall() {
    if (!root.liveVallum)
      return
    root.liveVallum.installPrivilegedHelper()
    root.close()
  }

  function launchPackageInstall() {
    if (!root.liveVallum)
      return
    root.liveVallum.installBlockingPackages()
    root.close()
  }

  function launchDaemonBuild() {
    if (!root.liveVallum)
      return
    root.liveVallum.buildVallumd()
    root.close()
  }

  function launchReleaseInstall() {
    if (!root.liveVallum)
      return
    root.liveVallum.installRelease()
    root.close()
  }

  function setupTitle() {
    return Setup.title(setupStage)
  }

  function setupBody() {
    return Setup.body(setupStage, panelVersion)
  }
}
