import QtQuick
import Quickshell
import qs.Commons
import "Fixture.js" as Fixture

Scope {
  id: harness
  property var target: null
  property var checkedList: null
  property string expectedSelection: ""
  property real expectedScroll: 0
  QtObject {
    id: bar
    property string position: "top"
    property int barSize: 26
    property bool vertical: false
    property string fontFamily: "sans-serif"
    // The sandbox has no theme, so the kit's foreground and background come out
    // the same; a screenshot needs text a person can see.
    property color foreground: Quickshell.env("VALLUM_CHECK") === "ux-shots" ? "#e8e8e8" : Color.foreground
    property color barForeground: foreground
    property color background: Color.background
    property color urgent: Color.urgent
    property bool foregroundAnimationEnabled: false
    property var activePopout: null
    function requestPopout(owner) { activePopout = owner }
    function releasePopout(owner) { if (activePopout === owner) activePopout = null }
    function switchPanelFrom(owner, direction) { console.log("HARNESS_TAB", direction); return true }
  }
  function findAppList(item) {
    if (String(item).indexOf("ListView") >= 0 && item.count > 10) return item;
    if (item.children) for (let i = 0; i < item.children.length; i++) {
      let found = findAppList(item.children[i]);
      if (found) return found;
    }
    return null;
  }
  function findText(item, text, contains) {
    if (item.text !== undefined && (contains ? String(item.text).indexOf(text) >= 0 : item.text === text)) return item;
    if (item.children) for (let i = 0; i < item.children.length; i++) {
      let found = findText(item.children[i], text, contains);
      if (found) return found;
    }
    return null;
  }
  function effectivelyVisible(item) {
    if (!item) return false;
    for (let ancestor = item; ancestor; ancestor = ancestor.parent)
      if (ancestor.visible === false) return false;
    return true;
  }
  function visibleAge(text) {
    for (let i = 0; i < harness.target.data.length; i++) {
      let obj = harness.target.data[i];
      if (obj.contentItem && obj.contentItem.length) for (let j = 0; j < obj.contentItem.length; j++) {
        let label = harness.findText(obj.contentItem[j], text, true);
        if (effectivelyVisible(label)) return String(label.text);
      }
    }
    return "";
  }
  function findNamed(item, name) {
    if (item.objectName === name) return item;
    if (item.children) for (let i = 0; i < item.children.length; i++) {
      let found = findNamed(item.children[i], name);
      if (found) return found;
    }
    return null;
  }
  function panelNamed(name) {
    for (let i = 0; i < target.data.length; i++) {
      let obj = target.data[i];
      if (obj.contentItem && obj.contentItem.length) for (let j = 0; j < obj.contentItem.length; j++) {
        let found = findNamed(obj.contentItem[j], name);
        if (found) return found;
      }
    }
    return null;
  }
  function point(name) {
    let item = panelNamed(name);
    if (!item) return null;
    let p = item.mapToItem(null, item.width / 2, Math.min(item.height / 2, 25));
    return {x:p.x, y:p.y};
  }
  QtObject {
    id: fake
    property string policyDaemonMode: "user"
    property string prefsError: ""
    // Null until a check writes a preference: the panel then runs on its own
    // defaults, as it always has here. setPref mirrors Service.qml in handing
    // the panel a NEW object, which is what makes its bindings re-evaluate.
    property var prefs: null
    function setPref(key, value) {
      let next = {};
      let base = prefs || harness.target.prefs;
      for (let k in base) next[k] = base[k];
      next[key] = value;
      prefs = next;
      return value;
    }
    property int modelRevision: 0
    property var model: Fixture.models[Quickshell.env("VALLUM_SCENARIO") || "populated"]
    property int activeCount: model.count
    property string daemonStatus: monitoring === "unavailable" ? "missing" : monitoring === "connecting" ? "reconnecting" : "connected"
    property string monitoring: Quickshell.env("VALLUM_HEALTH") || "current"
    property bool dataCurrent: monitoring === "current"
    property bool snapshotReady: dataCurrent || monitoring === "stale"
    property int observationAgeMs: 65000
    property string observationAgeText: "65s ago"
    property int healthTick: 1
    property string barLabel: dataCurrent ? (activeCount ? "On" : "Idle") : monitoring === "stale" ? "Stale" : "Off"
    property string barTooltip: "Synthetic fixture: " + monitoring
    property bool usingFallback: false
    property bool blockingReady: Quickshell.env("VALLUM_BLOCK_READY") === "1"
    property bool needsHelperInstall: false
    property bool needsBlockingPackages: false
    property bool helperInstallPending: false
    property bool offerBinds: false
    property string offerNote: ""
    property string setupWatchFor: ""
    property string digestText: ""
    property string coverage: "TCP + connected UDP"
    property string blockHint: ""
    property string pendingIpsApp: ""
    property bool helperBusy: false
    property var temporaryRules: []
    property string temporaryRulesError: ""
    function cancelDestinationBlock(app, ip) { console.log("SCOPED_CANCEL", app, ip) }
    property string lastBlockError: ""
    property var kub0: ({
      connected: Quickshell.env("VALLUM_KUB0") === "1",
      githubUsername: "alice",
      nodeName: "fixture-host",
      lastHeartbeatOk: true,
      lastHeartbeatTs: Date.now() - 5000,
      orgEndpoints: 3,
      nodeLimit: 10,
      selfState: "monitored",
      endpointsUpdatedAt: Date.now() - 5000,
      endpointsRefreshOk: Quickshell.env("VALLUM_ENDPOINT_CASE") !== "failed",
      endpoints: [
        {nodeName:"fixture-host", state:"enforcing", lastSeen:new Date().toISOString(), agentVer:"0.2.0", blocksActive:3, kernelVersion:"6.12", arch:"x86_64"},
        {nodeName:"fixture-remote", state:"monitoring", lastSeen:new Date().toISOString(), agentVer:"0.2.0", blocksActive:0, kernelVersion:"6.12", arch:"aarch64"},
        {nodeName:"fixture-offline", state:"down", lastSeen:"2026-01-01T00:00:00Z", agentVer:"0.1.0", blocksActive:null, kernelVersion:"", arch:""}
      ],
      denylistVersion: 7,
      denylist: [{ comm: "curl", path: "/usr/bin/curl", action: "deny", reason: "org policy" }]
    })
    property var historyEntries: []
    property bool historyMore: false
    property bool historyBusy: false
    property string historyError: ""
    function requestHistory(query, hours) {
      var conn = Fixture.appRow(0).connections[0]
      conn.exe = "/usr/bin/fixture-probe"
      historyEntries = [{ key: "fixture-history", firstObserved: Date.now() - 60000,
        lastObserved: Date.now() - 30000, active: false, connection: conn, bytes: { tx: 1024, rx: 65536 } }]
    }
    property int kub0Revision: 1
    property string connectState: "idle"
    property string connectCode: ""
    property string connectUrl: ""
    property var connectExpiresAt: 0
    property string connectError: ""
    property bool helperInstalled: true
    property bool polkitAgentPresent: true
    property bool blockingToolsReady: true
    function requestConnect() { console.log("HARNESS_CONNECT") }
    function requestDisconnect() { console.log("HARNESS_DISCONNECT") }
    function openConnectUrl() { console.log("HARNESS_OPEN_CONNECT") }
    function cancelConnect() { console.log("HARNESS_CANCEL_CONNECT") }
    property string pluginDir: Quickshell.env("VALLUM_CANDIDATE_DIR")
    property string worldDataPath: pluginDir + "/data/world-paths.json"
    property var origin: ({ lat: 4.61, lon: -74.08 })
    function markLooked() {}
    // Only the picture's scenario has anywhere to draw an arc to.
    function drawableArcs() { return Quickshell.env("VALLUM_SCENARIO") === "showcase" ? Fixture.arcs(model) : [] }
    function appIcon(app) { return "" }
    function appById(id) { return model.apps[id] || null }
    function requestBlock(id) { console.log("HARNESS_BLOCK", id) }
    function requestBlockIps(id) { console.log("HARNESS_ENDPOINTS", id) }
  }
  Timer {
    interval: 100
    running: harness.target !== null && Quickshell.env("VALLUM_CHECK") === "endpoints-native"
    repeat: true
    onTriggered: {
      let view = harness.panelNamed("endpointsView");
      if (!view) return;
      harness.target.selectedAppId = "fixture-0";
      harness.target.toggleSelectedBlock();
      console.log("ENDPOINT_NATIVE_STATE", JSON.stringify({
        view: harness.target.panelView, opened:harness.target.opened, filter:view.stateFilter, selected:view.selectedName,
        query:view.query, searchFocused:view.searchFocused,
        rows:view.rows.map(function(row) {return row.nodeName}),
        status:harness.panelNamed("endpointInventoryStatus").text,
        pendingBlock:harness.target.pendingBlockApp,
        thisDevice:harness.visibleAge("fixture-host · this device"),
        points:{monitoring:harness.point("endpointFilter_monitoring"),offline:harness.point("endpointFilter_offline"),
          self:harness.point("endpointRow_fixture-host"), search:harness.point("endpointSearch"), tab:harness.point("endpointsTab")}
      }));
    }
  }
  Timer {
    interval: 80
    running: true
    onTriggered: {
      let c = Qt.createComponent("file://" + fake.pluginDir + "/Panel.qml");
      if (c.status !== Component.Ready) { console.error("HARNESS_LOAD_ERROR", c.errorString()); Qt.quit(); return; }
      // For a screenshot the panel has to live in a window; every check runs it bare.
      let host = Quickshell.env("VALLUM_CHECK") === "ux-shots" ? shotWindow.contentItem : harness;
      harness.target = c.createObject(host, { bar: bar, vallum: fake, pluginDir: fake.pluginDir });
      if (!harness.target) { console.error("HARNESS_CREATE_FAILED", c.errorString()); Qt.quit(); return; }
      harness.target.open();
      if (Quickshell.env("VALLUM_VIEW") === "scoped") {
        var scoped = Fixture.appRow(0);
        scoped.id = "com.discordapp.Discord"; scoped.name = "Discord";
        scoped.pids = []; scoped.connections = []; scoped.hasTemporaryRule = true;
        var retained = Fixture.modelWith(0);
        retained.apps[scoped.id] = scoped; retained.ordered = [scoped];
        fake.model = retained; fake.modelRevision += 1;
        fake.temporaryRules = [{app:"com.discordapp.discord",ip:"127.0.0.1",expiresAt:Date.now()+600000}];
        harness.target.selectedAppId = scoped.id;
        scopedCancel.start();
      }
      if (harness.target.panelView !== undefined)
        harness.target.panelView = ["evidence", "scoped"].indexOf(Quickshell.env("VALLUM_VIEW")) >= 0 ? "apps" : (Quickshell.env("VALLUM_VIEW") || "overview");
      if (Quickshell.env("VALLUM_CONFIRM_TARGET"))
        fake.pendingIpsApp = Quickshell.env("VALLUM_CONFIRM_TARGET");
      console.log("HARNESS_PANEL_OPEN", harness.target.opened);
      if (Quickshell.env("VALLUM_VIEW") === "evidence") evidenceOpen.start();
      let check = Quickshell.env("VALLUM_CHECK") || "";
      if (check === "selection-scroll") exercise.start();
      if (check === "selection-disappears") disappear.start();
      if (check === "age-timer") ageProbe.start();
      if (check === "search-while-typing") searchProbe.start();
      if (check === "scroll-settings") { harness.target.panelView = "settings"; scrollProbe.start(); }
      if (check === "ux-settings") { harness.target.panelView = "settings"; uxProbe.start(); }
      if (check === "ux-shots") {
        let spec = (Quickshell.env("VALLUM_UX") || "").split(",");
        let keys = ["textSize", "density", "panelWidth", "panelHeight", "timeStyle", "byteUnits"];
        for (let i = 0; i < keys.length; i++) if (spec[i]) fake.setPref(keys[i], spec[i]);
        shotTimer.start();
      }
      if (check === "hold-defers") holdProbe.start();
      if (check === "policy-status") {
        harness.target.panelView = "settings";
        fake.kub0 = {connected:true, netpolicies:[], netpolicyRefreshOk:false,
          netpolicyEnforcement:{state:"error",enforcing:false,reason:"<b>rules left in place</b>"}};
        fake.blockingReady = true;
        policyProbe.start();
      }
      if (check === "protection") {
        harness.target.panelView = "settings";
        fake.kub0.connected = true;
        fake.kub0Revision++;
      }
      finish.start();
    }
  }
  property int policyStep: 0
  property int policyFailures: 0
  function policyAssert(name, ok) {
    console.log("POLICY_ASSERT", name, ok);
    if (!ok) policyFailures++;
  }
  Timer {
    id: policyProbe
    interval: 180
    repeat: true
    onTriggered: {
      let status = harness.panelNamed("policyEnforcementStatus");
      let role = harness.panelNamed("policyDaemonRole");
      if (policyStep === 0) {
        policyAssert("empty error rendered", effectivelyVisible(status) && status.text.indexOf("Policy error:") === 0 && harness.target.kub0NetRules.length === 0);
        policyAssert("reason plain text", effectivelyVisible(status) && status.textFormat === Text.PlainText && status.text.indexOf("<b>rules left in place</b>") >= 0);
        policyAssert("user role separate from ready helper", effectivelyVisible(role) && role.text.indexOf("User daemon") === 0 && role.text.indexOf("unavailable") >= 0 && fake.blockingReady);
        fake.kub0 = {connected:true, netpolicyRefreshOk:false, netpolicies:[{id:"p",rules:[{id:"r",label:"Fixture rule",kind:"ip",hits:3,blocked:2,effectiveAction:"block",enforced:true}]}],
          netpolicyEnforcement:{state:"enforcing",enforcing:true,entries:2,appliedTs:1234}};
      } else if (policyStep === 1) {
        policyAssert("known plan retained", effectivelyVisible(status) && status.text.indexOf("Known applied plan:") === 0 && harness.visibleAge("Retaining the known applied plan.").length > 0);
        policyAssert("connection match wording", harness.visibleAge("matches to the known applied block plan").length > 0);
        fake.policyDaemonMode = "unknown";
        fake.kub0 = {connected:false};
        fake.blockingReady = true;
      } else if (policyStep === 2) {
        policyAssert("legacy role unknown despite helper readiness", effectivelyVisible(role) && role.text.indexOf("Daemon role unknown") === 0 && fake.blockingReady);
        policyAssert("disconnect no protection claim", effectivelyVisible(status) && status.text.indexOf("Policy enforcement unknown") === 0);
        fake.kub0 = {connected:false, netpolicies:[], netpolicyRefreshOk:false,
          netpolicyEnforcement:{state:"error",enforcing:false,reason:"disconnect cleanup failed"}};
        fake.policyDaemonMode = "system";
      } else {
        policyAssert("disconnected cleanup error visible", effectivelyVisible(status) && status.text.indexOf("Policy error:") === 0 && status.text.indexOf("disconnect cleanup failed") >= 0 && harness.target.kub0NetRules.length === 0);
        policyAssert("explicit system role", effectivelyVisible(role) && role.text.indexOf("System daemon reported") === 0);
        console.log("POLICY_NATIVE_RESULT", JSON.stringify({ok:policyFailures === 0, failures:policyFailures}));
        stop();
      }
      fake.kub0Revision++;
      policyStep++;
    }
  }
  Timer {
    id: ageProbe
    interval: 350
    onTriggered: {
      console.log("HARNESS_AGE_BEFORE", harness.visibleAge("65s ago"));
      fake.observationAgeMs = 66000;
      fake.observationAgeText = "66s ago";
      fake.healthTick = 2;
      Qt.callLater(function() {
        console.log("HARNESS_AGE_AFTER", harness.visibleAge("66s ago"), "revision", fake.modelRevision);
      });
    }
  }
  // A focused search field sets searchOpen, and searchOpen engages the list,
  // which holds back structural changes. Typing is the user asking for a new
  // list, so the rows must filter while the field still has focus, not only
  // after it loses focus.
  Timer {
    id: searchProbe
    interval: 350
    onTriggered: {
      harness.target.panelView = "apps";
      harness.target.searchOpen = true;
      harness.target.searchQuery = Quickshell.env("VALLUM_QUERY") || "Firefox";
      searchResult.start();
    }
  }
  Timer {
    id: searchResult
    interval: 250
    onTriggered: {
      let ids = [];
      for (let i = 0; i < harness.target.renderedLen(); i++)
        ids.push(harness.target.renderedAppAt(i).id);
      console.log("HARNESS_SEARCH", JSON.stringify({
        searchOpen: harness.target.searchOpen,
        filtered: harness.target.apps.map(function(a) { return a.id; }),
        rendered: ids
      }));
    }
  }
  // Screenshots, for a person looking at a layout change (run-runtime.sh,
  // VALLUM_SHOTS). No check reads the picture.
  Window {
    id: shotWindow
    visible: Quickshell.env("VALLUM_CHECK") === "ux-shots"
    width: 1000
    height: 1200
    color: "#16161a"
  }
  Timer {
    id: shotTimer
    interval: 900
    onTriggered: {
      shotWindow.contentItem.grabToImage(function(result) {
        console.log("HARNESS_SHOT", result.saveToFile(Quickshell.env("VALLUM_SHOT")), JSON.stringify(harness.target.ux));
        Qt.quit();
      });
    }
  }
  // Settings > Text and spacing, Panel size, Time and units: each choice is on the page showing
  // the default; a pick reaches the store, the sizes the panel lays out with
  // (root.ux) and the size the panel asks the shell for.
  property var uxBefore: null
  function uxState() {
    let out = { ux: harness.target.ux, shown: true, selected: {}, choices: {} };
    let names = { textSizeChoice: "textSize", densityChoice: "density", panelWidthChoice: "panelWidth", panelHeightChoice: "panelHeight",
                  timeStyleChoice: "timeStyle", byteUnitsChoice: "byteUnits" };
    for (let n in names) {
      let pick = harness.panelNamed(n);
      if (!pick || !pick.visible) { out.shown = false; continue; }
      out.selected[names[n]] = pick.value;
      out.choices[names[n]] = pick.options.map(function(o) { return o.value; });
    }
    for (let i = 0; i < harness.target.data.length; i++) {
      let obj = harness.target.data[i];
      if (obj && obj.contentWidth !== undefined && obj.fittedContentWidth) out.size = [obj.contentWidth, obj.contentHeight];
    }
    out.saved = fake.prefs ? { textSize: fake.prefs.textSize, density: fake.prefs.density, panelWidth: fake.prefs.panelWidth, panelHeight: fake.prefs.panelHeight,
                               timeStyle: fake.prefs.timeStyle, byteUnits: fake.prefs.byteUnits } : null;
    // What the formatters the panel hands to js/ print for one size and one time 90 s back.
    let u = harness.target.ux;
    out.prints = { bytes: u.bytes ? u.bytes(1500000) : null, time: u.time ? u.time(Date.now() - 90000, Date.now()) : null };
    return out;
  }
  Timer {
    id: uxProbe
    interval: 350
    onTriggered: {
      harness.uxBefore = harness.uxState();
      let picks = { textSizeChoice: "larger", densityChoice: "compact", panelWidthChoice: "wide", panelHeightChoice: "tall",
                    timeStyleChoice: "relative", byteUnitsChoice: "decimal" };
      for (let n in picks) { let pick = harness.panelNamed(n); if (pick) pick.changed(picks[n]); }
      uxResult.start();
    }
  }
  Timer {
    id: uxResult
    interval: 250
    onTriggered: console.log("HARNESS_UX_SETTINGS", JSON.stringify({ before: harness.uxBefore, after: harness.uxState() }))
  }
  // Settings > Scrolling: the speed chips and the momentum switch are on the
  // page, a pick reaches the preference store, and the panel hands the new
  // value to its wheel handlers (root.scrollSpeed / root.scrollMomentum are
  // what every WheelStep binds to).
  property var scrollBefore: null
  Timer {
    id: scrollProbe
    interval: 350
    onTriggered: {
      let pick = harness.panelNamed("scrollSpeedChoice");
      let toggle = harness.panelNamed("scrollMomentumToggle");
      harness.scrollBefore = {
        shown: !!pick && pick.visible && !!toggle && toggle.visible,
        choices: pick ? pick.options.map(function(o) { return o.value; }) : [],
        selected: pick ? pick.value : null,
        speed: harness.target.scrollSpeed,
        momentum: harness.target.scrollMomentum,
        checked: toggle ? toggle.checked : null
      };
      if (pick) pick.changed("fastest");
      if (toggle) toggle.toggled();
      scrollResult.start();
    }
  }
  Timer {
    id: scrollResult
    interval: 250
    onTriggered: {
      let pick = harness.panelNamed("scrollSpeedChoice");
      let toggle = harness.panelNamed("scrollMomentumToggle");
      console.log("HARNESS_SCROLL_SETTINGS", JSON.stringify({
        before: harness.scrollBefore,
        after: {
          selected: pick ? pick.value : null,
          speed: harness.target.scrollSpeed,
          momentum: harness.target.scrollMomentum,
          checked: toggle ? toggle.checked : null,
          saved: fake.prefs ? { scrollSpeed: fake.prefs.scrollSpeed, scrollMomentum: fake.prefs.scrollMomentum } : null
        }
      }));
    }
  }
  // The pair to searchProbe: a query change bypasses the engagement hold, so
  // prove the hold still holds a BACKGROUND change (query unchanged): an app
  // disappearing while the pointer is on the list. Rows sort by name, so a
  // reordered `ordered` array would render identically and prove nothing; a
  // removal is structural under every sort. The row stays while engaged, then
  // goes once released.
  function renderedIds() {
    let ids = [];
    for (let i = 0; i < harness.target.renderedLen(); i++)
      ids.push(harness.target.renderedAppAt(i).id);
    return ids;
  }
  property var holdBefore: []
  Timer {
    id: holdProbe
    interval: 350
    onTriggered: {
      harness.target.panelView = "apps";
      harness.holdBefore = harness.renderedIds();
      harness.target.listHold = true;
      let next = JSON.parse(JSON.stringify(fake.model));
      delete next.apps["fixture-3"];
      next.ordered = next.ordered.filter(function(app) { return app.id !== "fixture-3"; });
      fake.model = next;
      fake.modelRevision++;
      holdHeld.start();
    }
  }
  Timer {
    id: holdHeld
    interval: 250
    onTriggered: {
      console.log("HARNESS_HOLD_HELD", JSON.stringify({
        before: harness.holdBefore,
        during: harness.renderedIds(),
        pending: harness.target.pendingResync
      }));
      harness.target.listHold = false;
      holdReleased.start();
    }
  }
  Timer {
    id: holdReleased
    interval: 250
    onTriggered: {
      console.log("HARNESS_HOLD_RELEASED", JSON.stringify({
        after: harness.renderedIds(),
        want: harness.target.apps.map(function(a) { return a.id; }),
        pending: harness.target.pendingResync
      }));
    }
  }
  Timer {
    id: evidenceOpen
    interval: 250
    onTriggered: {
      var clicked=false;
      for (var i=0; i<harness.target.data.length && !clicked; i++) {
        var obj=harness.target.data[i];
        if (obj.contentItem && obj.contentItem.length) for (var j=0; j<obj.contentItem.length && !clicked; j++) {
          var button=harness.findText(obj.contentItem[j],"Connection evidence",false);
          if (button && button.clicked && button.visible) {button.clicked();clicked=true;}
        }
      }
      console.log("EVIDENCE_DRAWER_OPEN",clicked && harness.target.evidenceApp !== null);
    }
  }
  Timer {
    id: scopedCancel
    interval: 250
    onTriggered: {
      var clicked=false;
      for (var i=0; i<harness.target.data.length && !clicked; i++) {
        var obj=harness.target.data[i];
        if (obj.contentItem && obj.contentItem.length) for (var j=0; j<obj.contentItem.length && !clicked; j++) {
          var button=harness.findText(obj.contentItem[j],"Cancel destination rule",false);
          if (button && button.clicked && button.visible && button.enabled) {button.clicked();clicked=true;}
        }
      }
      console.log("SCOPED_CANCEL_CONTROL",clicked);
    }
  }
  Timer {
    id: disappear
    interval: 350
    onTriggered: {
      harness.target.panelView = "apps";
      let selected = Quickshell.env("VALLUM_SELECTED") || "fixture-0";
      if (Quickshell.env("VALLUM_QUERY"))
        harness.target.searchQuery = Quickshell.env("VALLUM_QUERY");
      harness.target.selectedAppId = selected;
      let next = JSON.parse(JSON.stringify(fake.model));
      delete next.apps[selected];
      next.ordered = next.ordered.filter(function(app) { return app.id !== selected; });
      fake.model = next;
      fake.modelRevision++;
      console.log("HARNESS_REMOVED_SELECTION", selected, harness.target.selectedAppId);
    }
  }
  Timer {
    id: exercise
    interval: 350
    onTriggered: {
      harness.expectedSelection = "fixture-15";
      harness.target.selectedAppId = harness.expectedSelection;
      for (let i = 0; i < harness.target.data.length; i++) {
        let obj = harness.target.data[i];
        if (obj.contentItem && obj.contentItem.length) for (let j = 0; j < obj.contentItem.length; j++) {
          let list = harness.findAppList(obj.contentItem[j]);
          if (list) harness.checkedList = list;
        }
      }
      if (!harness.checkedList) { console.error("HARNESS_CHECK_NO_LIST"); return; }
      harness.checkedList.contentY = 240;
      harness.expectedScroll = harness.checkedList.contentY;
      let next = JSON.parse(JSON.stringify(fake.model));
      next.ordered.reverse();
      fake.model = next;
      fake.modelRevision++;
      checkResult.start();
    }
  }
  Timer {
    id: checkResult
    interval: 200
    onTriggered: {
      console.log("HARNESS_SELECTION", harness.target.selectedAppId === harness.expectedSelection, harness.target.selectedAppId);
      console.log("HARNESS_SCROLL", Math.abs(harness.checkedList.contentY - harness.expectedScroll) < 1, harness.expectedScroll, harness.checkedList.contentY);
      fake.pendingIpsApp = "fixture-15";
      harness.target.close();
      console.log("HARNESS_CLOSE_CANCEL", fake.pendingIpsApp === "", fake.pendingIpsApp);
    }
  }
  Timer {
    id: finish
    interval: Number(Quickshell.env("VALLUM_HOLD_MS")) || 1400
    onTriggered: {
      console.log("HARNESS_FINAL_STATE", JSON.stringify({
        view: harness.target.panelView,
        selected: harness.target.selectedAppId,
        searchOpen: harness.target.searchOpen,
        query: harness.target.searchQuery,
        confirm: harness.target.confirmIps,
        pending: fake.pendingIpsApp,
        notBlockedLiteral: false
      }));
      console.log("HARNESS_WORDING", harness.visibleAge("No session-known block"), harness.visibleAge("Not blocked —"));
      console.log("HARNESS_PROTECTION",
        harness.visibleAge("kub0 endpoint:"),
        harness.visibleAge("Per-app helper"),
        harness.visibleAge("Fleet policy"));
      Qt.quit();
    }
  }
}
