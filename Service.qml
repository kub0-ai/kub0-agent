import QtQuick
import Quickshell
import Quickshell.Io
import "ConnectionModel.js" as ConnectionModel
import "Geo.js" as Geo
import "js/Binds.js" as Binds
import "js/Control.js" as Control
import "js/Health.js" as Health
import "js/Activity.js" as Activity
import "js/Kub0.js" as Kub0
import "js/Prefs.js" as Prefs
import "js/SystemStatus.js" as SystemStatus
import "js/Setup.js" as Setup

Item {
  id: root

  property var shell: null
  property var manifest: null
  property var pluginRegistry: null
  property string omarchyPath: ""

  readonly property string pluginId: "ai.kub0.agent"
  readonly property string coverage: model.coverage || "TCP + connected UDP"

  property var model: ConnectionModel.emptyState()
  property var systemDiagnostics: SystemStatus.empty()
  property int systemStatusGeneration: 0
  property int systemStatusActiveGeneration: 0
  property bool systemStatusTimedOut: false
  readonly property string systemProtectionText: SystemStatus.text(systemDiagnostics, healthTick)
  property var health: Health.emptyHealth()
  property int modelRevision: 0
  property int activeCount: 0
  property bool pulse: false
  property bool anyBlocked: false
  property string digestText: ""
  property string daemonStatus: "starting"
  property bool daemonAvailable: false
  property bool daemonRunning: daemonProc.running
  property var eventSock: null
  property int socketGeneration: 0
  property bool shuttingDown: false
  property bool socketConnected: !!eventSock && eventSock.connected
  property bool panelVisible: false
  property bool usingFallback: false
  property bool polkitAgentPresent: false
  property bool helperInstalled: false
  property bool blockingToolsReady: false
  // kub0's own drops are bypassed while this is true; the block list is
  // kept and returns on resume. Read from the helper's status, which sees the
  // marker file even without privilege.
  property bool enforcementPaused: false
  // The helper's nameservers and default gateways (status `hostCritical`). It
  // refuses to block these host-wide, so the panel never offers them.
  property var hostCriticalIps: []
  // A change in flight on any path: the helper (fallback), a control request
  // to the system daemon, or pkexec kub0.
  readonly property bool helperBusy: blockProc.running || kub0Proc.running || changeInFlight !== null
  property bool helperStatusFailed: false
  property bool helperStatusParsed: false
  property int helperBlockCount: 0
  property var temporaryRules: []
  property string temporaryRulesError: ""
  property int helperMutationGeneration: 0
  property int statusRequestGeneration: 0
  property bool statusRefreshPending: false
  property string blockingToolsHint: ""
  property bool blockingReady: polkitAgentPresent && helperInstalled && daemonAvailable && blockingToolsReady
  // The helper the fallback runs through pkexec. One path: a 0.4.x system
  // install's helper is not run any more (`kub0 install` replaces it).
  readonly property var helperPaths: ["/usr/lib/kub0/kub0-block"]
  property string canonicalHelper: helperPaths[0]
  // Absolute: a bare "pkexec" resolves through the user's PATH, where the
  // user's own writable directories come first, and whatever answers there is
  // handed the password prompt. Writable only so the runtime harness can pass
  // its refusing fake (tests/qml/fake-plugin/bin/pkexec) explicitly.
  property string pkexecPath: "/usr/bin/pkexec"
  // Changes go to the system daemon (js/Control.js): a raise as a control
  // request on a request-only connection to its socket, a lowering change
  // through `pkexec <kub0Path> --json …`. Writable only for the harness.
  property string systemSocketPath: "/run/kub0/kub0.sock"
  property string kub0Path: Control.KUB0
  property bool kub0Installed: false
  // The version the daemon gave in its greeting ("" until one arrives, and
  // again once that connection is gone), and this panel's, from its manifest.
  // They are installed separately, so they can differ.
  property string daemonVersion: ""
  readonly property string panelVersion: manifest && typeof manifest.version === "string" ? manifest.version : ""
  readonly property var versionSkew: Setup.skew(panelVersion, daemonVersion, eventSource)
  // Whether this login session is in the kub0 group, which is what lets it
  // read the system daemon: "in", "relogin" (the account is a member and this
  // session began before it was), "out", or "unknown" until asked.
  property string sessionGroup: "unknown"
  // What stands between this panel and a daemon it can read, for the
  // first-run screen: "install" (no kub0 on this machine and none built
  // here), "relogin", "group", "unreachable" (installed, this session may
  // read it, and there is still no system daemon to read: stopped, or too
  // old for this panel), or "" when there is nothing to set up.
  readonly property string setupStage: Setup.stage({
    fallback: usingFallback,
    shuttingDown: shuttingDown,
    daemonStatus: daemonStatus,
    source: eventSource,
    installed: kub0Installed,
    ownDaemon: vallumdPath !== "",
    sessionGroup: sessionGroup
  })
  // The request-only connection: never fed to ingest(), opened for a change
  // and closed when idle, so the system daemon's broadcast of every user's
  // rows is not read between changes.
  property var sysSock: null
  property int sysGeneration: 0
  property string sysState: "idle"
  property var sysWaiters: []
  property var sysPending: ({})
  property int sysSerial: 0
  property var changeInFlight: null
  property var kub0Exit: ({})
  property string connectVia: ""
  // Where the event stream comes from (#61, one daemon).
  //   "system": the system daemon's socket, read directly. The panel starts
  //             no kub0d of its own and shows what `kub0 apps` shows: the
  //             whole host.
  //   "user":   the daemon this panel starts, as before. Chosen when no
  //             system daemon can be used from this session (not installed,
  //             or not in group kub0), and while capture is switched on,
  //             which only the panel's own daemon can run.
  property string eventSource: "user"
  // The panel's own kub0d is running (never, while it reads the system daemon).
  readonly property bool ownDaemonRunning: daemonProc.running
  // This session's uid as the system daemon sees it (its `status` reply), or -1
  // before the first read. The whole host's rows are shown; a block names only
  // this account's processes.
  property int sessionUid: -1
  // Consecutive failed connects to the system daemon's socket. A restart of
  // that daemon is over in a second; past a few tries the source is chosen again.
  property int systemStreamFailures: 0
  // The kub0 found next to kub0d (the plugin's bin/, a build tree, or PATH):
  // the panel logs its own user daemon in and out through it when no system
  // daemon is reachable (the daemon's own `connect` verb is retired, #61 step 2).
  property string localKub0Path: ""
  // The user daemon's account and policies, as its frames report them; `kub0`
  // is this with the system daemon's view laid over it when that is reachable
  // (publishKub0).
  property var userKub0: Kub0.emptyKub0()
  // The system daemon's `status`, `policies` and `rules`, read over the
  // request connection on panel open and after an account or policy change;
  // null when it is not reachable (a user-only install).
  property var systemView: null
  property bool systemViewPending: false
  // A policy change went through `pkexec kub0` because this session cannot
  // read the system daemon: the list shown is not the one that changed.
  property bool policyViewBlind: false
  // Where the last name went, when it did not reach both daemons.
  property string tagNotice: ""
  property var connectBuffer: []
  property bool connectPending: false
  readonly property bool needsHelperInstall: !helperInstalled
  readonly property bool needsBlockingPackages: helperInstalled && !blockingToolsReady
  property bool helperInstallPending: false
  // The file a setup terminal leaves when its command has ended, whatever it
  // achieved ("" when none is open, or this session has no runtime dir).
  property string setupDoneFile: ""
  property int helperWatchTicks: 0
  property string setupWatchFor: ""
  property string blockHint: !helperInstalled
    ? "block helper not installed — click Install"
    : (!polkitAgentPresent
        ? "no polkit agent — monitoring only"
        : (!blockingToolsReady
            ? (blockingToolsHint || "install nftables and conntrack-tools (cgroup v2 required) — monitoring still works")
            : ""))
  property string pluginDir: adapter.pluginDir(manifest)
  property string worldDataPath: pluginDir ? pluginDir + "/data/world-paths.json" : ""
  property string replayPath: pluginDir ? pluginDir + "/data/replay.ndjson" : ""
  property var origin: ({ lat: 48.0, lon: 10.0 })
  property string lastBlockError: ""
  property string pendingIpsApp: ""
  property int restarts: 0
  property string vallumdPath: ""
  property string helperPath: ""
  property bool offerBinds: true
  property string offerNote: "Set Super+Alt+S to open kub0"
  property var workQueue: []
  property var workCurrent: null

  property string monitoring: "unavailable"
  property bool snapshotReady: false
  property bool dataCurrent: false
  property string barLabel: "Off"
  property string barTooltip: "kub0—waiting for service"
  property var lastFreshAt: 0
  property var lastSnapshotAt: 0
  property int observationAgeMs: 0
  property string observationAgeText: ""
  property real healthTick: Date.now()
  property int socketRetryAttempts: 0
  property var historyEntries: []
  property bool historyMore: false
  property string historyError: ""
  property bool historyBusy: false
  property string historyRequest: ""
  property int historySerial: 0
  property string historyQuery: ""
  property int historyHours: 24
  property var captureStatus: ({ state: "off", detail: "Optional capture is off", kernelDropped: 0, userspaceDropped: 0, invalid: 0 })
  property var activityEntries: []
  property int activityRevision: 0
  // Local intelligence (docs/INTEL.md): listening sockets, the user's watch
  // rules, and the reply to the last investigate request. All additive frames;
  // Health ignores types it does not know, so these are read here.
  property var listeners: []
  property int listenersRevision: 0
  property var watchRules: []
  property string watchError: ""
  property int watchRevision: 0
  property var timelineResult: null
  property int timelineHours: 24
  property string timelineError: ""
  property bool timelineBusy: false
  property string timelineRequest: ""
  property int timelineSerial: 0
  property var investigateResult: null
  property string investigateSubject: ""
  property string investigateError: ""
  property bool investigateBusy: false
  property string investigateRequest: ""
  property int investigateSerial: 0
  // Counted, but currently rendered nowhere: its only reader was the kub0 header
  // line the fact rows replaced. Kept because the count is cheap and correct, and
  // a session total is the one thing `endpointFacts()` cannot derive from a
  // snapshot. Wire it there rather than re-deriving it if it is wanted back.
  property int activitySinceStart: 0
  // Activity frames seen since the last hello; the first is the replay.
  property int activityFramesSinceHello: 0
  property var kub0Account: ({ connected: false, node_name: "", last_heartbeat_ok: null })
  property string policyDaemonMode: "unknown"
  property var kub0: Kub0.emptyKub0()
  property int kub0Revision: 0
  // sha256 -> ms of the last exec-gate notification; Activity.execGateNotifyAllowed
  // keeps it to one per digest per ten minutes.
  property var execGateNotified: ({})
  property string connectState: "idle"
  property string connectCode: ""
  property string connectUrl: ""
  property var connectExpiresAt: 0
  property string connectError: ""

  Kub0Adapter { id: adapter }

  // Retire only evidence owned by the current daemon source.
  function retirePolicyEvidence() {
    // The system daemon's stream ended or began again: a read made before
    // that is not evidence of what it holds now.
    if (eventSource === "system")
      systemView = null
    policyDaemonMode = "unknown"
    // Nor is its version: the next greeting may be another build's.
    daemonVersion = ""
    userKub0 = Kub0.clearPolicyEvidence(Kub0.copyKub0(userKub0))
    publishKub0()
  }

  // What the panel shows: the user daemon's account and policies, with the
  // system daemon's laid over them when it is reachable, since that is the
  // account that heartbeats and the daemon that enforces.
  //
  // Reading the system daemon's own stream there is nothing to lay over: its
  // frames are live and the read is older. Only who the account is comes from
  // the read (no frame carries it).
  function publishKub0() {
    if (!systemView)
      kub0 = userKub0
    else if (eventSource === "system")
      kub0 = Kub0.applySystemIdentity(userKub0, systemView)
    else
      kub0 = Kub0.applySystemView(userKub0, systemView)
    kub0Account = {
      connected: kub0.connected === true,
      node_name: kub0.nodeName ? String(kub0.nodeName) : "",
      last_heartbeat_ok: kub0.lastHeartbeatOk
    }
    kub0Revision += 1
  }

  // Read the system daemon's account card and policy list over the request
  // connection (#61 step 2): `status` (the account and fleet facts, a
  // superset of `whoami`), `policies` (the list, with its snoozes) and `rules`
  // (its deny list). Without a reachable system daemon, the user daemon's own.
  function refreshSystemView() {
    if (shuttingDown || systemViewPending)
      return
    systemViewPending = true
    withSystem(function(reachable) { root.loadSystemView(reachable) })
  }

  function loadSystemView(reachable) {
    // The system daemon answers and the panel is still on its own daemon
    // (installed since, or it was down when the source was chosen).
    if (reachable && eventSource === "user")
      useSystemSource()
    if (!reachable) {
      systemViewPending = false
      if (systemView !== null) {
        systemView = null
        publishKub0()
      }
      return
    }
    var view = { status: null, policies: null, rules: null }
    var left = 3
    var failed = false
    function done(key, reply) {
      if (reply && reply.ok === true)
        view[key] = reply.result
      else
        failed = true
      if (key === "status" && reply && reply.ok === true && reply.result && reply.result.peer && typeof reply.result.peer.uid === "number")
        root.sessionUid = reply.result.peer.uid
      left -= 1
      if (left > 0)
        return
      root.systemViewPending = false
      root.systemView = failed && !view.status && !view.policies ? null : view
      root.publishKub0()
    }
    for (var verb of ["status", "policies", "rules"]) {
      var key = verb
      if (!sendSystemRead(key, done))
        done(key, null)
    }
  }

  // One read on the request connection, for loadSystemView.
  function sendSystemRead(verb, done) {
    if (verb === "status")
      return controlRequest("status", {}, function(r) { done("status", r) })
    if (verb === "policies")
      return controlRequest("policies", {}, function(r) { done("policies", r) })
    return controlRequest("rules", {}, function(r) { done("rules", r) })
  }

  function ingest(line) {
    var ev = null
    try { ev = JSON.parse(String(line)) } catch (e) { ev = null }
    if (ev && ev.type === "hello") {
      retirePolicyEvidence()
      policyDaemonMode = ev.mode === "user" || ev.mode === "system" ? ev.mode : "unknown"
      // The demo's recorded greeting is not a daemon's: its version says
      // nothing about what is installed here.
      daemonVersion = (!root.usingFallback && typeof ev.version === "string") ? ev.version : ""
      captureStatus = { state: "off", detail: "Optional capture is off", kernelDropped: 0, userspaceDropped: 0, invalid: 0 }
      historyEntries = []
      historyBusy = false
      activityEntries = []
      activitySinceStart = 0
      activityFramesSinceHello = 0
      listeners = []
      listenersRevision += 1
      timelineResult = null
      watchRules = []
      watchError = ""
      watchRevision += 1
      if (ev.account && typeof ev.account === "object") {
        userKub0 = Kub0.applyHelloAccount(userKub0, ev.account)
        publishKub0()
      }
    }
    if (ev && ev.type === "capture-status") {
      captureStatus = ev
      // Capture attempts and counters cannot make sampled sockets current.
      return
    }
    if (ev && ev.type === "history" && ev.request === historyRequest) {
      historyBusy = false
      historyTimeout.stop()
      historyError = typeof ev.error === "string" ? ev.error : "Invalid history response"
      historyEntries = ev.entries && Object.prototype.toString.call(ev.entries) === "[object Array]" ? ev.entries : []
      historyMore = ev.more === true
    }
    if (ev && ev.type === "listeners") {
      listeners = ev.listeners && Object.prototype.toString.call(ev.listeners) === "[object Array]" ? ev.listeners : []
      listenersRevision += 1
    }
    if (ev && ev.type === "watchlist") {
      watchRules = ev.rules && Object.prototype.toString.call(ev.rules) === "[object Array]" ? ev.rules : []
      watchError = typeof ev.error === "string" ? ev.error : ""
      watchRevision += 1
    }
    if (ev && ev.type === "timeline" && ev.request === timelineRequest) {
      timelineBusy = false
      timelineTimeout.stop()
      timelineError = typeof ev.error === "string" ? ev.error : ""
      timelineResult = ev.timeline && typeof ev.timeline === "object" ? ev.timeline : null
    }
    if (ev && ev.type === "investigate" && ev.request === investigateRequest) {
      investigateBusy = false
      investigateTimeout.stop()
      investigateError = typeof ev.error === "string" ? ev.error : ""
      investigateResult = ev.pivot && typeof ev.pivot === "object" ? ev.pivot : null
    }
    if (ev && ev.type === "fleet") {
      userKub0 = Kub0.applyFleet(userKub0, ev)
      publishKub0()
    }
    if (ev && ev.type === "activity" && ev.entries && Object.prototype.toString.call(ev.entries) === "[object Array]") {
      activityEntries = Activity.ingest(activityEntries, ev.entries, 1000)
      activitySinceStart += ev.entries.length
      activityRevision += 1
      // The hello replay is history; only entries that arrive one at a time
      // afterwards are news worth a notification.
      if (activityFramesSinceHello > 0 && ev.entries.length === 1) {
        if (!notifyExecGate(ev.entries[0]))
          notifyIntel(ev.entries[0])
      }
      activityFramesSinceHello += 1
    }
    var now = Date.now()
    var out = Health.applyIngest(health, model, line, now, applyDeferred)
    health = out.health
    if (out.model)
      model = out.model
    syncFromModel()
    // SplitParser delivers every line of one socket read in the same turn of
    // the event loop, and Qt.callLater runs a given function once per turn,
    // so a sample's burst of connects/disconnects regroups the apps once.
    if (model.needsRebuild)
      Qt.callLater(root.settleModel)
  }

  function requestHistory(query, hours) {
    historyQuery = String(query || "").substring(0, 128)
    historyHours = [1, 24, 168].indexOf(hours) >= 0 ? hours : 24
    historyRequest = "history-" + Date.now() + "-" + (++historySerial)
    historyMore = false
    if (!eventSock || !eventSock.connected || usingFallback) {
      historyBusy = false
      historyEntries = []
      historyError = "Connect to the live daemon to read local history."
      return
    }
    historyError = ""
    historyBusy = true
    writeSock(JSON.stringify({ cmd: "history", request: historyRequest, query: historyQuery, since: Math.max(0, Date.now() - historyHours * 3600000) }))
    historyTimeout.restart()
  }

  Timer {
    id: historyTimeout
    interval: 5000
    onTriggered: {
      root.historyBusy = false
      root.historyError = "History request timed out. Refresh after the daemon reconnects."
    }
  }

  // Pivot on one subject ("ip:1.2.3.4", "asn:13335", "app:curl", ...) over
  // retained history plus live rows. One request in flight at a time; a
  // newer request retires the older reply by its id.
  function requestInvestigate(subject, hours) {
    investigateSubject = String(subject || "").substring(0, 256)
    var h = [1, 24, 168].indexOf(hours) >= 0 ? hours : 168
    investigateRequest = "investigate-" + Date.now() + "-" + (++investigateSerial)
    investigateResult = null
    if (!eventSock || !eventSock.connected || usingFallback) {
      investigateBusy = false
      investigateError = "Connect to the live daemon to investigate."
      return
    }
    investigateError = ""
    investigateBusy = true
    writeSock(JSON.stringify({ cmd: "investigate", request: investigateRequest, subject: investigateSubject, since: Math.max(0, Date.now() - h * 3600000) }))
    investigateTimeout.restart()
  }

  // When this machine talked, by app and by hour, from retained history.
  function requestTimeline(hours) {
    timelineHours = [1, 24, 168].indexOf(hours) >= 0 ? hours : 24
    timelineRequest = "timeline-" + Date.now() + "-" + (++timelineSerial)
    if (!eventSock || !eventSock.connected || usingFallback) {
      timelineBusy = false
      timelineResult = null
      timelineError = "Connect to the live daemon to read the timeline."
      return
    }
    timelineError = ""
    timelineBusy = true
    writeSock(JSON.stringify({ cmd: "timeline", request: timelineRequest, hours: timelineHours }))
    timelineTimeout.restart()
  }

  Timer {
    id: timelineTimeout
    interval: 5000
    onTriggered: {
      root.timelineBusy = false
      root.timelineError = "Timeline request timed out. Try again after the daemon reconnects."
    }
  }

  function clearInvestigate() {
    investigateTimeout.stop()
    investigateBusy = false
    investigateRequest = ""
    investigateSubject = ""
    investigateResult = null
    investigateError = ""
  }

  Timer {
    id: investigateTimeout
    interval: 5000
    onTriggered: {
      root.investigateBusy = false
      root.investigateError = "Investigate request timed out. Try again after the daemon reconnects."
    }
  }

  // A desktop notification for one live activity entry, when it is a watch
  // hit or a warning-level indicator and the preference allows. Pure decision
  // in Activity.notification so it is tested under Node; only the exec is here.
  function notifyIntel(entry) {
    if (!prefs || prefs.notifyIntel !== true)
      return false
    if (entry && entry.kind === "exec_gate_deny")
      return false
    var n = Activity.notification(entry)
    if (!n)
      return false
    Quickshell.execDetached(Binds.notifyArgvWithIcon("kub0", "󰒃", n.headline, n.body))
    return true
  }

  // The exec gate refused a file (or wanted to and could not). Not behind the
  // Intel preference: a program the owner just ran did not start, and the
  // notification is the only thing that says why. Two buttons run the
  // privileged helper through polkit; the digest travels after `--with` so it
  // is appended to each action's argv and never read as an option. One
  // notification per sha256 per ten minutes (pure decision in Activity.js).
  function notifyExecGate(entry) {
    if (!entry || entry.kind !== "exec_gate_deny")
      return false
    var n = Activity.notification(entry)
    if (!n || !n.sha256)
      return true
    var gate = Activity.execGateNotifyAllowed(execGateNotified, n.sha256, Date.now())
    execGateNotified = gate.seen
    if (!gate.allowed)
      return true
    Quickshell.execDetached(Binds.notifyArgvWithActions("kub0", "󰒃", n.headline, n.body, n.urgency, n.actions, n.withArgs))
    return true
  }

  // Local trust for the exec gate is the system daemon's store; the helper
  // appends a request behind its own polkit action and the daemon applies it.
  function execGateTrust(sha256) { return runExecGateVerb("execgate-trust", sha256) }
  function execGateUntrust(sha256) { return runExecGateVerb("execgate-untrust", sha256) }
  function execGateAllowOnce(sha256) { return runExecGateVerb("execgate-allow-once", sha256) }

  function runExecGateVerb(verb, sha256) {
    var sha = String(sha256 || "").toLowerCase()
    if (!/^[0-9a-f]{64}$/.test(sha))
      return false
    if (!helperInstalled) {
      lastBlockError = "canonical helper missing at " + canonicalHelper
      return false
    }
    lastBlockError = ""
    submitChange([verb, sha])
    return true
  }

  // Watch rules: the daemon validates, stores, and answers with the full list
  // (and an error string when the change was refused).
  //
  // To the daemon whose rows are shown. The panel's own daemon takes the
  // `watch` line. The system daemon takes it from root only, so there it is a
  // request (`watch-set`, `watch-delete`: a member changes the rules they set).
  function setWatch(kind, value, note) {
    if (!kind || !value)
      return false
    watchError = ""
    if (eventSource === "system")
      return watchOnSystem("watch-set", { kind: String(kind), value: String(value).substring(0, 256), note: String(note || "").substring(0, 120) })
    return writeSock(JSON.stringify({ cmd: "watch", action: "set", kind: String(kind), value: String(value).substring(0, 256), note: String(note || "").substring(0, 120) }))
  }

  function deleteWatch(id) {
    if (!id)
      return false
    watchError = ""
    if (eventSource === "system")
      return watchOnSystem("watch-delete", { id: String(id) })
    return writeSock(JSON.stringify({ cmd: "watch", action: "delete", id: String(id) }))
  }

  // A change that went through arrives as the `watchlist` frame every client
  // gets. Only a refusal is answered here, to this panel.
  function watchOnSystem(verb, fields) {
    withSystem(function(reachable) {
      var sent = reachable && root.controlRequest(verb, fields, function(r) {
        if (r && r.ok === true)
          return
        root.watchError = r && r.error ? String(r.error) : "The system daemon refused the watch rule."
        root.watchRevision += 1
      })
      if (!sent) {
        root.watchError = "The system daemon is not reachable; the watch rule was not changed."
        root.watchRevision += 1
      }
    })
    return true
  }

  function applyDeferred(m, line, now) {
    return ConnectionModel.applyLine(m, line, now, { deferRebuild: true })
  }

  function settleModel() {
    if (ConnectionModel.settle(model, Date.now()))
      syncFromModel()
  }

  function noteActivity(kind, app, detail) {
    // The system daemon records what it did itself, and takes this line from
    // root only.
    if (eventSource === "system")
      return
    var a = app && typeof app === "object"
      ? { id: String(app.id || ""), name: String(app.name || app.id || "") }
      : { id: "", name: "" }
    var d = detail && typeof detail === "object" ? detail : {}
    var payload = {}
    if (d.mechanism === "cgroup" || d.mechanism === "endpoints")
      payload.mechanism = d.mechanism
    if (d.error) {
      var err = String(d.error)
      if (err.length > 200)
        err = err.substring(0, 200)
      payload.error = err
    }
    writeSock(JSON.stringify({ cmd: "note", kind: kind, app: a, detail: payload }))
  }

  function syncHealthView() {
    var now = Date.now()
    healthTick = now
    var view = Health.derive(health, now, { count: model.count })
    monitoring = view.monitoring
    snapshotReady = view.snapshotReady === true
    dataCurrent = view.monitoring === "current"
    lastFreshAt = view.lastFreshAt
    lastSnapshotAt = view.lastSnapshotAt
    observationAgeMs = view.observationAgeMs || 0
    observationAgeText = view.lastSnapshotAt ? Health.formatAge(view.observationAgeMs) : ""
    barLabel = view.label
    barTooltip = Health.barTooltip(view, {
      coverage: coverage,
      count: model.count,
      appCount: model.ordered ? model.ordered.length : 0,
      blockingReady: blockingReady,
      blockHint: blockHint,
      anyBlocked: anyBlocked,
      needsHelperInstall: needsHelperInstall,
      daemonStatus: daemonStatus
    })
  }

  function syncFromModel() {
    modelRevision = model.revision
    activeCount = model.count
    digestText = model.digestText || ""
    anyBlocked = ConnectionModel.anyBlocked(model)
    syncHealthView()
    pulse = model.pulse === true && dataCurrent
  }

  function rerun(proc) {
    if (!proc)
      return
    proc.running = false
    proc.running = true
  }

  function refreshInstallState() {
    rerun(installCheck)
    rerun(kub0Check)
    // Only an installed kub0 has a group to be in. This runs every few
    // seconds on a machine with nothing installed; it should not cost more.
    if (kub0Installed)
      rerun(groupCheck)
    if (!helperInstalled && !daemonAvailable)
      probeBinaries()
    else if (helperInstalled)
      probeHelperStatus()
  }

  function markLooked() {
    ConnectionModel.markLooked(model)
    panelVisible = true
    replayPanelState()
    refreshInstallState()
    refreshSystemView()
    syncFromModel()
  }

  function markClosed() {
    panelVisible = false
    if (eventSock && eventSock.connected)
      writeSock(JSON.stringify({ type: "panel-close" }))
  }

  function replayPanelState() {
    if (panelVisible && eventSock && eventSock.connected)
      writeSock(JSON.stringify({ type: "panel-open" }))
  }

  function clearPulse() {
    ConnectionModel.clearPulse(model)
    syncFromModel()
  }

  // Live rows plus last-known rows, and session-known blocks even after the
  // app dropped out of the observation set.
  function appById(id) {
    function own(map, key) {
      if (!map || key === undefined || key === null)
        return undefined
      if (!Object.prototype.hasOwnProperty.call(map, String(key)))
        return undefined
      return map[String(key)]
    }
    var live = own(model.apps, id)
    if (live)
      return live
    var past = own(model.historyApps, id)
    if (past)
      return past
    var known = own(model.blocked, id)
    if (known)
      return {
        id: id,
        name: id,
        blocked: true,
        mechanism: known.mechanism || "",
        pids: [],
        connections: [],
        system: false
      }
    return null
  }

  function appIcon(app) {
    if (!app)
      return ""
    return adapter.iconSource(app.desktop || app.id, app.icon)
  }

  function filteredApps(query) {
    return ConnectionModel.filterApps(model.ordered, query)
  }

  function drawableArcs() {
    if (!dataCurrent)
      return []
    return ConnectionModel.drawableArcs(model.connections, origin, 40)
  }

  /// Name a network key, or clear its name when `label` is empty. The name
  /// goes to both daemons (#61 step 2): the user daemon, whose rows the panel
  /// shows, and the system daemon, whose heartbeat carries it to the org.
  ///
  /// To the user daemon it is fire-and-forget by design: that daemon answers a
  /// tag by rebroadcasting the whole snapshot, so the tag appearing on the rows
  /// IS the acknowledgement. The system daemon answers a `tag` request; when it
  /// refuses or cannot be reached, `tagNotice` says the name stayed here.
  function tagNetwork(key, label, kind) {
    if (!key)
      return
    var fields = { networkKey: String(key), label: label ? String(label) : "", kind: kind ? String(kind) : "service" }
    // Reading the system daemon there is one store, and its `tag` request is
    // the whole change: the rows are renamed by the snapshot it sends back.
    if (eventSource !== "system")
      writeSock(JSON.stringify({
        type: "tag",
        networkKey: fields.networkKey,
        label: fields.label,
        kind: fields.kind
      }))
    tagNotice = ""
    withSystem(function(reachable) { root.tagOnSystem(reachable, fields) })
  }

  function tagOnSystem(reachable, fields) {
    // What happened to the name when the system daemon did not take it: on its
    // own daemon the panel has it and the org does not; reading the system
    // daemon nothing was named at all.
    var kept = eventSource === "system" ? "Not named: " : "Named on this panel only: "
    if (!reachable) {
      tagNotice = kept + (eventSource === "system" ? "the system daemon is not reachable." : "the system daemon is not reachable, so the org does not get this name.")
      return
    }
    var sent = controlRequest("tag", fields, function(r) {
      root.tagNotice = r && r.ok === true ? ""
        : kept + "the system daemon refused it (" + (r && r.error ? String(r.error) : "no reason") + ")."
    })
    if (!sent)
      tagNotice = kept + "the system daemon connection closed."
  }

  function writeSock(s) {
    if (!eventSock || !eventSock.connected || usingFallback || shuttingDown)
      return false
    try {
      eventSock.write(s + "\n")
      eventSock.flush()
      return true
    } catch (e) { return false }
  }

  function eventSocketPath() {
    return eventSource === "system" ? systemSocketPath : adapter.socketPath()
  }

  // Capture runs only in a kub0d the panel starts, so it decides the source
  // only where there is one to start.
  function captureNeedsOwnDaemon() {
    return root.prefs.captureEnabled === true && vallumdPath !== ""
  }

  // Pick the event source: the system daemon when this session can use it and
  // capture is off, else the panel's own daemon. Called once the binaries are
  // known, when the capture switch changes, when the system daemon's stream
  // has stayed down, and every few seconds while the panel is on its own
  // daemon (or on none) with kub0 installed.
  function chooseSource() {
    if (shuttingDown || usingFallback)
      return
    if (captureNeedsOwnDaemon()) {
      useUserSource()
      return
    }
    withSystem(function(reachable) {
      // The preferences may have loaded while this was pending.
      if (root.captureNeedsOwnDaemon())
        root.useUserSource()
      else if (reachable)
        root.useSystemSource()
      // A request connection that failed while the stream itself is up says
      // nothing against the daemon the panel is reading right now.
      else if (!(root.eventSource === "system" && root.daemonStatus === "connected"))
        root.useUserSource()
    })
  }

  function useSystemSource() {
    if (shuttingDown || usingFallback || captureNeedsOwnDaemon())
      return
    if (eventSource === "system" && eventSock && eventSock.connected)
      return
    eventSource = "system"
    systemStreamFailures = 0
    restartTimer.stop()
    sockConnectDelay.stop()
    // Its onExited sees the new source and leaves the socket alone.
    if (daemonProc.running)
      daemonProc.running = false
    daemonAvailable = true
    daemonStatus = "starting"
    health = Health.markDaemonAvailable(health, true)
    health = Health.markSocketDown(health, "connecting to kub0d")
    syncHealthView()
    replaceEventSocket()
  }

  function useUserSource() {
    if (shuttingDown || usingFallback)
      return
    var wasSystem = eventSource === "system"
    eventSource = "user"
    systemStreamFailures = 0
    daemonAvailable = vallumdPath !== ""
    // The system daemon's socket is not this source's: a line written for the
    // panel's own daemon must not reach it.
    if (wasSystem)
      retireEventSocket()
    if (!daemonAvailable) {
      // Nothing to start. With kub0 installed the system daemon is what is
      // missing, and it is asked again (sourceRecheck); "not built" is for a
      // panel that has neither.
      daemonStatus = kub0Installed ? "reconnecting" : "missing"
      health = Health.markDaemonAvailable(health, false, kub0Installed ? "the system daemon is not answering" : "kub0d is not built")
      syncHealthView()
      return
    }
    if (!daemonProc.running)
      startDaemon()
    else if (!(eventSock && eventSock.connected))
      replaceEventSocket()
  }

  function retireEventSocket() {
    sockRetry.stop()
    retirePolicyEvidence()
    socketGeneration += 1
    var old = eventSock
    eventSock = null
    if (old) {
      try { old.connected = false } catch (e) { }
      old.destroy()
    }
  }

  // On its own daemon, or on none, with kub0 installed: the system daemon may
  // have started, or this session may have joined the group, since the source
  // was chosen. Nothing else asks while the panel stays closed.
  function recheckSource() {
    if (shuttingDown || usingFallback || eventSource === "system" || !kub0Installed || captureNeedsOwnDaemon())
      return
    withSystem(function(reachable) {
      if (reachable)
        root.useSystemSource()
    })
  }

  function replaceEventSocket() {
    if (shuttingDown || !daemonAvailable || usingFallback)
      return
    sockRetry.stop()
    retirePolicyEvidence()
    socketGeneration += 1
    var old = eventSock
    eventSock = null
    if (old) {
      try { old.connected = false } catch (e) { }
      old.destroy()
    }
    eventSock = eventSocketComponent.createObject(root, {
      path: eventSocketPath(), connected: false, socketGeneration: socketGeneration
    })
    if (!eventSock) {
      scheduleSocketRetry()
      return
    }
    eventSock.connected = true
  }

  function currentSocket(sock, generation) {
    return !shuttingDown && sock && sock === eventSock && generation === socketGeneration
  }

  function onEventSocketRead(sock, generation, line) {
    if (!currentSocket(sock, generation) || usingFallback)
      return
    ingest(line)
  }

  function onEventSocketConnected(sock, generation, connected) {
    if (!currentSocket(sock, generation) || (health && health.demo))
      return
    if (connected) {
      replayPanelState()
      daemonStatus = "connected"
      usingFallback = false
      restarts = 0
      systemStreamFailures = 0
      socketRetryAttempts = 0
      sockRetry.stop()
      health = Health.markSocketUp(health, Date.now())
      syncHealthView()
    } else {
      retirePolicyEvidence()
      failPendingSocketRequests("daemon connection lost; retry after reconnecting")
      health = Health.markSocketDown(health, "not connected to kub0d")
      daemonStatus = daemonAvailable ? "reconnecting" : "missing"
      syncHealthView()
      if (daemonAvailable && (daemonProc.running || eventSource === "system"))
        scheduleSocketRetry()
    }
  }

  function failPendingSocketRequests(message) {
    if (historyBusy) {
      historyBusy = false
      historyTimeout.stop()
      historyError = message
    }
    historyRequest = ""
    if (investigateBusy) {
      investigateBusy = false
      investigateTimeout.stop()
      investigateError = message
    }
    investigateRequest = ""
    if (timelineBusy) {
      timelineBusy = false
      timelineTimeout.stop()
      timelineError = message
    }
    timelineRequest = ""
  }

  function applyConnectFields(c) {
    connectState = c.connectState
    connectCode = c.connectCode
    connectUrl = c.connectUrl
    connectExpiresAt = c.connectExpiresAt
    connectError = c.connectError
  }

  // The account that heartbeats is the system daemon's when there is one this
  // user can reach: Connect then logs it in through `pkexec kub0 --json login`
  // (root-only on the system daemon). Otherwise the user daemon's own account,
  // through the local kub0 on the user daemon's socket.
  function requestConnect() {
    if (connectState === "waiting" || connectProc.running || connectPending)
      return
    connectPending = true
    withSystem(function(reachable) { root.startConnect(reachable) })
  }

  function startConnect(reachable) {
    connectPending = false
    if (connectState === "waiting" || connectProc.running)
      return
    // Reading the system daemon, the account is that daemon's whether or not
    // this one request connection came up: no daemon of the panel's own is
    // there to log in instead.
    if ((reachable || eventSource === "system") && kub0Installed) {
      applyConnectFields(Kub0.beginConnect({
        connectState: connectState,
        connectCode: connectCode,
        connectUrl: connectUrl,
        connectExpiresAt: connectExpiresAt,
        connectError: connectError
      }))
      connectVia = "kub0"
      connectBuffer = []
      connectProc.command = Control.kub0Command(pkexecPath, kub0Path, ["login"])
      connectProc.running = true
      return
    }
    connectVia = ""
    if (localKub0Path) {
      // The user daemon's own account, through kub0 on its socket: the daemon
      // runs the device login and writes the account (the daemon's `connect` is
      // retired). Same output, same parser as the system path.
      applyConnectFields(Kub0.beginConnect({
        connectState: connectState,
        connectCode: connectCode,
        connectUrl: connectUrl,
        connectExpiresAt: connectExpiresAt,
        connectError: connectError
      }))
      connectVia = "kub0"
      connectBuffer = []
      connectProc.command = [localKub0Path, "--socket", adapter.socketPath(), "--json", "login"]
      connectProc.running = true
      return
    }
    applyConnectFields({
      connectState: "error",
      connectCode: "",
      connectUrl: "",
      connectExpiresAt: 0,
      connectError: "kub0 is not built (./build.sh puts it in the plugin's bin/)"
    })
  }

  function openConnectUrl() {
    if (!connectUrl)
      return
    Quickshell.execDetached(["xdg-open", connectUrl])
  }

  // Where this endpoint's fleet inventory lives in the console.
  //
  // Deliberately NOT a hardcoded kub0.ai: the daemon hands us a connect_url during
  // pairing (e.g. https://kub0.ai/connect), so we reuse ITS origin. A self-hosted or
  // staging control plane must not deep-link its users back out to kub0.ai. The
  // literal below is only the fallback for a host that has never seen a connect_url.
  //
  // The path is /dashboard/posture because that is the page live today that lists
  // cluster nodes and kub0 endpoints. When the richer hosts page ships, this is
  // the one line that changes.
  readonly property string inventoryUrl: {
    var base = "https://kub0.ai"
    if (connectUrl) {
      var m = String(connectUrl).match(/^(https?:\/\/[^\/]+)/)
      if (m)
        base = m[1]
    }
    return base + "/dashboard/posture"
  }

  function openInventoryUrl() {
    Quickshell.execDetached(["xdg-open", inventoryUrl])
  }

  function cancelConnect() {
    // A cancelled kub0 login is not a failed one. (pkexec's child runs as
    // root, so stopping it may not reach it; the daemon then finishes the
    // login on its own, as a cancelled browser round-trip would.)
    connectVia = ""
    connectBuffer = []
    if (connectProc.running)
      connectProc.running = false
    applyConnectFields(Kub0.cancelConnect({}))
  }

  // Disconnect undoes Connect on the same daemon: the system daemon's account
  // through `pkexec kub0 --json logout` when it is reachable, else the user
  // daemon's.
  function requestDisconnect() {
    connectVia = ""
    connectBuffer = []
    if (connectProc.running)
      connectProc.running = false
    if (disconnectProc.running)
      return
    withSystem(function(reachable) { root.startDisconnect(reachable) })
  }

  function startDisconnect(reachable) {
    if (disconnectProc.running)
      return
    if ((reachable || eventSource === "system") && kub0Installed)
      disconnectProc.command = Control.kub0Command(pkexecPath, kub0Path, ["logout"])
    else if (localKub0Path)
      disconnectProc.command = [localKub0Path, "--socket", adapter.socketPath(), "logout"]
    else
      return
    disconnectProc.running = true
    applyConnectFields(Kub0.emptyConnect())
    userKub0 = Kub0.emptyKub0()
    systemView = null
    publishKub0()
  }

  function onConnectStdout(line) {
    if (connectVia === "kub0") {
      connectBuffer.push(String(line))
      line = Kub0.kub0LoginPartial(line)
      if (!line)
        return
    }
    applyConnectEvent(line)
  }

  // kub0's final reply is pretty-printed over several lines, so it is read
  // once the process has ended.
  function onKub0LoginExit(stderr, code) {
    connectVia = ""
    var lines = connectBuffer
    connectBuffer = []
    applyConnectEvent(Kub0.kub0LoginFinish(lines.join("\n"), stderr, code))
    refreshSystemView()
  }

  function applyConnectEvent(line) {
    var cur = {
      connectState: connectState,
      connectCode: connectCode,
      connectUrl: connectUrl,
      connectExpiresAt: connectExpiresAt,
      connectError: connectError
    }
    applyConnectFields(Kub0.applyConnectLine(cur, line, Date.now()))
    userKub0 = Kub0.applyConnectToKub0(userKub0, line)
    publishKub0()
  }

  function startDaemon() {
    if (daemonProc.running || shuttingDown || usingFallback)
      return
    if (!vallumdPath) {
      daemonStatus = "missing"
      health = Health.markDaemonAvailable(health, false, "kub0d is not built")
      syncHealthView()
      return
    }
    usingFallback = false
    if (health.demo)
      health = Health.exitDemo(health)
    health = Health.markDaemonAvailable(health, true)
    daemonProc.command = [
      vallumdPath,
      "--socket", adapter.socketPath(),
      "--data-dir", pluginDir + "/data",
      "--state-dir", adapter.stateDir(),
      "--interval-ms", "500",
      // One release: the panel's own daemon is the one that moves a 0.4.x
      // ~/.local/state/vallum to its state directory (never while a 0.4.x
      // daemon still runs); a bare kub0d start never moves anything.
      "--migrate-state"
    ]
    if (root.prefs.captureEnabled === true)
      daemonProc.command = daemonProc.command.concat(["--capture"])
    if (root.prefs.shareDestinations === true)
      daemonProc.command = daemonProc.command.concat(["--share-destinations"])
    daemonStatus = "starting"
    health = Health.markSocketDown(health, "connecting to kub0d")
    syncHealthView()
    daemonProc.running = true
  }

  function resetDemoObservations() {
    model = ConnectionModel.resetNetworkObservations(model, Date.now())
    syncFromModel()
  }

  function resumeLiveSource() {
    if (shuttingDown || usingFallback)
      return
    health = Health.markDaemonAvailable(health, true)
    health = Health.markSocketDown(health, "connecting to kub0d")
    syncHealthView()
    socketRetryAttempts = 0
    if (eventSource !== "system" && !daemonProc.running) {
      startDaemon()
      return
    }
    replaceEventSocket()
  }

  // The system daemon's stream is down. It restarts within a second (an
  // upgrade, a `systemctl restart`), so try its socket again a few times
  // before asking whether it can be used at all: that question starts the
  // panel's own daemon when the answer is no.
  function retrySystemStream() {
    systemStreamFailures += 1
    if (systemStreamFailures > 5) {
      systemStreamFailures = 0
      chooseSource()
      return
    }
    replaceEventSocket()
  }

  function scheduleSocketRetry() {
    if (shuttingDown || usingFallback)
      return
    if (eventSock && eventSock.connected)
      return
    if (!root.daemonAvailable)
      return
    if (root.health && root.health.demo)
      return
    if (sockRetry.running)
      return
    socketRetryAttempts += 1
    sockRetry.interval = Math.min(4000, 250 * Math.pow(2, Math.min(socketRetryAttempts - 1, 4)))
    sockRetry.restart()
  }

  // Explicit development/test entry only. Never selected because the daemon
  // is missing. Labeled Demo in the bar and panel.
  function enterDemo(arg) {
    var a = String(arg || "").replace(/^\s+|\s+$/g, "")
    if (a === "off" || a === "stop") {
      usingFallback = false
      fallbackTimer.stop()
      fallbackIndex = 0
      retirePolicyEvidence()
      health = Health.exitDemo(health)
      resetDemoObservations()
      if (vallumdPath || eventSource === "system") {
        daemonStatus = "reconnecting"
        resumeLiveSource()
        // A capture switch flipped during the replay was not acted on.
        if (captureNeedsOwnDaemon() === (eventSource === "system"))
          chooseSource()
      } else {
        daemonStatus = "missing"
        health = Health.markDaemonAvailable(health, false, "kub0d is not built")
        syncHealthView()
      }
      return "off"
    }
    fallbackTimer.stop()
    fallbackIndex = 0
    usingFallback = true
    sockRetry.stop()
    sockConnectDelay.stop()
    restartTimer.stop()
    failPendingSocketRequests("demo replay started; pending request cancelled")
    // Retire the live receiver before replay begins. Its queued callbacks
    // cannot publish into demo state, and the existing Process stays the sole
    // daemon owner until live monitoring resumes or this Service is destroyed.
    retirePolicyEvidence()
    socketGeneration += 1
    var old = eventSock
    eventSock = null
    if (old) {
      try { old.connected = false } catch (e) { }
      old.destroy()
    }
    daemonStatus = "fallback"
    health = Health.enterDemo(health, Date.now())
    resetDemoObservations()
    if (replayView.text && replayView.text().trim())
      fallbackTimer.restart()
    else
      replayView.reload()
    return "demo"
  }

  function requestBlock(appId) {
    if (!appId)
      return
    var now = Date.now()
    var known = (model.blocked && Object.prototype.hasOwnProperty.call(model.blocked, String(appId)))
      ? model.blocked[String(appId)]
      : undefined
    if (known) {
      if (!Health.canDispatchUnblock(model.blocked, appId, blockingReady))
        return
      lastBlockError = ""
      if (known.mechanism === "endpoints")
        submitChange(["unblock-ips", appId])
      else
        submitChange(["unblock-app", appId])
      return
    }
    if (!Health.canDispatchNewBlock(health, now)) {
      lastBlockError = "monitoring is not current — refusing to block from stale or incomplete data"
      return
    }
    var app = appById(appId)
    if (!app || !blockingReady)
      return
    if (!ConnectionModel.isBlockable(app)) {
      lastBlockError = "refusing to block system/unknown identity"
      return
    }
    var args = ["block-app", appId]
    var pids = ownPids(app)
    if (!pids.length && ConnectionModel.pidsOf(app).length) {
      lastBlockError = otherAccountsApp
      return
    }
    for (var i = 0; i < pids.length; i++)
      args.push(String(pids[i]))
    lastBlockError = ""
    submitChange(args)
  }

  readonly property string otherAccountsApp: "This app is running under another account. Its owner can block it, or root: sudo kub0 block."

  // The processes of an app this session may act on. Reading the system
  // daemon, one row can hold another account's processes under the same app
  // id, and the helper refuses a block that names one of them.
  function ownPids(app) {
    if (eventSource !== "system" || sessionUid < 0)
      return ConnectionModel.pidsOf(app)
    return ConnectionModel.pidsOwnedBy(model, app.id, sessionUid)
  }

  function requestDestinationBlock(appId, ip, seconds) {
    var app = appById(appId)
    if (!app || !blockingReady || helperBusy || !Health.canDispatchNewBlock(health, Date.now()) || !ConnectionModel.isBlockable(app)) return
    if (model.blocked && model.blocked[appId]) { lastBlockError = "Unblock the whole app before adding a destination rule."; return }
    var pids = ownPids(app)
    if (!pids.length && ConnectionModel.pidsOf(app).length) { lastBlockError = otherAccountsApp; return }
    if (!pids.length || [300, 900, 3600].indexOf(seconds) < 0) return
    var args = ["block-scoped", appId, String(ip), String(seconds)]
    for (var i=0; i<pids.length; i++) args.push(String(pids[i]))
    lastBlockError = ""
    submitChange(args)
  }

  // Snooze or resume one org network-policy rule on this device. Only the system
  // daemon enforces, so that is where a snooze goes (#61 step 2): a snooze lowers
  // protection, so it runs `pkexec kub0 --json policy snooze` (one prompt each
  // time); a resume is a `policy-resume` request. The org's user_can_snooze
  // still decides; its refusal shows where change failures show. Without a
  // reachable system daemon, the user daemon's snooze (userDaemonPolicyChange).
  function snoozePolicyRule(ruleId, seconds) {
    if (!ruleId) return
    submitChange(["policy-snooze", String(ruleId), String(seconds || 3600)])
  }

  function resumePolicyRule(ruleId) {
    if (!ruleId) return
    submitChange(["policy-resume", String(ruleId)])
  }

  // A user-only install: no daemon enforces, so a snooze there only quiets the
  // user daemon's alerts. Its refusal comes back as a status line.
  function userDaemonPolicyChange(args) {
    if (args[0] === "policy-snooze")
      writeSock(JSON.stringify({ cmd: "netpolicy-snooze", ruleId: String(args[1]), seconds: Number(args[2]) || 3600 }))
    else
      writeSock(JSON.stringify({ cmd: "netpolicy-resume", ruleId: String(args[1]) }))
  }

  function cancelDestinationBlock(appId, ip) {
    if (!helperInstalled || helperBusy) return
    lastBlockError = ""
    submitChange(["unblock-scoped", String(appId), String(ip)])
  }

  function requestBlockIps(appId) {
    function reject(msg) {
      if (msg)
        lastBlockError = msg
      pendingIpsApp = ""
    }
    if (!appId) {
      reject("")
      return
    }
    var now = Date.now()
    if (!Health.canDispatchNewBlock(health, now)) {
      reject("monitoring is not current — refusing endpoint block from stale or incomplete data")
      return
    }
    var app = appById(appId)
    if (!app || !blockingReady) {
      reject(!blockingReady ? "blocking is not ready" : "app is not available")
      return
    }
    if (!ConnectionModel.isBlockable(app)) {
      reject("refusing to block system/unknown identity")
      return
    }
    var ips = ConnectionModel.remotesOf(app, hostCriticalIps)
    if (ips.length === 0) {
      reject("no endpoints to block")
      return
    }
    var args = ["block-ips", appId]
    for (var i = 0; i < ips.length; i++)
      args.push(ips[i])
    pendingIpsApp = ""
    submitChange(args)
  }

  function offerIpsFallback(appId, err) {
    lastBlockError = err || "blocking this app's running processes failed"
    if (!appId) {
      pendingIpsApp = ""
      return
    }
    // Every destination is this machine's own gateway or nameserver: the
    // helper would refuse them all, so a confirm could only end in an error.
    if (ConnectionModel.remotesOf(appById(appId), hostCriticalIps).length === 0) {
      pendingIpsApp = ""
      return
    }
    if (pendingIpsApp === appId)
      pendingIpsApp = ""
    pendingIpsApp = appId
  }

  function runHelper(args) {
    if (!helperInstalled) {
      lastBlockError = "canonical helper missing at " + canonicalHelper
      return
    }
    var cmd = [pkexecPath, canonicalHelper]
    for (var i = 0; i < args.length; i++)
      cmd.push(args[i])
    if (blockProc.running)
      return
    helperMutationGeneration += 1
    statusRefreshPending = true
    blockProc.command = cmd
    blockProc.running = true
  }

  function setEnforcementPaused(paused) {
    if (!helperInstalled || !blockingToolsReady)
      return
    lastBlockError = ""
    submitChange([paused ? "pause" : "resume"])
  }

  function onBlockOutput(text) {
    var raw = String(text || "").trim()
    var ev
    try { ev = JSON.parse(raw) } catch (e) {
      lastBlockError = raw || "helper produced no JSON"
      return
    }
    // pkexec argv: pkexec bin verb args...
    applyChangeOutcome(blockProc.command ? blockProc.command.slice(2) : [], ev)
  }

  // What a change's result does to the panel, whichever path ran it: `args`
  // is the helper argv the panel built, `ev` the helper's JSON (or the same
  // shape from the system daemon's reply or kub0's output).
  function applyChangeOutcome(args, ev) {
    if (!ev || typeof ev !== "object") {
      lastBlockError = "the change produced no result"
      return
    }
    var verb = args && args.length >= 1 ? String(args[0]) : ""
    var appArg = args && args.length >= 2 ? String(args[1]) : ""
    // A policy snooze or resume changes the system daemon's list: read it back.
    if (verb === "policy-snooze" || verb === "policy-resume") {
      var blind = policyViewBlind
      policyViewBlind = false
      if (!ev.ok)
        lastBlockError = ev.error ? String(ev.error) : "the policy change failed"
      else if (blind)
        lastBlockError = (verb === "policy-snooze" ? "Snoozed" : "Resumed")
          + " on the system daemon. This panel cannot read its policy list until you log in again (the kub0 group), so the rule may show unchanged here"
      else
        lastBlockError = ""
      refreshSystemView()
      return
    }
    // The sharing setting changes no model here either: the system daemon's
    // next fleet frame is what moves the switch.
    if (verb === "share-on" || verb === "share-off") {
      lastBlockError = ev.ok ? "" : (ev.error ? String(ev.error) : "the sharing setting did not change")
      if (ev.ok) {
        // The panel's own preference follows the owner's last choice, so a
        // daemon the panel has to start later (the system one gone) does not
        // share by a preference from before it.
        setPref("shareDestinations", verb === "share-on")
        // On its own daemon the switch shows the system daemon's `status`.
        refreshSystemView()
      }
      return
    }
    // An exec-gate request changes no model here: the system daemon applies
    // it and the next fleet frame shows the result.
    if (verb.indexOf("execgate-") === 0) {
      lastBlockError = ev.ok ? "" : (ev.error ? String(ev.error) : "exec gate request failed")
      return
    }
    // A verified nft rule can be active even when the helper reports that
    // preexisting sockets escaped complete enforcement. Keep its unblock path
    // visible and show the warning; only a rolled-back rule is a failed block.
    if (ev.ok && (ev.verified !== false || ev.ruleVerified === true)) {
      if (Object.prototype.toString.call(ev.temporaryRules) === "[object Array]") {
        temporaryRules = ev.temporaryRules
        ConnectionModel.setTemporaryRules(model, temporaryRules, Date.now())
      }
      lastBlockError = ev.warning ? String(ev.warning) : ""
      if (ev.teardown) {
        model.blocked = {}
        temporaryRules = []
        ConnectionModel.setTemporaryRules(model, [], Date.now())
        ConnectionModel.rebuild(model, Date.now())
        syncFromModel()
        return
      }
      if (verb === "pause" || verb === "resume") {
        enforcementPaused = ev.paused === true
        return
      }
      // The user daemon's activity view is the panel's: whichever path ran
      // the change, the panel notes it there, once. The system daemon keeps
      // its own record of the blocks it runs (#61 step 1b).
      if (verb === "unblock-app" || verb === "unblock-ips") {
        if (appArg)
          ConnectionModel.setBlocked(model, appArg, "")
        var unApp = appById(appArg) || { id: appArg, name: appArg }
        noteActivity("unblock", unApp, { mechanism: ev.mechanism || (verb === "unblock-ips" ? "endpoints" : "cgroup") })
      } else if (verb === "block-app" || verb === "block-ips") {
        ConnectionModel.setBlocked(model, appArg, ev.mechanism || (verb === "block-ips" ? "endpoints" : "cgroup"))
        var blApp = appById(appArg) || { id: appArg, name: appArg }
        noteActivity("block", blApp, { mechanism: ev.mechanism || (verb === "block-ips" ? "endpoints" : "cgroup") })
      }
      syncFromModel()
    } else {
      lastBlockError = ev.error || (ev.warning ? String(ev.warning) : "") || "block incomplete"
      if (verb === "pause" || verb === "resume") {
        // The helper backs out a half-done pause, but read the marker back
        // rather than assume which way it landed.
        probeHelperStatus()
        return
      }
      // Only offer host-wide IP fallback when cgroup work was fully rolled back
      // (or never started, e.g. root-cgroup). If restore failed, processes may
      // still sit in vallum.slice — stacking an IP-set on that is unsafe.
      var rolled = ev.rollback === true || ev.code === "root-cgroup" || ev.code === "empty-forest"
      if (verb === "block-app" && appArg && rolled)
        offerIpsFallback(appArg, ev.error)
      if (appArg && (verb === "block-app" || verb === "block-ips")) {
        var failApp = appById(appArg) || { id: appArg, name: appArg }
        noteActivity("block_failed", failApp, {
          mechanism: verb === "block-ips" ? "endpoints" : "cgroup",
          error: ev.error || lastBlockError
        })
      }
    }
  }

  // ------------------------------------------------ changes (#61 step 1b)

  // A change in flight on any path.
  function changeRunning() {
    return blockProc.running || kub0Proc.running || changeInFlight !== null
  }

  // One change at a time, as with the helper: find out whether the system
  // daemon is reachable, then route it (dispatchChange).
  function submitChange(args) {
    if (changeRunning() || shuttingDown)
      return false
    changeInFlight = { args: args.slice(), via: "probe" }
    helperMutationGeneration += 1
    statusRefreshPending = true
    withSystem(function(reachable) { root.dispatchChange(reachable) })
    return true
  }

  // Destination sharing. Reading the system daemon it is that daemon's
  // setting, the one that reports this host: the switch shows what the daemon
  // says and changes it there (`share-on` needs root, so it asks once;
  // `share-off` is a request any member may make). On its own daemon it is
  // the panel's preference, passed to that daemon when it starts; next to a
  // logged-in system daemon that never had any effect.
  //
  // The system daemon owns the setting whenever it has said what it is: also
  // while the panel reads its own daemon (capture on), where that daemon
  // defers to the system one and the preference decides nothing. Only with
  // no system daemon to ask is the preference the setting.
  readonly property var systemSharing: systemSharingOf(systemView)
  readonly property bool sharingIsSystems: eventSource === "system" || systemSharing !== null
  readonly property bool sharingDestinations: eventSource === "system"
    ? (kub0 && kub0.sharingDestinations === true)
    : (systemSharing !== null ? systemSharing === true : root.prefs.shareDestinations === true)

  // What the system daemon's `status` says about sharing: true, false, or
  // null when it has not said (not read, not reachable, older than 0.5).
  function systemSharingOf(view) {
    var f = view && view.status && typeof view.status === "object" ? view.status.fleet : null
    return f && typeof f.sharingDestinations === "boolean" ? f.sharingDestinations : null
  }

  function setSharing(on) {
    if (sharingIsSystems) {
      if (on === true)
        submitChange(["share-on"])
      else
        submitChange(["share-off"])
      return
    }
    setPref("shareDestinations", on === true)
  }

  function dispatchChange(reachable) {
    var change = changeInFlight
    if (!change || change.via !== "probe")
      return
    var r = Control.route(change.args)
    if (Control.isSharingChange(change.args)) {
      // Through root when the verb needs it (share-on), or when this session's
      // request connection did not come up: root reaches the system daemon
      // either way. Never the helper, which has no such verb.
      var viaRoot = !reachable || !r || r.path === "root"
      if (!r || (viaRoot && !kub0Installed)) {
        changeInFlight = null
        lastBlockError = "Destination sharing is a setting of the system daemon, and kub0 is not installed here to change it."
        return
      }
      if (viaRoot) {
        change.via = "root"
        kub0Exit = {}
        kub0Proc.command = Control.kub0Command(pkexecPath, kub0Path, r.argv)
        kub0Proc.running = true
        return
      }
    }
    if (!reachable && Control.isPolicyChange(change.args)) {
      if (!kub0Installed) {
        // A user-only install: no daemon enforces, so the user daemon's
        // snooze only quiets alerts.
        changeInFlight = null
        userDaemonPolicyChange(change.args)
        return
      }
      // A system install this session cannot reach: not in the kub0 group yet,
      // or not logged in again since being added. Root reaches the system
      // daemon, the only one that enforces, so the change still goes there.
      change.via = "root"
      policyViewBlind = true
      kub0Exit = {}
      kub0Proc.command = Control.kub0Command(pkexecPath, kub0Path, r.argv)
      kub0Proc.running = true
      return
    }
    if (!reachable || !r || (r.path === "root" && !kub0Installed)) {
      // Fallback, kept for one release: no system daemon this user can reach
      // (none installed, or not a member of the kub0 group), or no installed
      // kub0 for a change that needs root. The helper runs through pkexec as
      // before (its polkit actions are deprecated, docs/system-status.md).
      changeInFlight = null
      runHelper(change.args)
      return
    }
    if (r.path === "system") {
      change.via = "system"
      if (!controlRequest(r.cmd, r.request, function(reply) { root.finishChange(Control.replyEvent(reply)) })) {
        changeInFlight = null
        if (Control.isSharingChange(change.args))
          lastBlockError = "The system daemon connection closed; the sharing setting did not change."
        else
          runHelper(change.args)
      }
      return
    }
    change.via = "root"
    kub0Exit = {}
    kub0Proc.command = Control.kub0Command(pkexecPath, kub0Path, r.argv)
    kub0Proc.running = true
  }

  function finishChange(ev) {
    var change = changeInFlight
    changeInFlight = null
    if (change)
      applyChangeOutcome(change.args, ev)
    if (statusRefreshPending)
      Qt.callLater(root.probeHelperStatus)
  }

  // kub0's stdout, stderr and exit arrive separately; the change ends on all
  // three.
  function onKub0Part(key, value) {
    var e = {}
    for (var k in kub0Exit)
      e[k] = kub0Exit[k]
    e[key] = value
    kub0Exit = e
    if (e.out === undefined || e.err === undefined || e.code === undefined)
      return
    kub0Exit = {}
    finishChange(Control.kub0Event(e.out, e.err, e.code))
  }

  // Call `cb(true)` once the request connection is greeted by a system daemon
  // that answers requests, `cb(false)` when it cannot be reached.
  function withSystem(cb) {
    if (shuttingDown) {
      cb(false)
      return
    }
    if (sysState === "ready" && sysSock && sysSock.connected) {
      sysIdle.stop()
      cb(true)
      return
    }
    sysWaiters.push(cb)
    if (sysState === "connecting")
      return
    openSystemSocket(systemSocketPath)
  }

  function openSystemSocket(path) {
    closeSystemSocket()
    sysState = "connecting"
    sysGeneration += 1
    sysSock = systemSocketComponent.createObject(root, { path: path, socketGeneration: sysGeneration })
    if (!sysSock) {
      systemUnreachable()
      return
    }
    sysSock.connected = true
    sysDeadline.restart()
  }

  // A connect that failed: the system daemon is unreachable. There is one
  // socket; a 0.4.x daemon's is not tried.
  function systemConnectFailed() {
    systemUnreachable()
  }

  function flushSystemWaiters(reachable) {
    var waiting = sysWaiters
    sysWaiters = []
    for (var i = 0; i < waiting.length; i++)
      waiting[i](reachable)
    if (reachable && Object.keys(sysPending).length === 0)
      sysIdle.restart()
  }

  function systemUnreachable() {
    closeSystemSocket()
    flushSystemWaiters(false)
  }

  function closeSystemSocket() {
    sysDeadline.stop()
    sysIdle.stop()
    sysRequestTimeout.stop()
    sysGeneration += 1
    var old = sysSock
    sysSock = null
    sysState = "idle"
    if (old) {
      try { old.connected = false } catch (e) { }
      old.destroy()
    }
    failSystemRequests("the system daemon connection closed before it answered")
  }

  function failSystemRequests(message) {
    var pending = sysPending
    sysPending = ({})
    for (var req in pending)
      pending[req]({ req: req, ok: false, error: message })
  }

  // One control request on the request connection; `onReply` gets the reply
  // frame. False when there is no greeted connection to send it on.
  function controlRequest(cmd, fields, onReply) {
    if (!sysSock || sysState !== "ready" || !sysSock.connected)
      return false
    var req = "panel-" + (++sysSerial)
    try {
      sysSock.write(Control.requestLine(req, cmd, fields) + "\n")
      sysSock.flush()
    } catch (e) {
      return false
    }
    sysPending[req] = onReply
    sysIdle.stop()
    sysRequestTimeout.restart()
    return true
  }

  function onSystemSocketRead(sock, generation, line) {
    if (sock !== sysSock || generation !== sysGeneration)
      return
    var f = Control.systemFrame(line)
    if (!f)
      return
    if (f.type === "hello") {
      if (sysState !== "connecting")
        return
      if (Control.helloUsable(f)) {
        sysState = "ready"
        sysDeadline.stop()
        flushSystemWaiters(true)
      } else {
        systemUnreachable()
      }
      return
    }
    if (f.partial === true || !Object.prototype.hasOwnProperty.call(sysPending, f.req))
      return
    var done = sysPending[f.req]
    delete sysPending[f.req]
    if (Object.keys(sysPending).length === 0) {
      sysRequestTimeout.stop()
      sysIdle.restart()
    }
    done(f)
  }

  function onSystemSocketConnected(sock, generation, connected) {
    if (sock !== sysSock || generation !== sysGeneration || connected)
      return
    if (sysState === "connecting")
      systemConnectFailed()
    else
      closeSystemSocket()
  }

  function probeBinaries() {
    findBinProc.command = [
      "bash", "-c",
      "dir=" + shellQuote(pluginDir) + "; " +
      "found=''; " +
      "for p in \"$dir/bin/kub0d\" \"$dir/target/release/kub0d\" \"$dir/target/debug/kub0d\"; do " +
      "  if [ -x \"$p\" ]; then found=$p; break; fi; " +
      "done; " +
      "if [ -z \"$found\" ]; then found=$(command -v kub0d 2>/dev/null || true); fi; " +
      "printf 'kub0d=%s\\n' \"$found\"; " +
      "k=''; " +
      "for p in \"$dir/bin/kub0\" \"$dir/target/release/kub0\" \"$dir/target/debug/kub0\"; do " +
      "  if [ -x \"$p\" ]; then k=$p; break; fi; " +
      "done; " +
      "if [ -z \"$k\" ]; then k=$(command -v kub0 2>/dev/null || true); fi; " +
      "printf 'kub0=%s\\n' \"$k\"; " +
      "h=''; for p in " + helperPaths.map(shellQuote).join(" ") + "; do if [ -x \"$p\" ]; then h=$p; break; fi; done; " +
      "printf 'helper=%s\\n' \"$h\""
    ]
    findBinProc.running = true
  }

  function shellQuote(s) {
    return "'" + String(s || "").replace(/'/g, "'\\''") + "'"
  }

  function privilegedInstallCommand() {
    var dir = pluginDir
    if (!dir)
      return ""
    return "cd " + shellQuote(dir) + " && ./scripts/setup-from-ui.sh"
  }

  function launchSetupTerminal(inner) {
    if (!inner)
      return false
    var marker = ""
    var runtime = ""
    try { runtime = Quickshell.env("XDG_RUNTIME_DIR") || "" } catch (e) { runtime = "" }
    if (runtime)
      marker = runtime + "/kub0-setup-" + Date.now() + ".done"
    try {
      Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation",
        Setup.terminalCommand(inner, marker ? shellQuote(marker) : "")])
      setupDoneFile = marker
      return true
    } catch (e) {
      lastBlockError = "could not open a terminal"
      return false
    }
  }

  // The setup terminal's command has ended. Whether it worked is what the
  // watch is still looking for; that the buttons work again does not wait
  // for it. A failed install used to keep them disabled for ten minutes.
  function setupTerminalEnded() {
    setupDoneFile = ""
    if (!helperInstallPending)
      return
    helperInstallPending = false
    // A few more looks, to pick up what the command changed.
    helperWatchTicks = Math.max(helperWatchTicks, 295)
    refreshInstallState()
  }

  function watchHelperInstall(kind) {
    setupWatchFor = kind || "helper"
    helperInstallPending = true
    helperWatchTicks = 0
    helperWatch.restart()
  }

  function installPrivilegedHelper() {
    if (helperInstalled || helperInstallPending)
      return
    if (!launchSetupTerminal(privilegedInstallCommand()))
      return
    watchHelperInstall("helper")
  }

  function installBlockingPackages() {
    if (helperInstallPending)
      return
    if (!launchSetupTerminal("omarchy pkg add nftables conntrack-tools"))
      return
    watchHelperInstall("packages")
  }

  function applyBindPlan(plan) {
    var p = plan || Binds.offer
    root.offerBinds = !!p.needed
    root.offerNote = String(p.note || "")
    Binds.setOffer(p)
  }

  function enqueueWork(command, done) {
    workQueue.push({ command: command, done: done || null })
    runWork()
  }

  function runWork() {
    if (bindWorkProc.running || root.workCurrent)
      return
    if (!workQueue.length)
      return
    root.workCurrent = workQueue.shift()
    bindWorkProc.command = root.workCurrent.command
    bindWorkProc.running = true
  }

  function scanBinds() {
    enqueueWork(["hyprctl", "-j", "binds"], function(text, code) {
      if (Number(code) !== 0) {
        root.offerBinds = true
        if (!root.offerNote)
          root.offerNote = "Set Super+Alt+S to open kub0"
        return
      }
      root.applyBindPlan(Binds.applyScan(text))
    })
  }

  function notifyNewBinds(plan) {
    var body = Binds.notifyBody(plan.toAdd, plan.skipped)
    if (!body)
      return
    Quickshell.execDetached(Binds.notifyArgv("kub0", "kub0 keybinding", body))
  }

  // Only called from an explicit Set hotkey click (or installBinds IPC).
  // Never from Component.onCompleted / scanBinds.
  function installBinds(arg) {
    var _a = arg
    enqueueWork(["hyprctl", "-j", "binds"], function(text, code) {
      if (Number(code) !== 0) {
        root.offerNote = "could not read keybinds"
        root.offerBinds = true
        return
      }
      var plan = Binds.applyScan(text)
      if (!plan.toAdd || !plan.toAdd.length) {
        root.applyBindPlan(plan)
        return
      }
      var lua = Binds.luaBlock(plan.toAdd)
      enqueueWork(["python3", root.pluginDir + "/compat/install-binds.py", root.pluginId, lua], function(out, instCode) {
        if (Number(instCode) !== 0) {
          root.offerNote = "could not write ~/.config/hypr/bindings.lua"
          root.offerBinds = true
          return
        }
        root.notifyNewBinds(plan)
        Qt.callLater(root.scanBinds)
      })
    })
    return "ok"
  }

  // The release that matches this panel: downloaded, checked against its
  // checksum, and installed by its own `sudo ./kub0 install`, in a terminal
  // the user watches (scripts/install-release.sh). Done when the helper is
  // where `kub0 install` puts it.
  function installRelease() {
    if (helperInstallPending)
      return
    var dir = pluginDir
    if (!dir)
      return
    if (!launchSetupTerminal("cd " + shellQuote(dir) + " && ./scripts/install-release.sh"))
      return
    watchHelperInstall("helper")
  }

  function buildVallumd() {
    if (helperInstallPending)
      return
    var dir = pluginDir
    if (!dir)
      return
    if (!launchSetupTerminal("cd " + shellQuote(dir) + " && ./build.sh"))
      return
    watchHelperInstall("daemon")
  }

  function applyBinaryMap(text) {
    var lines = String(text || "").split("\n")
    for (var i = 0; i < lines.length; i++) {
      var pair = lines[i].split("=")
      if (pair.length < 2)
        continue
      var k = pair[0]
      var v = pair.slice(1).join("=").trim()
      if (k === "kub0d")
        vallumdPath = v
      if (k === "helper") {
        helperPath = v
        if (helperPaths.indexOf(v) >= 0)
          canonicalHelper = v
      }
      if (k === "kub0")
        localKub0Path = v
    }
    daemonAvailable = vallumdPath !== ""
    helperInstalled = helperPath === canonicalHelper
    if (!helperInstalled) {
      blockingToolsReady = false
      helperStatusFailed = false
      helperBlockCount = 0
    } else
      probeHelperStatus()
    chooseSource()
  }

  function probeHelperStatus() {
    if (!helperInstalled)
      return
    if (changeRunning() || helperStatusProc.running) {
      statusRefreshPending = true
      return
    }
    statusRefreshPending = false
    statusRequestGeneration = helperMutationGeneration
    helperStatusParsed = false
    helperStatusProc.command = [canonicalHelper, "status"]
    helperStatusProc.running = true
  }

  function applyHelperStatus(text) {
    // A status started before a block/unblock may finish after it. Never let
    // that older snapshot erase the row needed to undo a live kernel rule.
    if (statusRequestGeneration !== helperMutationGeneration || changeRunning()) {
      statusRefreshPending = true
      return
    }
    var raw = String(text || "").trim()
    var ev
    try { ev = JSON.parse(raw) } catch (e) {
      helperStatusFailed = true
      blockingToolsReady = false
      helperBlockCount = 0
      blockingToolsHint = "helper status unreadable — install nftables and conntrack-tools (cgroup v2 required). Monitoring still works."
      return
    }
    if (!ev || typeof ev !== "object") {
      helperStatusFailed = true
      blockingToolsReady = false
      helperBlockCount = 0
      blockingToolsHint = "helper status unreadable — install nftables and conntrack-tools (cgroup v2 required). Monitoring still works."
      return
    }
    helperStatusFailed = false
    helperStatusParsed = true
    var scopedChanged = false
    temporaryRulesError = ev.temporaryRulesKnown === false ? String(ev.temporaryRulesError || "Timed rule state is unavailable") : ""
    if (ev.temporaryRulesKnown !== false && Object.prototype.toString.call(ev.temporaryRules) === "[object Array]") {
      temporaryRules = ev.temporaryRules
      ConnectionModel.setTemporaryRules(model, temporaryRules, Date.now())
      scopedChanged = true
    }
    blockingToolsReady = ev.blockingReady === true
    enforcementPaused = ev.paused === true
    hostCriticalIps = Array.isArray(ev.hostCritical) ? ev.hostCritical.map(String) : []
    // Whole status, not just ev.owners: cgroup blocks never reach the owners
    // map, so owners alone reads 0 during a live block. See blockedAppCount.
    helperBlockCount = Health.blockedAppCount(ev)
    blockingToolsHint = ev.hint ? String(ev.hint) : ""
    // The helper has been reporting `owners` since it was written and nothing
    // read it. That map is the on-disk record of every endpoint block — the
    // rules it describes are live in nftables right now and survive a shell
    // restart, while `model.blocked` starts empty every launch. Dropping it
    // meant the panel could come back up showing nothing blocked while the
    // kernel was still enforcing, with no surface anywhere to discover or undo
    // it. probeHelperStatus() runs on load and on every panel open, so this is
    // also what keeps the UI honest if a block is changed out of band.
    // An unprivileged panel cannot read nftables on this host. The helper's
    // root-written markers preserve known cgroup blocks across a shell
    // restart; they are recorded state, not a fresh kernel verification.
    // A failed nft read with no marker source remains unknown, not empty.
    var cgroupKnown = ev.table === true
      || (ev.cgroupBlocksSource === "marker" && ev.cgroupBlocksKnown === true)
    var cgroupApps = cgroupKnown && ev.cgroupBlocks && typeof ev.cgroupBlocks.length === "number"
      ? ev.cgroupBlocks : undefined
    var blocksChanged = ConnectionModel.rehydrateBlocked(model, ev.owners, cgroupApps)
    if (blocksChanged) {
      ConnectionModel.rebuild(model, Date.now())
    }
    if (scopedChanged || blocksChanged)
      syncFromModel()
    if (!blockingToolsReady && !blockingToolsHint) {
      var pkgs = ev.packages
      if (pkgs && pkgs.length)
        blockingToolsHint = "install " + pkgs.join(", ") + " — blocking requires nftables, conntrack-tools, and cgroup v2"
      else
        blockingToolsHint = "blocking unavailable — need nftables, conntrack-tools, and cgroup v2. Monitoring still works."
    }
  }

  function probePolkit() {
    if (adapter.polkitEnabled(pluginRegistry)) {
      polkitAgentPresent = true
      return
    }
    polkitProc.command = [
      "bash", "-c",
      "pgrep -af 'PolkitAgent|polkit-gnome-authentication-agent|polkit-kde-authentication-agent|lxqt-policykit|mate-polkit|xfce-polkit' >/dev/null"
    ]
    polkitProc.running = true
  }

  function guessOrigin() {
    var tz = ""
    try { tz = Quickshell.env("TZ") || "" } catch (e) { tz = "" }
    origin = Geo.timezoneOrigin(tz)
    if (!tz)
      tzProc.running = true
  }

  function statusPayload() {
    var now = Date.now()
    var view = Health.derive(health, now, { count: activeCount })
    return Health.statusPayload(view, {
      count: root.activeCount,
      history: root.model ? (root.model.historyCount || 0) : 0,
      daemon: root.daemonStatus,
      blocking: root.blockingReady,
      coverage: root.coverage,
      fallback: root.usingFallback,
      helper: root.helperInstalled,
      polkit: root.polkitAgentPresent,
      needsHelper: root.needsHelperInstall,
      panelVersion: root.panelVersion,
      daemonVersion: root.daemonVersion,
      setup: root.setupStage,
      bindOfferNeeded: root.offerBinds,
      bindOfferNote: root.offerNote,
      anyBlocked: root.anyBlocked,
      sessionKnownBlocks: Health.sessionKnownIds(root.model ? root.model.blocked : {})
    })
  }

  onPluginRegistryChanged: probePolkit()
  // kub0 was just installed (the Install button, or by hand): the panel that
  // said "not built" has a system daemon to look for now.
  onKub0InstalledChanged: {
    if (kub0Installed)
      rerun(groupCheck)
    if (kub0Installed && daemonStatus === "missing")
      chooseSource()
  }
  onBlockingReadyChanged: syncHealthView()
  onAnyBlockedChanged: syncHealthView()
  onBlockHintChanged: syncHealthView()

  Component.onCompleted: {
    refreshSystemDiagnostics()
    guessOrigin()
    probeBinaries()
    probePolkit()
    installCheck.running = true
    kub0Check.running = true
    Qt.callLater(root.scanBinds)
    syncHealthView()
    ensurePrefsDir.running = true
    // Give mkdir a tick before the first read. FileView reports an absent file
    // as empty text rather than failing, which Prefs.parse treats as a first
    // run, so a race here degrades to defaults rather than to an error.
    Qt.callLater(function() { prefsFile.reload() })
  }

  function refreshSystemDiagnostics() {
    if (systemStatusProc.running || shuttingDown) return
    systemStatusActiveGeneration = ++systemStatusGeneration
    systemStatusTimedOut = false
    systemStatusProc.running = true
    systemStatusDeadline.restart()
  }

  // A trusted OS interpreter checks all installed CLI ancestors BEFORE native
  // execution. -I/-S and clearEnvironment isolate inherited loader/Python state.
  // Never uses vallumdPath, PATH discovery, eventSock or the helper response.
  Process {
    id: systemStatusProc
    command: ["/usr/bin/python3", "-I", "-S", "-c", SystemStatus.bootstrap]
    clearEnvironment: true
    environment: ({ "LANG": "C", "LC_ALL": "C" })
    stdout: StdioCollector { id: systemStatusOutput }
    onExited: function(code, exitStatus) {
      systemStatusDeadline.stop()
      if (root.systemStatusActiveGeneration !== root.systemStatusGeneration) return
      root.systemDiagnostics = SystemStatus.finish(root.systemDiagnostics,
        String(systemStatusOutput.text || ""), exitStatus === 0 ? code : 1, root.systemStatusTimedOut, Date.now())
    }
  }
  Timer {
    id: systemStatusDeadline
    interval: 2000
    onTriggered: {
      root.systemStatusTimedOut = true
      ++root.systemStatusGeneration
      root.systemDiagnostics = SystemStatus.fail(root.systemDiagnostics, "System diagnostics timed out")
      systemStatusProc.signal(9)
    }
  }
  Timer {
    interval: 15000
    running: !root.shuttingDown
    repeat: true
    onTriggered: root.refreshSystemDiagnostics()
  }

  // ---------------------------------------------------- preferences
  //
  // Omarchy renders no settings UI for plugins — `barWidget.schema` and
  // `settingsForm` are written into the registry by shell.qml and never read
  // back—so kub0 owns its own store and its own editor. The store lives
  // here rather than in Panel.qml because the panel is torn down on close and
  // the bar widget needs the same values.

  readonly property string prefsPath: adapter.configDir() + "/ui.json"
  property var prefs: Prefs.defaults()
  property bool prefsLoaded: false
  property string prefsError: ""

  Process {
    id: ensurePrefsDir
    command: ["mkdir", "-p", adapter.configDir()]
    running: false
  }

  FileView {
    id: prefsFile
    path: root.prefsPath
    watchChanges: false
    atomicWrites: true
    printErrors: false
    onLoaded: root.loadPrefs(text(), null)
    // No ui.json here: a first run, or a panel that last ran as 0.4.6 or
    // earlier and kept it in the old settings folder
    // (Kub0Adapter.legacyConfigDir). Look there once. Either way
    // loadPrefs must run: without it prefsLoaded stays false forever,
    // savePrefs becomes a no-op, the file is never created, and every
    // preference silently resets on shell restart.
    onLoadFailed: root.legacyPrefsPath = adapter.legacyConfigDir() + "/ui.json"
  }

  // Empty until the file above turns out to be missing. A FileView loads
  // when its path is set and reports the outcome either way; one told not to
  // preload reports nothing on reload(), which left prefsLoaded false.
  property string legacyPrefsPath: ""

  // Read only, and only when the file above is missing. The old file is
  // left where it is: nothing here deletes a user's settings.
  FileView {
    id: legacyPrefsFile
    path: root.legacyPrefsPath
    watchChanges: false
    printErrors: false
    onLoaded: if (root.legacyPrefsPath !== "") root.loadPrefs(null, text())
    onLoadFailed: if (root.legacyPrefsPath !== "") root.loadPrefs(null, null)
  }

  Timer {
    id: prefsSaveTimer
    interval: 200
    repeat: false
    onTriggered: prefsFile.setText(Prefs.serialize(root.prefs))
  }

  // `text` is ui.json where it lives now, `legacyText` the one from the old
  // folder; null is "no such file".
  function loadPrefs(text, legacyText) {
    // FileView can fire onLoaded more than once during startup — the implicit
    // preload when `path` resolves, and the explicit reload() above.
    if (root.prefsLoaded)
      return
    var source = Prefs.startupSource(text, legacyText)
    var r = Prefs.parse(source.raw)
    if (r.error) {
      root.prefsError = r.errorMessage
      console.warn("kub0: settings parse failed:", r.errorMessage)
    }
    root.prefs = r.prefs
    root.prefsLoaded = true
    if ((root.prefs.captureEnabled === true || root.prefs.shareDestinations === true) && daemonProc.running)
      daemonProc.running = false // onExited restarts with the loaded preference
    // Capture runs only in the panel's own daemon: a source picked before the
    // preferences were read is picked again. (One still being picked reads
    // them when the system daemon answers.)
    if (captureNeedsOwnDaemon() && eventSource === "system")
      chooseSource()
    // A file that failed to parse is rewritten from defaults so the bad text
    // does not sit there re-failing on every start. Settings carried over
    // from the old folder are written to the new one now, not at the first
    // change, so the panel reads one file from here on.
    if (r.error || source.carried)
      prefsSaveTimer.restart()
  }

  // Single write path. Returns the applied value so a caller can tell when a
  // write was rejected by the clamp rather than silently ignored.
  function setPref(key, value) {
    var next = Prefs.withValue(root.prefs, key, value)
    if (!Prefs.changed(root.prefs, next))
      return next[key]
    // Assign a NEW object: mutating in place fires no change signal, so no
    // binding on prefs.* would re-evaluate. Same trap as the row model.
    root.prefs = next
    if ((key === "captureEnabled" || key === "shareDestinations") && daemonProc.running)
      daemonProc.running = false
    if (key === "captureEnabled")
      chooseSource()
    if (root.prefsLoaded)
      prefsSaveTimer.restart()
    return next[key]
  }

  function resetPrefs() {
    var wasCapture = root.prefs.captureEnabled === true || root.prefs.shareDestinations === true
    root.prefs = Prefs.defaults()
    if (wasCapture && daemonProc.running)
      daemonProc.running = false
    if (wasCapture)
      chooseSource()
    root.prefsError = ""
    if (root.prefsLoaded)
      prefsSaveTimer.restart()
  }

  Process {
    id: findBinProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyBinaryMap(text)
    }
  }

  Process {
    id: polkitProc
    onExited: function(code) { root.polkitAgentPresent = (code === 0) || adapter.polkitEnabled(root.pluginRegistry) }
  }

  Process {
    id: tzProc
    command: ["bash", "-c", "readlink /etc/localtime 2>/dev/null | sed 's|.*/zoneinfo/||'; timedatectl show -p Timezone --value 2>/dev/null | head -1"]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        var tz = String(text || "").trim().split("\n")[0]
        if (tz)
          root.origin = Geo.timezoneOrigin(tz)
      }
    }
  }

  Process {
    id: helperStatusProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.applyHelperStatus(text)
    }
    onExited: function(code) {
      if (code !== 0 && !root.helperStatusParsed
          && root.statusRequestGeneration === root.helperMutationGeneration
          && !root.changeRunning()) {
        root.helperStatusFailed = true
        root.blockingToolsReady = false
        root.helperBlockCount = 0
        root.blockingToolsHint = root.blockingToolsHint || "helper status failed — install nftables and conntrack-tools (cgroup v2 required)"
      }
      if (root.statusRefreshPending && !root.changeRunning())
        Qt.callLater(root.probeHelperStatus)
    }
  }

  Process {
    id: installCheck
    command: ["bash", "-c", "for p in \"$@\"; do if [ -x \"$p\" ]; then printf '%s' \"$p\"; exit 0; fi; done; exit 1", "helper"].concat(root.helperPaths)
    stdout: StdioCollector {
      id: installCheckOut
      waitForEnd: true
    }
    onExited: function(code) {
      root.helperInstalled = (code === 0)
      if (code === 0) {
        var found = String(installCheckOut.text || "").trim()
        if (root.helperPaths.indexOf(found) >= 0)
          root.canonicalHelper = found
        root.helperPath = root.canonicalHelper
        root.helperStatusFailed = false
        root.probeHelperStatus()
      } else {
        root.blockingToolsReady = false
        root.helperStatusFailed = false
        root.helperBlockCount = 0
      }
    }
  }

  Process {
    id: kub0Check
    command: ["test", "-x", root.kub0Path]
    onExited: function(code) { root.kub0Installed = (code === 0) }
  }

  // `id -Gn` is this session's groups; `id -Gn <name>` is the account's, as
  // the group database has them now. A member whose session is older than
  // the membership is in the second and not the first.
  Process {
    id: groupCheck
    command: ["sh", "-c", Setup.GROUP_CHECK]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.sessionGroup = Setup.sessionGroup(text)
    }
  }

  // Has the setup terminal left its file? Taking it away is part of the
  // answer, so one terminal is reported once.
  Process {
    id: setupDoneCheck
    command: ["sh", "-c", "[ -e \"$1\" ] && rm -f \"$1\"", "sh", root.setupDoneFile]
    onExited: function(code) {
      if (code === 0)
        root.setupTerminalEnded()
    }
  }

  // `pkexec kub0 --json …` for a change the system daemon keeps to root.
  Process {
    id: kub0Proc
    stdout: StdioCollector {
      id: kub0Out
      waitForEnd: true
      onStreamFinished: root.onKub0Part("out", String(kub0Out.text || ""))
    }
    stderr: StdioCollector {
      id: kub0Err
      waitForEnd: true
      onStreamFinished: root.onKub0Part("err", String(kub0Err.text || ""))
    }
    onExited: function(code) { root.onKub0Part("code", code) }
  }

  Component { id: systemSocketComponent
    Socket {
      id: systemSocket
      property int socketGeneration: 0
      parser: SplitParser {
        onRead: function(line) { root.onSystemSocketRead(systemSocket, systemSocket.socketGeneration, line) }
      }
      onConnectedChanged: root.onSystemSocketConnected(systemSocket, systemSocket.socketGeneration, connected)
      onError: {
        if (systemSocket === root.sysSock && root.sysState === "connecting")
          root.systemUnreachable()
      }
    }
  }

  // No greeting from the system socket in time: treat it as unreachable.
  Timer {
    id: sysDeadline
    interval: 3000
    repeat: false
    onTriggered: if (root.sysState === "connecting") root.systemUnreachable()
  }

  // Close the request connection when nothing is waiting on it.
  Timer {
    id: sysIdle
    interval: 3000
    repeat: false
    onTriggered: if (Object.keys(root.sysPending).length === 0 && root.sysWaiters.length === 0) root.closeSystemSocket()
  }

  // A request the system daemon never answers: a block runs the helper, which
  // can take a while, so this is generous.
  Timer {
    id: sysRequestTimeout
    interval: 90000
    repeat: false
    onTriggered: root.closeSystemSocket()
  }

  Process {
    id: connectProc
    stdout: SplitParser {
      onRead: function(line) { root.onConnectStdout(line) }
    }
    stderr: StdioCollector {
      id: connectErr
    }
    onExited: function(code) {
      if (root.connectVia === "kub0") {
        var err = String(connectErr.text || "")
        Qt.callLater(function() { root.onKub0LoginExit(err, code) })
        return
      }
      if (root.connectState === "waiting" && code !== 0) {
        var msg = String(connectErr.text || "").trim()
        if (!root.connectError)
          root.connectError = msg || ("connect exited " + code)
        root.connectState = "error"
      }
    }
  }

  Process {
    id: disconnectProc
    stdout: StdioCollector { }
    stderr: StdioCollector { }
    onExited: root.refreshSystemView()
  }

  Process {
    id: daemonProc
    stdout: StdioCollector { }
    stderr: StdioCollector { id: daemonErr }
    onStarted: {
      root.daemonStatus = "starting"
      sockConnectDelay.restart()
    }
    onExited: function() {
      // Stopped because the panel now reads the system daemon: the socket in
      // use is that daemon's, and nothing restarts this one.
      if (root.eventSource === "system" && !root.shuttingDown)
        return
      if (root.shuttingDown) {
        root.failPendingSocketRequests("service shutting down; pending request cancelled")
        return
      }
      if (daemonErr.text)
        console.warn("kub0: daemon exited:", String(daemonErr.text).trim())
      sockConnectDelay.stop()
      sockRetry.stop()
      root.failPendingSocketRequests("kub0d exited; pending request cancelled")
      if (eventSock) {
        var old = eventSock
        eventSock = null
        socketGeneration += 1
        old.destroy()
      }
      root.retirePolicyEvidence()
      // A live daemon may exit while replay is active. Demo owns health and
      // status until the explicit exit path starts the live source again.
      if (root.usingFallback)
        return
      root.restarts += 1
      root.daemonStatus = "reconnecting"
      root.health = Health.markSocketDown(root.health, "reconnecting to kub0d")
      root.syncHealthView()
      restartTimer.interval = Math.min(8000, 400 * Math.pow(2, Math.min(root.restarts, 5)))
      restartTimer.restart()
    }
  }

  Timer {
    id: restartTimer
    interval: 800
    repeat: false
    onTriggered: {
      if (root.vallumdPath && !root.shuttingDown && !root.usingFallback)
        root.startDaemon()
    }
  }

  Timer {
    id: sockConnectDelay
    interval: 120
    repeat: false
    onTriggered: root.replaceEventSocket()
  }

  Component { id: eventSocketComponent
    Socket {
      id: socket
      property int socketGeneration: 0
      parser: SplitParser {
        onRead: function(line) { root.onEventSocketRead(socket, socket.socketGeneration, line) }
      }
      onConnectedChanged: root.onEventSocketConnected(socket, socket.socketGeneration, connected)
      onError: {
        if (root.currentSocket(socket, socket.socketGeneration) && root.daemonAvailable && !connected)
          root.scheduleSocketRetry()
      }
    }
  }

  Timer {
    id: sourceRecheck
    interval: 10000
    repeat: true
    running: root.eventSource === "user" && root.kub0Installed && !root.shuttingDown && !root.usingFallback
    onTriggered: root.recheckSource()
  }

  Timer {
    id: sockRetry
    interval: 250
    repeat: false
    onTriggered: {
      if ((eventSock && eventSock.connected) || !root.daemonAvailable || root.shuttingDown || root.usingFallback)
        return
      if (root.eventSource === "system") {
        root.retrySystemStream()
        return
      }
      if (!daemonProc.running)
        return
      root.replaceEventSocket()
    }
  }

  Component.onDestruction: {
    shuttingDown = true
    closeSystemSocket()
    socketGeneration += 1
    sockRetry.stop()
    sockConnectDelay.stop()
    restartTimer.stop()
    historyTimeout.stop()
    failPendingSocketRequests("service shutting down; pending request cancelled")
    if (eventSock) {
      var old = eventSock
      eventSock = null
      old.destroy()
    }
    if (daemonProc.running) daemonProc.running = false
  }

  Process {
    id: blockProc
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: root.onBlockOutput(text)
    }
    stderr: StdioCollector {
      id: blockErr
      waitForEnd: true
    }
    onExited: function(code) {
      if (code !== 0 && !root.lastBlockError)
        root.lastBlockError = (blockErr.text || "helper exit " + code).trim()
      if (root.statusRefreshPending)
        Qt.callLater(root.probeHelperStatus)
    }
  }

  FileView {
    id: replayView
    path: root.replayPath
    watchChanges: false
    printErrors: false
    onLoaded: {
      if (root.usingFallback && root.health && root.health.demo && !fallbackTimer.running) {
        root.fallbackIndex = 0
        fallbackTimer.restart()
      }
    }
  }

  property int fallbackIndex: 0

  Timer {
    id: fallbackTimer
    interval: 90
    repeat: true
    onTriggered: {
      if (!root.health || !root.health.demo) {
        stop()
        return
      }
      var raw = replayView.text ? replayView.text() : ""
      var lines = String(raw || "").split("\n")
      if (fallbackIndex >= lines.length) {
        fallbackTimer.stop()
        return
      }
      root.ingest(lines[fallbackIndex])
      fallbackIndex += 1
    }
  }

  Timer {
    id: pulseClear
    interval: 2200
    running: root.pulse
    repeat: false
    onTriggered: root.clearPulse()
  }

  Timer {
    interval: 400
    running: true
    repeat: true
    onTriggered: root.syncHealthView()
  }

  Process {
    id: bindWorkProc
    running: false
    stdout: StdioCollector {
      id: bindWorkOut
      waitForEnd: true
    }
    onExited: function(exitCode) {
      var text = bindWorkOut.text
      var job = root.workCurrent
      root.workCurrent = null
      if (job && job.done) {
        try {
          job.done(text, exitCode)
        } catch (e) {
          console.warn("kub0: bind work callback failed", e)
        }
      }
      root.runWork()
    }
  }

  Timer {
    interval: 4000
    repeat: true
    running: true
    onTriggered: root.scanBinds()
  }

  IpcHandler {
    target: "ai.kub0.agent"

    function status(arg: string): string {
      return JSON.stringify(root.statusPayload())
    }

    function ping(arg: string): string { return "ok" }

    function installBinds(arg: string): string { return root.installBinds(arg) }

    function install(arg: string): string {
      root.installPrivilegedHelper()
      return "launched"
    }

    // Report only. This used to accept `off|on` and drive the power switch,
    // which let any process running as the user pause every block on the
    // host: the helper is pkexec'd from this shell process, so inside the
    // auth_admin_keep window the pause needed no password at all. Turning
    // enforcement off stays on the panel's switch. A click is not the
    // boundary (same-user code can reach this process); the polkit policy is:
    // pause, unblock and teardown ask for a password every time.
    function enforcement(arg: string): string {
      var a = String(arg || "").trim()
      var out = {
        paused: root.enforcementPaused,
        busy: root.helperBusy,
        helper: root.helperInstalled,
        tools: root.blockingToolsReady,
        error: root.lastBlockError
      }
      if (a !== "")
        out.refused = "IPC reports enforcement only; change it with the panel switch"
      return JSON.stringify(out)
    }

    function refresh(arg: string): string {
      root.refreshInstallState()
      return JSON.stringify({ helper: root.helperInstalled, blocking: root.blockingReady })
    }

    function demo(arg: string): string {
      return root.enterDemo(arg)
    }
  }

  Timer {
    interval: 2500
    running: !root.helperInstalled
    repeat: true
    onTriggered: root.refreshInstallState()
  }

  // The bar learns about a pause only from a status read. Those ran on load,
  // on panel open and after each helper call, so a pause made anywhere else
  // (a terminal, another tool) left the wall up until the panel next opened.
  // `status` runs without pkexec, so this cannot prompt.
  Timer {
    id: pauseWatch
    interval: 30000
    running: root.helperInstalled
    repeat: true
    onTriggered: root.probeHelperStatus()
  }

  Timer {
    id: helperWatch
    interval: 2000
    repeat: true
    onTriggered: {
      root.helperWatchTicks += 1
      if (root.helperWatchTicks > 300) {
        stop()
        root.helperInstallPending = false
        root.setupWatchFor = ""
        return
      }
      root.refreshInstallState()
      if (root.setupDoneFile)
        root.rerun(setupDoneCheck)
      var done = false
      if (root.setupWatchFor === "packages")
        done = root.blockingToolsReady
      else if (root.setupWatchFor === "daemon")
        done = root.daemonAvailable
      else
        done = root.helperInstalled
      if (done) {
        stop()
        root.helperInstallPending = false
        root.setupWatchFor = ""
      }
    }
  }
}
