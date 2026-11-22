import QtQuick
import QtQuick.Window
import "../ConnectionModel.js" as ConnectionModel

// Exercises the exact data path Panel.qml now uses: a dynamicRoles ListModel
// holding one `app` role per row, reconciled in place, read by a delegate via
// `required property var model`.
//
// The claim under test is that delegates SURVIVE an update. That is the whole
// point of the change — a rebuilt delegate is what reset the scroll position
// and made transitions impossible — and it is the one thing a Node test of
// ConnectionModel.js cannot check.
Window {
  id: probe
  width: 400
  height: 400
  visible: true

  property int created: 0
  property int destroyed: 0
  property bool listHold: false
  property bool pendingResync: false
  property bool userResync: false
  property bool syncingRows: false
  readonly property bool listEngaged: listHold
  property var latestSrc: []
  property string sortKey: "name"
  property string filterKey: "all"
  property string selectedAppId: ""
  property int selectedIndex: -1
  property int structuralPasses: 0
  property int moveCount: 0
  property int insertCount: 0
  property int removeCount: 0
  property int tickMs: 60

  Timer {
    id: listHoldTimer
    interval: 1500
    repeat: false
    onTriggered: probe.listHold = false
  }

  function bumpListHold() {
    listHold = true
    listHoldTimer.restart()
  }

  onListEngagedChanged: if (!listEngaged && pendingResync) syncRows(probe.latestSrc)

  function resolveSelection() {
    selectedIndex = -1
    for (var i = 0; i < appModel.count; i++) {
      if (appModel.get(i).app.id === selectedAppId) {
        selectedIndex = i
        return
      }
    }
  }

  function applySortFilter(nextSort, nextFilter, src) {
    userResync = true
    sortKey = nextSort
    filterKey = nextFilter
    pendingResync = false
    syncRows(src)
    userResync = false
    resolveSelection()
  }

  function row(id, name, lastActivity, connCount, blocked) {
    var cs = []
    var i
    for (i = 0; i < connCount; i++)
      cs.push({ state: "ESTABLISHED" })
    return {
      id: id,
      name: name,
      flows: connCount,
      blocked: !!blocked,
      spark: [1, 2, connCount],
      lastActivity: lastActivity,
      connections: cs
    }
  }

  function derived(list, key, filter) {
    return ConnectionModel.filterApps(ConnectionModel.orderRows(list, key || sortKey), "", filter || filterKey)
  }

  ListModel {
    id: appModel
    dynamicRoles: true
  }

  // Verbatim port of Panel.qml's syncRows, including the engagement gate.
  function rowFor(a) {
    var out = {}
    for (var k in a) out[k] = a[k]
    return out
  }

  function syncRows(src) {
    probe.syncingRows = true
    probe.latestSrc = src
    var i, j, cur
    var structural = appModel.count !== src.length
    if (!structural) {
      for (i = 0; i < src.length; i++) {
        if (appModel.get(i).app.id !== src[i].id) { structural = true; break }
      }
    }
    if (structural && probe.listEngaged && !probe.userResync) {
      probe.pendingResync = true
      var byId = {}
      for (i = 0; i < src.length; i++)
        byId[src[i].id] = src[i]
      for (i = 0; i < appModel.count; i++) {
        cur = appModel.get(i).app
        if (byId[cur.id])
          appModel.setProperty(i, "app", rowFor(byId[cur.id]))
      }
      probe.syncingRows = false
      return
    }
    probe.pendingResync = false
    if (!structural) {
      for (i = 0; i < src.length; i++)
        appModel.setProperty(i, "app", rowFor(src[i]))
      probe.syncingRows = false
      return
    }
    probe.structuralPasses++
    var want = {}
    for (i = 0; i < src.length; i++)
      want[src[i].id] = true
    for (i = appModel.count - 1; i >= 0; i--) {
      if (!want[appModel.get(i).app.id]) {
        appModel.remove(i)
        probe.removeCount++
      }
    }
    for (i = 0; i < src.length; i++) {
      var at = -1
      for (j = i; j < appModel.count; j++) {
        if (appModel.get(j).app.id === src[i].id) { at = j; break }
      }
      if (at === -1) {
        appModel.insert(i, { app: rowFor(src[i]) })
        probe.insertCount++
      } else {
        if (at !== i) {
          appModel.move(at, i, 1)
          probe.moveCount++
        }
        appModel.setProperty(i, "app", rowFor(src[i]))
      }
    }
    probe.syncingRows = false
  }

  ListView {
    id: view
    anchors.fill: parent
    model: appModel
    cacheBuffer: 0
    delegate: Item {
      required property var model
      required property int index
      readonly property var appData: model.app
      // Mirrors Panel.qml's Canvas: it repaints on sparkData changing, not on
      // appData changing. That distinction is the whole question here.
      readonly property var sparkData: appData.spark || []
      // Mirrors Panel.qml exactly: the row repaints on appData, because a
      // binding to the spark array itself does not fire when the model pushes
      // onto that same array in place.
      onAppDataChanged: probe.sparkChanges++
      // A REAL binding, the kind Panel.qml's ToggleSwitch uses. Reading
      // appData.blocked from a function dereferences the object at call time
      // and will happily see an in-place mutation a binding never received —
      // which is exactly how an earlier version of this test lied.
      readonly property bool boundBlocked: appData.blocked === true
      width: view.width
      height: 20
      Component.onCompleted: probe.created++
      Component.onDestruction: probe.destroyed++
      Text { text: parent.appData.name + " " + parent.appData.flows }
    }
  }

  function app(id, name, flows) { return { id: id, name: name, flows: flows, blocked: false, spark: [1, 2, flows] } }

  // What the DELEGATE can see, which is the only thing the user can see.
  // appModel.get(i) reads the stored value directly and will happily report a
  // change the delegate's bindings never received — so asserting on get() is a
  // lying gate for exactly the same-reference case below.
  function delegateBlocked(i) {
    var it = view.itemAtIndex(i)
    return it ? it.boundBlocked : "no-delegate"
  }

  property int fail: 0
  function check(name, cond, detail) {
    console.warn((cond ? "  ok   " : "  FAIL ") + name + (detail ? "  [" + detail + "]" : ""))
    if (!cond) probe.fail++
  }

  property int step: 0
  property int mark: 0
  property var sameRef: []
  property int sparkChanges: 0

  // Delegates are instantiated by the view on a later frame, not synchronously
  // inside syncRows. Counting them in one straight-line block measures nothing —
  // so each sample gets its own turn of the event loop before it is judged.
  Timer {
    id: stepper
    interval: probe.tickMs
    repeat: true
    running: true
    onTriggered: {
      probe.tickMs = 60
      switch (probe.step) {
      case 0:
        probe.syncRows([probe.app("aria", "Aria", 1), probe.app("firefox", "Firefox", 4), probe.app("zulip", "Zulip", 2)])
        break
      case 1:
        probe.check("initial rows built", appModel.count === 3 && probe.created === 3, probe.created + " delegates")
        probe.mark = probe.created
        for (var n = 0; n < 20; n++)
          probe.syncRows([probe.app("aria", "Aria", n), probe.app("firefox", "Firefox", n * 2), probe.app("zulip", "Zulip", n)])
        break
      case 2:
        probe.check("20 value-only updates created NO new delegates",
                    probe.created === probe.mark, "created " + probe.created + ", expected " + probe.mark)
        probe.check("...and destroyed none either", probe.destroyed === 0, "destroyed " + probe.destroyed)
        probe.check("the role value actually updated in the delegate",
                    appModel.get(1).app.flows === 38, "firefox flows = " + appModel.get(1).app.flows)
        probe.check("an array inside the role survives dynamicRoles",
                    appModel.get(1).app.spark.length === 3, "spark = " + JSON.stringify(appModel.get(1).app.spark))
        probe.mark = probe.created
        probe.syncRows([probe.app("aria", "Aria", 9), probe.app("slack", "Slack", 3), probe.app("zulip", "Zulip", 9)])
        break
      case 3:
        probe.check("a structural change rebuilds ONLY the new row",
                    probe.created - probe.mark === 1, "created " + (probe.created - probe.mark))
        probe.check("order is what was asked for",
                    appModel.get(0).app.id === "aria" && appModel.get(1).app.id === "slack" && appModel.get(2).app.id === "zulip",
                    [0,1,2].map(function (i) { return appModel.get(i).app.id }).join(","))
        probe.mark = probe.created
        probe.syncRows([probe.app("slack", "Slack", 3), probe.app("zulip", "Zulip", 9), probe.app("aria", "Aria", 9)])
        break
      case 4:
        probe.check("a pure reorder MOVES rows instead of rebuilding them",
                    probe.created - probe.mark === 0, "created " + (probe.created - probe.mark))
        probe.check("reordered correctly",
                    appModel.get(0).app.id === "slack" && appModel.get(2).app.id === "aria",
                    [0,1,2].map(function (i) { return appModel.get(i).app.id }).join(","))

        // The same-reference case. ConnectionModel.setBlocked deliberately
        // mutates the EXISTING app object so a privileged click shows up
        // immediately instead of waiting half a second for the next daemon
        // sample. syncRows then hands that same object back to setProperty.
        //
        // If the delegate does not see it, the toggle stays visually off while
        // the model says blocked — and the user's second click, reading
        // blocked=true from the model, sends UNBLOCK. Click twice, silently
        // undo the block.
        probe.sameRef = [probe.app("slack", "Slack", 3), probe.app("zulip", "Zulip", 9), probe.app("aria", "Aria", 9)]
        probe.syncRows(probe.sameRef)
        break
      case 5:
        probe.sameRef[0].blocked = true          // mutate in place, as setBlocked does
        probe.syncRows(probe.sameRef)            // hand back the SAME references
        break
      case 6:
        probe.check("stored value reflects the in-place mutation",
                    appModel.get(0).app.blocked === true,
                    "get(0).blocked = " + appModel.get(0).app.blocked)
        probe.check("THE DELEGATE sees an in-place mutation re-sent by setProperty",
                    probe.delegateBlocked(0) === true,
                    "delegate sees " + probe.delegateBlocked(0))
        // ConnectionModel.sampleSparklines does spark.push() on the SAME array
        // every tick, and a tick does not rebuild. So appData may re-signal
        // while sparkData resolves to an identical array reference — and a
        // binding whose value did not change does not fire. That would freeze
        // the sparkline at its last full-rebuild paint.
        probe.mark = probe.sparkChanges
        probe.sameRef[0].spark.push(99)
        probe.syncRows(probe.sameRef)
        break
      case 7:
        probe.check("an in-place spark push still triggers the delegate repaint",
                    probe.sparkChanges > probe.mark,
                    "repaint fired " + (probe.sparkChanges - probe.mark) + " time(s)")
        probe.syncRows([
          probe.row("aria", "Aria", 10, 5, false),
          probe.row("firefox", "Firefox", 20, 1, false),
          probe.row("zulip", "Zulip", 30, 3, true)
        ])
        probe.sortKey = "name"
        probe.filterKey = "all"
        probe.selectedAppId = "firefox"
        probe.resolveSelection()
        break
      case 8:
        probe.check("sort-filter fixture is name order",
                    appModel.get(0).app.id === "aria" && appModel.get(1).app.id === "firefox" && appModel.get(2).app.id === "zulip",
                    [0,1,2].map(function (i) { return appModel.get(i).app.id }).join(","))
        probe.mark = probe.created
        probe.structuralPasses = 0
        probe.moveCount = 0
        probe.insertCount = 0
        probe.removeCount = 0
        probe.sortKey = "activity"
        // Synthetic contentY change: same function Panel.qml's onContentYChanged calls.
        probe.bumpListHold()
        probe.tickMs = 200
        break
      case 9:
        probe.check("hold is engaged 200ms after contentY", probe.listHold === true, "listHold=" + probe.listHold)
        for (var n = 0; n < 20; n++) {
          probe.syncRows(probe.derived([
            probe.row("aria", "Aria", 10 + n, 5, false),
            probe.row("firefox", "Firefox", 20 + n * 10, 1, false),
            probe.row("zulip", "Zulip", 30 + n, 3, true)
          ], "activity", "all"))
        }
        probe.check("(a) activity burst under hold created NO new delegates",
                    probe.created === probe.mark, "created " + probe.created + ", expected " + probe.mark)
        probe.check("(a) zero moves while held", probe.moveCount === 0, "moves " + probe.moveCount)
        probe.check("(a) zero inserts while held", probe.insertCount === 0, "inserts " + probe.insertCount)
        probe.check("(a) zero removes while held", probe.removeCount === 0, "removes " + probe.removeCount)
        probe.check("(a) zero structural passes while held",
                    probe.structuralPasses === 0, "passes " + probe.structuralPasses)
        probe.check("(a) visible order unchanged under hold",
                    appModel.get(0).app.id === "aria" && appModel.get(1).app.id === "firefox" && appModel.get(2).app.id === "zulip",
                    [0,1,2].map(function (i) { return appModel.get(i).app.id }).join(","))
        probe.tickMs = 1800
        break
      case 10:
        probe.check("(a) hold elapsed", probe.listHold === false, "listHold=" + probe.listHold)
        probe.check("(a) exactly one structural pass after hold",
                    probe.structuralPasses === 1, "passes " + probe.structuralPasses)
        probe.check("(a) order is activity order after hold",
                    appModel.get(0).app.id === "firefox" && appModel.get(1).app.id === "zulip" && appModel.get(2).app.id === "aria",
                    [0,1,2].map(function (i) { return appModel.get(i).app.id }).join(","))
        probe.syncRows([
          probe.row("aria", "Aria", 10, 5, false),
          probe.row("firefox", "Firefox", 20, 1, false),
          probe.row("zulip", "Zulip", 30, 3, true)
        ])
        probe.sortKey = "name"
        probe.filterKey = "all"
        probe.selectedAppId = "firefox"
        probe.resolveSelection()
        probe.bumpListHold()
        probe.structuralPasses = 0
        probe.moveCount = 0
        probe.insertCount = 0
        probe.removeCount = 0
        probe.applySortFilter("connections", "all", probe.derived([
          probe.row("aria", "Aria", 10, 5, false),
          probe.row("firefox", "Firefox", 20, 1, false),
          probe.row("zulip", "Zulip", 30, 3, true)
        ], "connections", "all"))
        probe.check("(b) user sort bypasses hold: one structural pass immediately",
                    probe.structuralPasses === 1, "passes " + probe.structuralPasses)
        probe.check("(b) connections order",
                    appModel.get(0).app.id === "aria" && appModel.get(1).app.id === "zulip" && appModel.get(2).app.id === "firefox",
                    [0,1,2].map(function (i) { return appModel.get(i).app.id }).join(","))
        probe.check("(b) selected id still firefox",
                    probe.selectedAppId === "firefox", "selected " + probe.selectedAppId)
        probe.check("(b) selection resolved by id not index",
                    probe.selectedIndex === 2, "selectedIndex " + probe.selectedIndex)
        probe.mark = probe.created
        probe.destroyed = 0
        probe.applySortFilter("name", "blocked", probe.derived([
          probe.row("aria", "Aria", 10, 5, false),
          probe.row("firefox", "Firefox", 20, 1, false),
          probe.row("zulip", "Zulip", 30, 3, true)
        ], "name", "blocked"))
        break
      case 11:
        probe.check("(c) filterKey=blocked hides non-blocked rows",
                    appModel.count === 1 && appModel.get(0).app.id === "zulip",
                    "count=" + appModel.count + " id=" + (appModel.count ? appModel.get(0).app.id : "?"))
        probe.check("(c) blocked row kept its delegate",
                    probe.created === probe.mark, "created " + probe.created + ", expected " + probe.mark)
        console.warn(probe.fail === 0 ? "PROBE PASS" : "PROBE FAIL (" + probe.fail + ")")
        Qt.exit(probe.fail === 0 ? 0 : 1)
        break
      }
      probe.step++
      stepper.interval = probe.tickMs
    }
  }
}
