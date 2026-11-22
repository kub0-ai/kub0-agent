import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "js/Ux.js" as Ux
import "js/Intel.js" as Intel
import "js/Kub0.js" as Kub0
import "ConnectionModel.js" as ConnectionModel

// Local intelligence: indicators on the current rows, what this machine
// listens on, the user's watch rules, and a pivot drawer over retained
// history. Everything shown here was computed on this machine by the daemon
// (docs/INTEL.md); this view orders and phrases it through js/Intel.js.
Item {
  id: root
  objectName: "intelView"
  property var service: null
  // The kub0 snapshot, for org prevalence lines (js/Kub0.js prevalenceText).
  property var kub0: null
  // The service's ConnectionModel state and the revision that says it moved.
  property var model: null
  property int revision: 0
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color badColor: Commons.Color.urgent
  property color warnColor: Commons.Color.accent
  property string fontFamily: Style.font.family
  // Font sizes and the gap multiplier: the textSize and density preferences,
  // handed down by the panel (js/Ux.js). Alone, a view uses the kit's sizes.
  property var ux: Ux.metrics(Style.font, "normal", "normal", "mixed", "binary")
  // The scrollSpeed and scrollMomentum preferences, handed down by the panel.
  property string scrollSpeed: "normal"
  property bool scrollMomentum: true
  property string query: ""
  property string severityFilter: ""
  // indicators | exposure | watch
  property string section: "indicators"
  property string watchKind: "asn"
  property string watchFormError: ""
  property bool drawerOpen: false
  property var drawerConnection: null
  signal viewEvidence(var connection)

  readonly property bool searchFocused: search.activeFocus || watchValue.activeFocus || watchNote.activeFocus
  readonly property var allRows: {
    var _r = revision
    return Intel.indicatorRows(model && model.connections ? model.connections : {})
  }
  readonly property var rows: Intel.filterRows(allRows, severityFilter, query)
  readonly property var counts: Intel.summarize(allRows)
  readonly property var listeners: {
    var _r = service ? service.listenersRevision : 0
    return Intel.listenerRows(service && service.listeners ? service.listeners : [])
  }
  readonly property var watchRules: {
    var _r = service ? service.watchRevision : 0
    return Intel.watchRows(service && service.watchRules ? service.watchRules : [], Date.now())
  }
  readonly property string watchError: service && service.watchError ? service.watchError : ""
  readonly property var pivot: service ? service.investigateResult : null
  readonly property bool pivotBusy: service && service.investigateBusy === true
  readonly property string pivotError: service && service.investigateError ? service.investigateError : ""
  readonly property string pivotSubject: service && service.investigateSubject ? service.investigateSubject : ""
  // Timeline: when this machine talked, by app and by hour (js/Intel.js).
  readonly property var timeline: service ? service.timelineResult : null
  readonly property bool timelineBusy: service && service.timelineBusy === true
  readonly property string timelineError: service && service.timelineError ? service.timelineError : ""
  readonly property int timelineHours: service && service.timelineHours ? service.timelineHours : 24
  readonly property var timelineRows: Intel.timelineRows(root.timeline)
  readonly property var timelineLabels: Intel.timelineLabels(root.timeline)
  readonly property int timelineBuckets: Intel.normalizeTimeline(root.timeline).buckets
  property string timelineHover: ""

  function refreshTimeline(hours) {
    if (service && typeof service.requestTimeline === "function")
      service.requestTimeline(hours || timelineHours)
  }
  onSectionChanged: if (section === "timeline" && visible) refreshTimeline(timelineHours)

  function focusSearch() {
    if (section === "watch") watchValue.forceActiveFocus()
    else search.forceActiveFocus()
  }
  // Whether an indicator row may offer a timed destination block, through the
  // same helper verb and the same gates the Apps view uses (js/Intel.js).
  function blockStateFor(connection) {
    var _t = service ? service.healthTick : 0
    var app = service && typeof service.appById === "function" && connection && connection.app ? service.appById(connection.app.id) : null
    return Intel.destinationBlockState({
      app: app,
      ip: connection && connection.remote ? connection.remote.ip : "",
      port: connection && connection.remote ? connection.remote.port : 0,
      blockingReady: service ? service.blockingReady === true : false,
      helperBusy: service ? service.helperBusy === true : false,
      current: service ? service.dataCurrent === true : false,
      enforcementPaused: service ? service.enforcementPaused === true : false,
      rules: service && service.temporaryRules ? service.temporaryRules : [],
      helperId: ConnectionModel.helperId,
      isBlockable: ConnectionModel.isBlockable,
      hostWideUnsafe: ConnectionModel.hostWideUnsafe,
      now: Date.now()
    })
  }
  function blockDestination(connection, seconds) {
    var st = blockStateFor(connection)
    if (!st.canBlock || !service || typeof service.requestDestinationBlock !== "function") return
    service.requestDestinationBlock(st.appId, connection.remote.ip, seconds)
  }
  function toggleSeverity(s) { severityFilter = severityFilter === s ? "" : s }
  function investigate(subject, connection) {
    if (!subject || !service || typeof service.requestInvestigate !== "function") return
    drawerConnection = connection || null
    drawerOpen = true
    service.requestInvestigate(subject, 168)
  }
  function closeDrawer() {
    drawerOpen = false
    drawerConnection = null
    if (service && typeof service.clearInvestigate === "function") service.clearInvestigate()
  }
  function submitWatch() {
    var err = Intel.validateWatch(watchKind, watchValue.text)
    watchFormError = err
    if (err) return
    if (service && typeof service.setWatch === "function" && service.setWatch(watchKind, watchValue.text, watchNote.text)) {
      watchValue.text = ""
      watchNote.text = ""
    } else {
      watchFormError = "Connect to the live daemon to edit watch rules."
    }
  }
  // Watch the subject the drawer is pivoted on: "asn:13335" -> kind asn, value 13335.
  function watchSubject() {
    var s = pivotSubject
    var i = s.indexOf(":")
    if (i < 0) return
    var kind = s.substring(0, i)
    var value = s.substring(i + 1)
    if (kind === "ip") kind = "cidr"
    if (kind === "network") kind = "cidr"
    if (["asn", "country", "cidr", "host", "port", "app"].indexOf(kind) < 0) return
    if (service && typeof service.setWatch === "function") service.setWatch(kind, value, "from investigate")
  }
  onVisibleChanged: {
    if (!visible) closeDrawer()
    else if (section === "timeline") refreshTimeline(timelineHours)
  }

  Column {
    id: controls
    width: parent.width
    spacing: Style.space(8 * root.ux.gap)
    Text {
      width: parent.width
      text: "Intel"
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: root.ux.body
      font.bold: true
    }
    Text {
      width: parent.width
      objectName: "intelSummary"
      text: Intel.summaryLine(root.allRows) + " · " + Intel.exposureLine(root.listeners) + (root.watchRules.length ? " · " + root.watchRules.length + (root.watchRules.length === 1 ? " watch rule" : " watch rules") : "")
      color: Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }
    Flow {
      width: parent.width
      spacing: Style.space(6 * root.ux.gap)
      Repeater {
        model: [
          { value: "indicators", label: "Indicators" },
          { value: "timeline", label: "Timeline" },
          { value: "exposure", label: "Exposure" },
          { value: "watch", label: "Watchlist" }
        ]
        Button {
          fontSize: root.ux.body
          required property var modelData
          text: modelData.label + (modelData.value === "indicators" ? " " + root.counts.total : modelData.value === "exposure" ? " " + root.listeners.length : modelData.value === "watch" ? " " + root.watchRules.length : "")
          objectName: "intelSection_" + modelData.value
          selected: root.section === modelData.value
          bordered: true
          focusable: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.section = modelData.value
        }
      }
    }

    // ---------------------------------------------------------- indicators
    Rectangle {
      width: parent.width
      height: Style.space(38)
      visible: root.section === "indicators"
      color: "transparent"
      border.color: search.activeFocus ? root.accent : Qt.darker(root.foreground, 2)
      radius: Style.cornerRadius
      TextInput {
        id: search
        objectName: "intelSearch"
        anchors.fill: parent
        anchors.margins: Style.space(9 * root.ux.gap)
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: root.ux.bodySmall
        clip: true
        maximumLength: 128
        selectByMouse: true
        onTextChanged: root.query = text
        Keys.onEscapePressed: { text = ""; focus = false }
      }
      Text {
        anchors.left: parent.left
        anchors.leftMargin: Style.space(9)
        anchors.verticalCenter: parent.verticalCenter
        visible: !search.text && !search.activeFocus
        text: "Search app, peer, network, country, indicator, or ATT&CK id"
        color: Qt.darker(root.foreground, 1.6)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
      }
    }
    Flow {
      width: parent.width
      visible: root.section === "indicators"
      spacing: Style.space(6 * root.ux.gap)
      Repeater {
        model: ["warning", "notice", "info"]
        Button {
          fontSize: root.ux.body
          required property var modelData
          text: Intel.severityLabel(modelData) + " " + root.counts[modelData]
          objectName: "intelSeverity_" + modelData
          selected: root.severityFilter === modelData
          bordered: true
          focusable: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.toggleSeverity(modelData)
        }
      }
    }
    Text {
      width: parent.width
      visible: root.section === "indicators"
      text: root.allRows.length === 0
        ? "No indicators on the current rows. Baseline rungs speak only once an app has 20 connections over a day; see docs/INTEL.md for every rung."
        : root.rows.length === 0 ? "No indicators match." : "A claim with its basis, never a verdict. Update checkers beacon and backups upload; read the basis before acting."
      color: Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }

    // ------------------------------------------------------------ exposure
    Text {
      width: parent.width
      visible: root.section === "exposure"
      text: "Sockets this machine accepts connections on, from /proc. 'All interfaces' means reachable from any network this host is on, firewall permitting; kub0 does not read the firewall to say which."
      color: Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }

    // ------------------------------------------------------------ timeline
    Flow {
      width: parent.width
      visible: root.section === "timeline"
      spacing: Style.space(6 * root.ux.gap)
      Repeater {
        model: [{ hours: 24, label: "24 hours" }, { hours: 168, label: "7 days" }]
        Button {
          fontSize: root.ux.body
          required property var modelData
          text: (root.timelineHours === modelData.hours ? "✓ " : "") + modelData.label
          bordered: root.timelineHours === modelData.hours
          focusable: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.refreshTimeline(modelData.hours)
        }
      }
      Button {
        fontSize: root.ux.body
        text: "Refresh"
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.refreshTimeline(root.timelineHours)
      }
    }
    Text {
      width: parent.width
      visible: root.section === "timeline"
      objectName: "intelTimelineStatus"
      text: root.timelineBusy ? "Reading retained history…"
        : root.timelineError ? root.timelineError
        : Intel.timelineSummary(root.timeline)
      textFormat: Text.PlainText
      color: root.timelineError && !root.timelineBusy ? root.badColor : Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }

    // --------------------------------------------------------------- watch
    Text {
      width: parent.width
      visible: root.section === "watch"
      text: "A watch rule raises a warning on every new connection that matches it and records the hit in Recent activity. Rules live in ~/.local/state/kub0/watchlist.json; `kub0 watch add|rm` edits the same rules."
      color: Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }
    Flow {
      width: parent.width
      visible: root.section === "watch"
      spacing: Style.space(6 * root.ux.gap)
      Dropdown {
        id: watchKindPicker
        width: Style.space(170)
        foreground: root.foreground
        fontFamily: root.fontFamily
        options: Intel.WATCH_KINDS.map(function(k) { return { value: k.value, label: k.label } })
        value: root.watchKind
        onChanged: function(v) { root.watchKind = v; root.watchFormError = "" }
      }
      Rectangle {
        width: Style.space(200)
        height: Style.space(38)
        color: "transparent"
        border.color: watchValue.activeFocus ? root.accent : Qt.darker(root.foreground, 2)
        radius: Style.cornerRadius
        TextInput {
          id: watchValue
          objectName: "watchValue"
          anchors.fill: parent
          anchors.margins: Style.space(9 * root.ux.gap)
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: root.ux.bodySmall
          clip: true
          maximumLength: 256
          selectByMouse: true
          onTextChanged: root.watchFormError = ""
          Keys.onReturnPressed: root.submitWatch()
          Keys.onEscapePressed: { text = ""; focus = false }
        }
        Text {
          anchors.left: parent.left
          anchors.leftMargin: Style.space(9)
          anchors.verticalCenter: parent.verticalCenter
          visible: !watchValue.text && !watchValue.activeFocus
          text: {
            var k = Intel.WATCH_KINDS.filter(function(x) { return x.value === root.watchKind })[0]
            return k ? k.hint : ""
          }
          color: Qt.darker(root.foreground, 1.6)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
        }
      }
      Rectangle {
        width: Style.space(160)
        height: Style.space(38)
        color: "transparent"
        border.color: watchNote.activeFocus ? root.accent : Qt.darker(root.foreground, 2)
        radius: Style.cornerRadius
        TextInput {
          id: watchNote
          objectName: "watchNote"
          anchors.fill: parent
          anchors.margins: Style.space(9 * root.ux.gap)
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: root.ux.bodySmall
          clip: true
          maximumLength: 120
          selectByMouse: true
          Keys.onReturnPressed: root.submitWatch()
          Keys.onEscapePressed: { text = ""; focus = false }
        }
        Text {
          anchors.left: parent.left
          anchors.leftMargin: Style.space(9)
          anchors.verticalCenter: parent.verticalCenter
          visible: !watchNote.text && !watchNote.activeFocus
          text: "note (optional)"
          color: Qt.darker(root.foreground, 1.6)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
        }
      }
      Button {
        fontSize: root.ux.body
        text: "Add rule"
        objectName: "watchAdd"
        bordered: true
        focusable: true
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.submitWatch()
      }
    }
    Text {
      width: parent.width
      visible: root.section === "watch" && (root.watchFormError !== "" || root.watchError !== "")
      objectName: "watchStatus"
      text: root.watchFormError || root.watchError
      textFormat: Text.PlainText
      color: root.badColor
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }
  }

  // ------------------------------------------------------------ lists
  // What the indicator list renders, synced from `rows` in place and never
  // rebound. `rows` is a fresh array on every sample, and QML does not diff a
  // JS array model: a new array rebuilds every delegate and puts the list back
  // at the top, so a row below the first could not be scrolled to and kept in
  // view (seen live 10-13). Same fix as the Apps list (Panel.qml syncRows).
  ListModel {
    id: indicatorModel
    dynamicRoles: true
  }
  onRowsChanged: syncIndicators()
  Component.onCompleted: syncIndicators()

  // Reconcile keyed by row key (connection id + indicator id), so a row that is
  // still present keeps its delegate. Quadratic only when the set changes.
  function syncIndicators() {
    var src = rows || []
    var i, j
    var same = indicatorModel.count === src.length
    for (i = 0; same && i < src.length; i++)
      same = indicatorModel.get(i).row.key === src[i].key
    if (same) {
      for (i = 0; i < src.length; i++)
        indicatorModel.setProperty(i, "row", src[i])
      return
    }
    var want = {}
    for (i = 0; i < src.length; i++)
      want[src[i].key] = true
    for (i = indicatorModel.count - 1; i >= 0; i--) {
      if (!want[indicatorModel.get(i).row.key])
        indicatorModel.remove(i)
    }
    for (i = 0; i < src.length; i++) {
      var at = -1
      for (j = i; j < indicatorModel.count; j++) {
        if (indicatorModel.get(j).row.key === src[i].key) {
          at = j
          break
        }
      }
      if (at === -1) {
        indicatorModel.insert(i, { row: src[i] })
      } else {
        if (at !== i)
          indicatorModel.move(at, i, 1)
        indicatorModel.setProperty(i, "row", src[i])
      }
    }
  }

  ListView {
    id: indicatorList
    objectName: "intelIndicatorList"
    anchors.top: controls.bottom
    anchors.topMargin: Style.space(8 * root.ux.gap)
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    visible: root.section === "indicators"
    clip: true
    WheelStep { flick: indicatorList; speed: root.scrollSpeed; momentum: root.scrollMomentum }
    spacing: Style.space(6 * root.ux.gap)
    model: indicatorModel
    delegate: Rectangle {
      id: indicatorRow
      required property var model
      readonly property var modelData: model.row
      width: indicatorList.width
      height: body.implicitHeight + Style.space(18 * root.ux.gap)
      radius: Style.cornerRadius
      color: "transparent"
      border.color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
      Column {
        id: body
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: Style.space(9 * root.ux.gap)
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(4 * root.ux.gap)
        Row {
          width: parent.width
          spacing: Style.space(8 * root.ux.gap)
          Rectangle {
            width: Style.space(8)
            height: Style.space(8)
            radius: width / 2
            anchors.verticalCenter: parent.verticalCenter
            color: modelData.severity === "warning" ? root.badColor
              : modelData.severity === "notice" ? root.warnColor
              : Qt.darker(root.foreground, 1.6)
          }
          Text {
            width: parent.width - Style.space(16)
            text: Intel.severityLabel(modelData.severity) + " · " + modelData.title + (modelData.live ? "" : " · no longer observed")
            textFormat: Text.PlainText
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: root.ux.bodySmall
            font.bold: true
            elide: Text.ElideRight
          }
        }
        Text {
          width: parent.width
          text: [modelData.appName, modelData.peer, modelData.network, modelData.country].filter(function(s) { return s }).join(" · ")
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          elide: Text.ElideMiddle
        }
        Text {
          width: parent.width
          text: modelData.basis
          textFormat: Text.PlainText
          color: Qt.darker(root.foreground, 1.3)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
        Text {
          width: parent.width
          readonly property string prevalence: Kub0.prevalenceText(root.kub0, modelData.connection ? modelData.connection.networkKey : "")
          visible: prevalence !== ""
          text: prevalence
          textFormat: Text.PlainText
          color: Qt.darker(root.foreground, 1.5)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
        Text {
          width: parent.width
          visible: modelData.attack !== null
          text: modelData.attack ? "ATT&CK " + modelData.attack.id + " " + modelData.attack.name + " · the shape of what was observed, not a finding that it is in use" : ""
          textFormat: Text.PlainText
          color: Qt.darker(root.foreground, 1.5)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
        Flow {
          width: parent.width
          spacing: Style.space(6 * root.ux.gap)
          Repeater {
            model: Intel.pivotOptions(modelData.connection)
            Button {
              fontSize: root.ux.body
              required property var modelData
              text: "Investigate " + modelData.label
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.investigate(modelData.subject, indicatorRow.modelData.connection)
            }
          }
          Button {
            fontSize: root.ux.body
            text: "Evidence"
            foreground: root.foreground
            fontFamily: root.fontFamily
            onClicked: root.viewEvidence(modelData.connection)
          }
        }
        // Turn a claim into an action without a new privilege surface: the
        // timed destination rule the Apps view already offers, scoped to this
        // app and this address, through the same gates. Info rows do not
        // offer it; a hosting provider is context, not a reason to block.
        Flow {
          id: blockOffer
          width: parent.width
          spacing: Style.space(6 * root.ux.gap)
          visible: modelData.severity !== "info" && modelData.ip !== "" && modelData.live
          // Children resolve unqualified names against the component root,
          // not this Flow, so they reach the state through the id.
          readonly property var blockState: root.blockStateFor(modelData.connection)
          Text {
            height: Style.space(28)
            verticalAlignment: Text.AlignVCenter
            text: blockOffer.blockState.canBlock ? "Block " + modelData.ip + " for" : (blockOffer.blockState.existingRule ? "Timed rule on " + blockOffer.blockState.existingRule.ip : blockOffer.blockState.reason)
            textFormat: Text.PlainText
            color: Qt.darker(root.foreground, 1.3)
            font.family: root.fontFamily
            font.pixelSize: root.ux.caption
          }
          Repeater {
            model: blockOffer.blockState.canBlock ? Intel.BLOCK_DURATIONS : []
            Button {
              fontSize: root.ux.body
              required property var modelData
              text: modelData.label
              bordered: true
              foreground: root.foreground
              fontFamily: root.fontFamily
              onClicked: root.blockDestination(indicatorRow.modelData.connection, modelData.seconds)
            }
          }
          Button {
            fontSize: root.ux.body
            visible: blockOffer.blockState.existingRule !== null
            text: "Cancel rule"
            foreground: root.foreground
            fontFamily: root.fontFamily
            enabled: root.service && root.service.helperInstalled && !root.service.helperBusy
            onClicked: if (blockOffer.blockState.existingRule) root.service.cancelDestinationBlock(blockOffer.blockState.existingRule.app, blockOffer.blockState.existingRule.ip)
          }
        }
        Text {
          width: parent.width
          visible: root.service && root.service.lastBlockError ? true : false
          text: root.service && root.service.lastBlockError ? String(root.service.lastBlockError) : ""
          textFormat: Text.PlainText
          color: root.badColor
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
      }
    }
  }

  // Heatmap: one row per app, one column per bucket, one hue light-to-dark for
  // magnitude. Labels are text in the panel's ink, never the series colour; a
  // hover tooltip names the cell; the table view is `kub0 intel --timeline`.
  Item {
    id: timelinePane
    objectName: "intelTimeline"
    anchors.top: controls.bottom
    anchors.topMargin: Style.space(8 * root.ux.gap)
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    visible: root.section === "timeline"
    readonly property int labelWidth: Style.space(110)
    readonly property int rowHeight: Style.space(22)
    readonly property int axisHeight: Style.space(18)
    readonly property int gridWidth: Math.max(0, width - labelWidth - Style.space(8))
    readonly property int gridHeight: root.timelineRows.length * rowHeight
    clip: true
    // The pane is as tall as the panel leaves it, and ten app rows, the axis and
    // the hint are taller than that on a laptop screen: unclipped, the axis and
    // hint drew past the panel's bottom edge onto whatever was beneath (seen
    // live 10-13). Clip, and scroll when the content does not fit.
    Flickable {
      id: timelineFlick
      objectName: "intelTimelineFlick"
      anchors.fill: parent
      contentWidth: width
      contentHeight: timelineContent.height
      boundsBehavior: Flickable.StopAtBounds
      WheelStep { flick: timelineFlick; speed: root.scrollSpeed; momentum: root.scrollMomentum }
      Item {
        id: timelineContent
        width: timelineFlick.width
        height: timelinePane.gridHeight + timelinePane.axisHeight + Style.space(4) + timelineHint.implicitHeight
        Column {
          id: timelineLabelsCol
          width: timelinePane.labelWidth
          anchors.top: parent.top
          anchors.left: parent.left
          Repeater {
            model: root.timelineRows
            delegate: Item {
              required property var modelData
              width: timelinePane.labelWidth
              height: timelinePane.rowHeight
              Text {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.verticalCenter: parent.verticalCenter
                text: modelData.label + "  " + modelData.total
                textFormat: Text.PlainText
                color: root.foreground
                font.family: root.fontFamily
                font.pixelSize: root.ux.caption
                elide: Text.ElideRight
              }
              MouseArea {
                anchors.fill: parent
                enabled: modelData.id !== ""
                cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                onClicked: root.investigate("app:" + modelData.id, null)
              }
            }
          }
        }
        Canvas {
          id: heat
          anchors.top: parent.top
          anchors.left: timelineLabelsCol.right
          anchors.leftMargin: Style.space(8)
          width: timelinePane.gridWidth
          height: timelinePane.gridHeight
          property var rows: root.timelineRows
          property int buckets: root.timelineBuckets
          onRowsChanged: requestPaint()
          onBucketsChanged: requestPaint()
          onWidthChanged: requestPaint()
          onPaint: {
            var ctx = getContext("2d")
            ctx.reset()
            if (!rows.length || !buckets) return
            var cw = width / buckets
            var rh = timelinePane.rowHeight
            var a = root.accent
            var fg = root.foreground
            for (var r = 0; r < rows.length; r++) {
              for (var c = 0; c < buckets; c++) {
                var cell = rows[r].cells[c]
                var shade = cell ? cell.shade : 0
                // Empty cells keep a faint outline so the grid reads as a grid;
                // filled cells are the accent at 0.15..1.0 alpha. Two-pixel gaps.
                ctx.fillStyle = shade > 0
                  ? Qt.rgba(a.r, a.g, a.b, 0.15 + 0.85 * shade)
                  : Qt.rgba(fg.r, fg.g, fg.b, 0.06)
                ctx.fillRect(c * cw + 1, r * rh + 1, Math.max(1, cw - 2), Math.max(1, rh - 2))
              }
            }
          }
          MouseArea {
            anchors.fill: parent
            hoverEnabled: true
            onPositionChanged: function(mouse) {
              var cell = Intel.timelineCellAt(heat.rows, heat.buckets, mouse.x, mouse.y, heat.width, heat.height)
              root.timelineHover = Intel.timelineHoverText(root.timeline, heat.rows, cell)
            }
            onExited: root.timelineHover = ""
          }
        }
        Item {
          objectName: "intelTimelineAxis"
          anchors.top: heat.bottom
          anchors.left: heat.left
          width: heat.width
          height: timelinePane.axisHeight
          Repeater {
            model: root.timelineLabels
            delegate: Text {
              required property var modelData
              // A label starts at its bucket, but the last one (bucket 24 of
              // 25) would run past the grid, where the pane now clips it:
              // pull it back so it ends at the grid's edge.
              x: heat.buckets ? Math.max(0, Math.min(modelData.index * (heat.width / heat.buckets), heat.width - implicitWidth)) : 0
              anchors.verticalCenter: parent.verticalCenter
              text: modelData.label
              textFormat: Text.PlainText
              color: Qt.darker(root.foreground, 1.5)
              font.family: root.fontFamily
              font.pixelSize: root.ux.caption
            }
          }
        }
        Text {
          id: timelineHint
          anchors.top: heat.bottom
          anchors.topMargin: timelinePane.axisHeight + Style.space(4)
          anchors.left: parent.left
          anchors.right: parent.right
          text: root.timelineHover || (root.timelineRows.length ? "Hover a cell for the hour's count; click an app to investigate it." : "")
          textFormat: Text.PlainText
          color: Qt.darker(root.foreground, 1.3)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
      }
    }
  }

  ListView {
    id: exposureList
    objectName: "intelExposureList"
    anchors.top: controls.bottom
    anchors.topMargin: Style.space(8 * root.ux.gap)
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    visible: root.section === "exposure"
    clip: true
    WheelStep { flick: exposureList; speed: root.scrollSpeed; momentum: root.scrollMomentum }
    spacing: Style.space(6 * root.ux.gap)
    model: root.listeners
    delegate: Rectangle {
      required property var modelData
      width: exposureList.width
      height: lbody.implicitHeight + Style.space(18 * root.ux.gap)
      radius: Style.cornerRadius
      color: "transparent"
      border.color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
      Column {
        id: lbody
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: Style.space(9 * root.ux.gap)
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(4 * root.ux.gap)
        Row {
          width: parent.width
          spacing: Style.space(8 * root.ux.gap)
          Rectangle {
            width: Style.space(8)
            height: Style.space(8)
            radius: width / 2
            anchors.verticalCenter: parent.verticalCenter
            color: modelData.exposed ? root.warnColor : Qt.darker(root.foreground, 1.6)
          }
          Text {
            width: parent.width - Style.space(16)
            text: modelData.proto.toUpperCase() + " " + modelData.port + " · " + modelData.appName + " · " + modelData.scopeLabel
            textFormat: Text.PlainText
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: root.ux.bodySmall
            font.bold: true
            elide: Text.ElideRight
          }
        }
        Text {
          width: parent.width
          text: [modelData.ip, modelData.pid ? "PID " + modelData.pid : "", typeof modelData.uid === "number" ? "UID " + modelData.uid : "", modelData.exe].filter(function(s) { return s }).join(" · ")
          textFormat: Text.PlainText
          color: Qt.darker(root.foreground, 1.3)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          elide: Text.ElideMiddle
        }
      }
    }
  }

  ListView {
    id: watchList
    objectName: "intelWatchList"
    anchors.top: controls.bottom
    anchors.topMargin: Style.space(8 * root.ux.gap)
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    visible: root.section === "watch"
    clip: true
    WheelStep { flick: watchList; speed: root.scrollSpeed; momentum: root.scrollMomentum }
    spacing: Style.space(6 * root.ux.gap)
    model: root.watchRules
    delegate: Rectangle {
      required property var modelData
      width: watchList.width
      height: wbody.implicitHeight + Style.space(18 * root.ux.gap)
      radius: Style.cornerRadius
      color: "transparent"
      border.color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
      Row {
        id: wbody
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: Style.space(9 * root.ux.gap)
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(8 * root.ux.gap)
        Column {
          width: parent.width - removeButton.width - Style.space(8)
          spacing: Style.space(4 * root.ux.gap)
          Text {
            width: parent.width
            text: modelData.title
            textFormat: Text.PlainText
            color: root.foreground
            font.family: root.fontFamily
            font.pixelSize: root.ux.bodySmall
            font.bold: true
            elide: Text.ElideRight
          }
          Text {
            width: parent.width
            text: modelData.detail
            textFormat: Text.PlainText
            color: Qt.darker(root.foreground, 1.3)
            font.family: root.fontFamily
            font.pixelSize: root.ux.caption
            wrapMode: Text.WordWrap
          }
        }
        Button {
          fontSize: root.ux.body
          id: removeButton
          text: "Remove"
          anchors.verticalCenter: parent.verticalCenter
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: if (root.service && root.service.deleteWatch) root.service.deleteWatch(modelData.id)
        }
      }
    }
  }

  // ------------------------------------------------------------ pivot drawer
  Rectangle {
    id: drawer
    objectName: "intelDrawer"
    anchors.fill: parent
    visible: root.drawerOpen
    z: 5
    color: Commons.Color.popups.background
    MouseArea { anchors.fill: parent; onWheel: function(wheel) { wheel.accepted = true } }
    Column {
      id: drawerHead
      width: parent.width
      spacing: Style.space(6 * root.ux.gap)
      Row {
        width: parent.width
        spacing: Style.space(8 * root.ux.gap)
        Text {
          width: Math.max(0, parent.width - drawerClose.width - Style.space(8))
          text: "Investigate · " + root.pivotSubject
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: root.ux.body
          font.bold: true
          elide: Text.ElideRight
        }
        Button { id: drawerClose; text: "Close"; fontSize: root.ux.body; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.closeDrawer() }
      }
      Text {
        width: parent.width
        text: root.pivotBusy ? "Reading retained history…"
          : root.pivotError ? root.pivotError
          : "Retained local observations for the last 7 days plus live rows. Counts are sampled connections; first/last are sampling times."
        textFormat: Text.PlainText
        color: root.pivotError && !root.pivotBusy ? root.badColor : Qt.darker(root.foreground, 1.4)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
        wrapMode: Text.WordWrap
      }
      Canvas {
        id: pivotTimeline
        width: parent.width
        height: Style.space(36)
        visible: bars.length > 0
        property var bars: Intel.timelineBars(root.pivot)
        onBarsChanged: requestPaint()
        onWidthChanged: requestPaint()
        onPaint: {
          var ctx = getContext("2d")
          ctx.reset()
          if (!bars.length) return
          var w = width / bars.length
          ctx.fillStyle = Qt.rgba(root.accent.r, root.accent.g, root.accent.b, 0.85)
          for (var i = 0; i < bars.length; i++) {
            var h = Math.max(1, bars[i] * (height - 2))
            ctx.fillRect(i * w + 0.5, height - h, Math.max(1, w - 1), h)
          }
        }
      }
      Flow {
        width: parent.width
        spacing: Style.space(6 * root.ux.gap)
        Button {
          fontSize: root.ux.body
          text: "Watch this"
          visible: !root.pivotBusy && root.pivotSubject !== "" && root.pivotSubject.indexOf("app:") !== 0
          bordered: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.watchSubject()
        }
        Button {
          fontSize: root.ux.body
          text: "Evidence"
          visible: root.drawerConnection !== null
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.viewEvidence(root.drawerConnection)
        }
      }
    }
    ListView {
      id: pivotList
      objectName: "intelPivotList"
      anchors.top: drawerHead.bottom
      anchors.topMargin: Style.space(8 * root.ux.gap)
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.bottom: parent.bottom
      clip: true
      WheelStep { flick: pivotList; speed: root.scrollSpeed; momentum: root.scrollMomentum }
      spacing: Style.space(8 * root.ux.gap)
      model: {
        if (root.pivotBusy || !root.pivot) return []
        var facts = Intel.pivotFacts(root.pivot, Date.now(), root.ux)
        var line = Kub0.prevalenceText(root.kub0, root.drawerConnection ? root.drawerConnection.networkKey : "")
        if (line) facts.push({ label: "Org prevalence", value: line })
        return facts
      }
      delegate: Column {
        required property var modelData
        width: ListView.view.width
        Text { width: parent.width; text: modelData.label; textFormat: Text.PlainText; color: root.foreground; font.family: root.fontFamily; font.pixelSize: root.ux.caption; font.bold: true }
        Text { width: parent.width; text: modelData.value; textFormat: Text.PlainText; wrapMode: Text.WrapAnywhere; color: Qt.darker(root.foreground, 1.3); font.family: root.fontFamily; font.pixelSize: root.ux.bodySmall }
        PanelSeparator { width: parent.width }
      }
    }
  }
}
