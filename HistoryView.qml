import QtQuick
import Quickshell
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "js/Ux.js" as Ux
import "js/History.js" as History
import "js/Traffic.js" as Traffic
import "js/Intel.js" as Intel

Item {
  id: root
  property var service: null
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color badColor: Commons.Color.urgent
  property string fontFamily: Style.font.family
  // Font sizes and the gap multiplier: the textSize and density preferences,
  // handed down by the panel (js/Ux.js). Alone, a view uses the kit's sizes.
  property var ux: Ux.metrics(Style.font, "normal", "normal", "mixed", "binary")
  // The scrollSpeed and scrollMomentum preferences, handed down by the panel.
  property string scrollSpeed: "normal"
  property bool scrollMomentum: true
  property string query: ""
  property int hours: 24
  property string copyNote: ""
  signal viewEvidence(var connection)
  readonly property bool searchFocused: search.activeFocus
  readonly property var entries: service && service.historyEntries ? service.historyEntries : []
  readonly property bool busy: service && service.historyBusy === true
  readonly property string error: service && service.historyError ? service.historyError : ""

  function refresh() {
    copyNote = ""
    if (service && service.requestHistory) service.requestHistory(query, hours)
  }
  function focusSearch() { search.forceActiveFocus() }
  onVisibleChanged: if (visible) refresh()
  onServiceChanged: if (visible) refresh()
  onQueryChanged: debounce.restart()
  onHoursChanged: refresh()
  Timer { id: debounce; interval: 250; onTriggered: root.refresh() }

  Column {
    id: controls
    width: parent.width
    spacing: Style.space(8 * root.ux.gap)
    Text {
      width: parent.width
      text: "Connection history"
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: root.ux.body
      font.bold: true
    }
    Text {
      width: parent.width
      text: "Local observations · kept for 7 days, up to 10,000 connections. TCP transfer is measured between samples; UDP transfer is unknown."
      color: Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }
    Rectangle {
      width: parent.width
      height: Style.space(38)
      color: "transparent"
      border.color: search.activeFocus ? root.accent : Qt.darker(root.foreground, 2)
      radius: Style.cornerRadius
      TextInput {
        id: search
        objectName: "historySearch"
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
        text: "Search app, IP, hostname, country, or port"
        color: Qt.darker(root.foreground, 1.6)
        font.family: root.fontFamily
        font.pixelSize: root.ux.bodySmall
      }
    }
    Flow {
      width: parent.width
      spacing: Style.space(6 * root.ux.gap)
      Repeater {
        model: [{ hours: 1, label: "1 hour" }, { hours: 24, label: "24 hours" }, { hours: 168, label: "7 days" }]
        Button {
          fontSize: root.ux.body
          required property var modelData
          text: (root.hours === modelData.hours ? "✓ " : "") + modelData.label
          bordered: root.hours === modelData.hours
          focusable: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.hours = modelData.hours
        }
      }
      Button {
        fontSize: root.ux.body
        text: "Refresh"
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.refresh()
      }
    }
    Row {
      spacing: Style.space(6 * root.ux.gap)
      Button {
        fontSize: root.ux.body
        id: copyButton
        objectName: "historyCopyButton"
        text: "Copy shown as CSV"
        enabled: !root.busy && !root.error && root.entries.length > 0
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: {
          Quickshell.clipboardText = History.csv(root.entries)
          root.copyNote = "Copied " + root.entries.length + " observations"
        }
      }
      Text {
        width: Math.max(0, root.width - copyButton.width - Style.space(6))
        text: root.copyNote
        wrapMode: Text.WordWrap
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
      }
    }
    Text {
      width: parent.width
      objectName: "historyStatus"
      text: root.busy ? "Loading observations…" : root.error ? root.error
        : root.entries.length === 0 ? "No retained observations match."
        : root.entries.length + (root.entries.length === 1 ? " observation" : " observations") + (root.service && root.service.historyMore ? " · showing the latest 200 matches. Narrow your search to find older observations." : "")
      color: Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }
  }
  ListView {
    id: list
    objectName: "historyList"
    anchors.top: controls.bottom
    anchors.topMargin: Style.space(8 * root.ux.gap)
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    clip: true
    WheelStep { flick: list; speed: root.scrollSpeed; momentum: root.scrollMomentum }
    spacing: Style.space(6 * root.ux.gap)
    model: root.entries
    delegate: Column {
      required property var modelData
      readonly property var conn: modelData.connection
      width: list.width
      spacing: Style.space(3 * root.ux.gap)
      Text {
        width: parent.width
        text: conn.app.name + " → " + History.endpoint(conn)
        textFormat: Text.PlainText
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: root.ux.bodySmall
        elide: Text.ElideRight
      }
      Text {
        width: parent.width
        text: [conn.proto.toUpperCase(), conn.country, conn.hostname, conn.state.indexOf("-attempt") >= 0 ? "attempt recorded · outcome unknown" : (modelData.active ? "observed in latest sample" : "no longer observed")].filter(function(s) { return s }).join(" · ")
        textFormat: Text.PlainText
        color: Qt.darker(root.foreground, 1.3)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
        wrapMode: Text.WordWrap
      }
      Text {
        width: parent.width
        text: "First observed " + History.time(modelData.firstObserved, root.ux, Date.now()) + "\nLast observed " + History.time(modelData.lastObserved, root.ux, Date.now())
        color: Qt.darker(root.foreground, 1.5)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
        wrapMode: Text.WordWrap
      }
      Text {
        width: parent.width
        visible: conn.indicators && conn.indicators.length > 0
        text: conn.indicators && conn.indicators.length
          ? conn.indicators.map(function(i) { return Intel.severityLabel(i.severity) + " · " + Intel.indicatorLabel(i.id) }).join(" · ")
          : ""
        textFormat: Text.PlainText
        color: conn.indicators && conn.indicators.some(function(i) { return i.severity === "warning" }) ? root.badColor : root.foreground
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
        wrapMode: Text.WordWrap
      }
      Text {
        width: parent.width
        text: modelData.bytes ? "Sampled transfer ↑ " + Traffic.bytes(modelData.bytes.tx, root.ux) + " ↓ " + Traffic.bytes(modelData.bytes.rx, root.ux) : "Transfer unknown"
        color: Qt.darker(root.foreground, 1.5)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
      }
      Text {
        width: parent.width
        text: conn.exe || conn.app.id
        textFormat: Text.PlainText
        color: Qt.darker(root.foreground, 1.6)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
        elide: Text.ElideMiddle
      }
      PanelSeparator { width: parent.width }
      Button {
        fontSize: root.ux.body
        text: "Connection evidence"
        foreground: root.foreground
        fontFamily: root.fontFamily
        onClicked: root.viewEvidence(conn)
      }
    }
  }
}
