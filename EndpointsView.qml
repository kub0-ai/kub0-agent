import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "js/Ux.js" as Ux
import "js/Endpoints.js" as Endpoints

Item {
  id: root
  objectName: "endpointsView"
  property var account: ({})
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property string fontFamily: Style.font.family
  // Font sizes and the gap multiplier: the textSize and density preferences,
  // handed down by the panel (js/Ux.js). Alone, a view uses the kit's sizes.
  property var ux: Ux.metrics(Style.font, "normal", "normal", "mixed", "binary")
  // The scrollSpeed and scrollMomentum preferences, handed down by the panel.
  property string scrollSpeed: "normal"
  property bool scrollMomentum: true
  property string query: ""
  property string stateFilter: ""
  property string selectedName: ""
  property double now: Date.now()
  property bool clockReady: false
  readonly property bool searchFocused: search.activeFocus
  readonly property var endpoints: account.connected === true && account.endpoints ? account.endpoints : []
  readonly property var rows: Endpoints.filtered(endpoints, query, stateFilter, now)
  readonly property var selected: rows.find(function(row) { return row.nodeName === root.selectedName }) || null

  function focusSearch() { search.forceActiveFocus() }
  function toggleState(value) { stateFilter = Endpoints.toggle(stateFilter, value) }
  function toggleEndpoint(value) { selectedName = Endpoints.toggle(selectedName, value) }
  onRowsChanged: if (!rows.some(function(row) { return row.nodeName === root.selectedName })) selectedName = ""
  function scheduleClock() {
    if (!clockReady) return
    viewClock.stop()
    if (!visible) return
    viewClock.interval = Endpoints.nextTransitionDelay(endpoints, now)
    viewClock.start()
  }
  onNowChanged: scheduleClock()
  onEndpointsChanged: {
    now = Date.now()
    scheduleClock()
  }
  // QML Timer wakes on animation frames (typically about 16 ms), so a deadline
  // updates on the next available frame, not with a real-time millisecond guarantee.
  Timer {
    id: viewClock
    repeat: false
    onTriggered: {
      root.now = Date.now()
      root.scheduleClock()
    }
  }
  onVisibleChanged: {
    if (visible) now = Date.now()
    scheduleClock()
  }
  Component.onCompleted: {
    clockReady = true
    scheduleClock()
  }

  Column {
    id: controls
    width: parent.width
    spacing: Style.space(8 * root.ux.gap)
    Text {
      width: parent.width
      text: "Tenant endpoints"
      color: root.foreground
      font.family: root.fontFamily
      font.pixelSize: root.ux.body
      font.bold: true
    }
    Text {
      objectName: "endpointInventoryStatus"
      width: parent.width
      text: Endpoints.inventoryStatus(root.account, root.endpoints, root.now, root.ux)
      color: Qt.darker(root.foreground, 1.3)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }
    Rectangle {
      width: parent.width
      height: Style.space(38)
      visible: root.account.connected === true
      color: "transparent"
      border.color: search.activeFocus ? root.accent : Qt.darker(root.foreground, 2)
      radius: Style.cornerRadius
      TextInput {
        id: search
        objectName: "endpointSearch"
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
        text: "Search hostname, version, architecture, or kernel"
        color: Qt.darker(root.foreground, 1.6)
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
      }
    }
    Flow {
      width: parent.width
      visible: root.account.connected === true
      spacing: Style.space(6 * root.ux.gap)
      Repeater {
        model: [{value: "online", label: "Online"}, {value: "offline", label: "Offline"}, {value: "enforcing", label: "Enforcing"}, {value: "monitoring", label: "Monitoring"}]
        Button {
          fontSize: root.ux.body
          required property var modelData
          text: modelData.label
          objectName: "endpointFilter_" + modelData.value
          selected: root.stateFilter === modelData.value
          bordered: true
          focusable: true
          foreground: root.foreground
          fontFamily: root.fontFamily
          onClicked: root.toggleState(modelData.value)
        }
      }
    }
    Text {
      width: parent.width
      visible: root.account.connected === true && Endpoints.age(root.account.endpointsUpdatedAt, root.now) !== null
      text: root.rows.length === 0 ? "No kub0 endpoints match." : root.rows.length + " shown · offline devices stay in your inventory."
      color: Qt.darker(root.foreground, 1.4)
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      wrapMode: Text.WordWrap
    }
  }
  ListView {
    id: list
    objectName: "endpointList"
    anchors.top: controls.bottom
    anchors.topMargin: Style.space(8 * root.ux.gap)
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    clip: true
    WheelStep { flick: list; speed: root.scrollSpeed; momentum: root.scrollMomentum }
    spacing: Style.space(6 * root.ux.gap)
    model: root.rows
    delegate: Rectangle {
      required property var modelData
      objectName: "endpointRow_" + modelData.nodeName
      activeFocusOnTab: true
      Keys.onReturnPressed: root.toggleEndpoint(modelData.nodeName)
      Keys.onSpacePressed: root.toggleEndpoint(modelData.nodeName)
      width: list.width
      height: row.implicitHeight + Style.space(18 * root.ux.gap)
      radius: Style.cornerRadius
      color: root.selectedName === modelData.nodeName ? Style.selectedFillFor(root.foreground, root.accent) : "transparent"
      border.color: Qt.rgba(root.foreground.r, root.foreground.g, root.foreground.b, 0.15)
      Column {
        id: row
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.margins: Style.space(9 * root.ux.gap)
        anchors.verticalCenter: parent.verticalCenter
        spacing: Style.space(4 * root.ux.gap)
        Text {
          width: parent.width
          text: modelData.nodeName + (modelData.nodeName === root.account.nodeName ? " · this device" : "")
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: root.ux.bodySmall
          font.bold: true
          elide: Text.ElideRight
        }
        Text {
          width: parent.width
          text: Endpoints.label(modelData, root.now) + " · kub0 " + (modelData.agentVer || "version not reported")
          textFormat: Text.PlainText
          color: root.foreground
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
        Text {
          width: parent.width
          text: "Last seen " + Endpoints.time(modelData.lastSeen, root.ux, root.now) + " · " + Endpoints.ownerApps(modelData.blocksActive)
          textFormat: Text.PlainText
          color: Qt.darker(root.foreground, 1.3)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
        Text {
          width: parent.width
          visible: root.selectedName === modelData.nodeName
          text: "Architecture: " + (modelData.arch || "not reported") + "\nKernel: " + (modelData.kernelVersion || "not reported")
          textFormat: Text.PlainText
          color: Qt.darker(root.foreground, 1.3)
          font.family: root.fontFamily
          font.pixelSize: root.ux.caption
          wrapMode: Text.WordWrap
        }
      }
      MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: root.toggleEndpoint(modelData.nodeName)
      }
    }
  }
}
