import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "js/Ux.js" as Ux
import "js/Evidence.js" as Evidence

Item {
  id: root
  property var app: null
  property color foreground: Commons.Color.foreground
  property string fontFamily: Style.font.family
  // Font sizes and the gap multiplier: the textSize and density preferences,
  // handed down by the panel (js/Ux.js). Alone, a view uses the kit's sizes.
  property var ux: Ux.metrics(Style.font, "normal", "normal", "mixed", "binary")
  // The scrollSpeed and scrollMomentum preferences, handed down by the panel.
  property string scrollSpeed: "normal"
  property bool scrollMomentum: true
  signal closed()
  readonly property var connections: app && app.connections ? app.connections : []
  readonly property var connection: connections.filter(function(c) {return c.id === picker.value})[0] || connections[0] || null
  onVisibleChanged: {if (visible) forceActiveFocus(); else picker.close()}
  Keys.onEscapePressed: closed()
  Rectangle {anchors.fill: parent; color: Commons.Color.popups.background}
  MouseArea {anchors.fill: parent; onWheel: function(wheel) {wheel.accepted=true}}
  Column {
    id: header
    width: parent.width
    spacing: Style.space(6 * root.ux.gap)
    Row {
      width: parent.width
      spacing: Style.space(8 * root.ux.gap)
      Text {
        width: Math.max(0,parent.width-closeButton.width-Style.space(8))
        text: "Connection evidence · " + (root.app ? root.app.name : "")
        textFormat: Text.PlainText
        font.family: root.fontFamily
        font.pixelSize: root.ux.body
        font.bold: true
        color: root.foreground
        elide: Text.ElideRight
      }
      Button {id: closeButton; text: "Close"; fontSize: root.ux.body; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.closed()}
    }
    Dropdown {
      id: picker
      width: parent.width
      foreground: root.foreground
      fontFamily: root.fontFamily
      options: root.connections.map(function(c) {return {value:c.id,label:String(c.proto).toUpperCase() + " " + Evidence.endpoint(c.remote)}})
      value: options.length ? options[0].value : ""
      onChanged: function(v) {value=v}
    }
    Text {
      width: parent.width
      text: "Source record at the time you opened this drawer. Inferences and annotations do not establish which firewall rule enforced a connection."
      wrapMode: Text.WordWrap
      font.family: root.fontFamily
      font.pixelSize: root.ux.caption
      color: Qt.darker(root.foreground,1.4)
    }
  }
  ListView {
    id: evidenceList
    objectName: "evidenceList"
    anchors.top: header.bottom
    anchors.topMargin: Style.space(8 * root.ux.gap)
    anchors.left: parent.left
    anchors.right: parent.right
    anchors.bottom: parent.bottom
    clip: true
    WheelStep { flick: evidenceList; speed: root.scrollSpeed; momentum: root.scrollMomentum }
    spacing: Style.space(8 * root.ux.gap)
    model: Evidence.describe(root.connection, root.ux, Date.now())
    delegate: Column {
      required property var modelData
      width: ListView.view.width
      Text {width:parent.width; text:modelData.label; textFormat:Text.PlainText; color:root.foreground; font.family:root.fontFamily; font.pixelSize:root.ux.caption; font.bold:true}
      Text {width:parent.width; text:modelData.value; textFormat:Text.PlainText; wrapMode:Text.WrapAnywhere; color:Qt.darker(root.foreground,1.3); font.family:root.fontFamily; font.pixelSize:root.ux.bodySmall}
      PanelSeparator {width:parent.width}
    }
  }
}
