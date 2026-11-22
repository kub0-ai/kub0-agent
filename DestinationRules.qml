import QtQuick
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "js/Ux.js" as Ux
import "js/Rules.js" as Rules
import "ConnectionModel.js" as ConnectionModel

Column {
  id: root
  property var app: null
  property var service: null
  property bool current: false
  property color foreground: Commons.Color.foreground
  property string fontFamily: Style.font.family
  // Font sizes and the gap multiplier: the textSize and density preferences,
  // handed down by the panel (js/Ux.js). Alone, a view uses the kit's sizes.
  property var ux: Ux.metrics(Style.font, "normal", "normal", "mixed", "binary")
  readonly property bool editing: target.popupOpen
  onVisibleChanged: if (!visible) target.close()
  readonly property var activeRules: {
    var tick = service ? service.healthTick : 0
    return Rules.forApp(service ? service.temporaryRules : [], ConnectionModel.helperId(app ? app.id : ""))
  }
  spacing: Style.space(4 * root.ux.gap)
  Text {
    width: parent.width
    visible: root.service && root.service.temporaryRulesError !== undefined && root.service.temporaryRulesError !== ""
    text: root.service ? String(root.service.temporaryRulesError || "") : ""
    wrapMode: Text.WordWrap
    color: root.foreground
    font.family: root.fontFamily
    font.pixelSize: root.ux.caption
  }
  Text {
    width: parent.width
    text: "Temporary destination rule"
    font.family: root.fontFamily
    font.pixelSize: root.ux.caption
    color: root.foreground
  }
  Repeater {
    model: root.activeRules
    Column {
      required property var modelData
      width: root.width
      Text {
        width: parent.width
        text: modelData.ip + (modelData.expiresAt > (root.service ? root.service.healthTick : Date.now()) ? " · expires " + (root.ux.time ? root.ux.time(modelData.expiresAt, Date.now()) : new Date(modelData.expiresAt).toLocaleTimeString()) : " · expired; cleanup pending")
        textFormat: Text.PlainText
        wrapMode: Text.WordWrap
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: root.ux.caption
      }
      Button {
        fontSize: root.ux.body
        text: "Cancel destination rule"
        foreground: root.foreground
        fontFamily: root.fontFamily
        enabled: root.service && root.service.helperInstalled && !root.service.helperBusy
        onClicked: root.service.cancelDestinationBlock(modelData.app, modelData.ip)
      }
    }
  }
  Text {
    width: parent.width
    visible: root.activeRules.length === 0
    text: "Select an IP and duration. Other destinations stay available. One timed rule per app."
    wrapMode: Text.WordWrap
    color: Qt.darker(root.foreground, 1.4)
    font.family: root.fontFamily
    font.pixelSize: root.ux.caption
  }
  Dropdown {
    id: target
    visible: root.activeRules.length === 0
    width: parent.width
    foreground: root.foreground
    fontFamily: root.fontFamily
    options: Rules.destinations(root.app).map(function(ip) {return {value:ip,label:ip}})
    value: options.length ? options[0].value : ""
    onChanged: function(v) {value=v}
  }
  Flow {
    width: parent.width
    visible: root.activeRules.length === 0
    spacing: Style.space(4 * root.ux.gap)
    Repeater {
      model: [{seconds:300,label:"Block 5 min"},{seconds:900,label:"15 min"},{seconds:3600,label:"1 hour"}]
      Button {
        fontSize: root.ux.body
        required property var modelData
        text: modelData.label
        foreground: root.foreground
        fontFamily: root.fontFamily
        enabled: root.current && target.value !== "" && root.service && root.service.blockingReady && !root.service.helperBusy && root.app && !root.app.blocked && !root.app.system && root.app.pids.length > 0
        onClicked: root.service.requestDestinationBlock(root.app.id, target.value, modelData.seconds)
      }
    }
  }
}
