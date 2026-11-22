import QtQuick
Rectangle {
  id: root
  property string label: ""
  property var value: ""
  property var options: []
  property bool popupOpen: false
  property color foreground: "#e6e6e6"
  property string fontFamily: "sans-serif"
  signal changed(var value)
  function close() { popupOpen = false }
  function currentLabel() {
    for (var i = 0; i < options.length; i++) if (options[i].value === value) return String(options[i].label)
    return String(value)
  }
  implicitHeight: 28
  color: "transparent"
  border.width: 1
  border.color: foreground
  Text { anchors.verticalCenter: parent.verticalCenter; x: 6; text: root.currentLabel(); color: root.foreground; font.family: root.fontFamily }
}
