import QtQuick
Rectangle {
  id: root
  property string text: ""
  property string iconText: ""
  property string tooltipText: ""
  property bool selected: false
  property bool bordered: false
  property bool focusable: false
  property color foreground: "#e6e6e6"
  property string fontFamily: "sans-serif"
  // The kit's Button takes its text size here (Ui/Button.qml: fontSize).
  property real fontSize: 12
  signal clicked()
  implicitWidth: label.implicitWidth + 14
  implicitHeight: label.implicitHeight + 8
  color: selected ? Qt.rgba(foreground.r, foreground.g, foreground.b, 0.15) : "transparent"
  border.width: bordered ? 1 : 0
  border.color: foreground
  radius: 4
  Text { id: label; anchors.centerIn: parent; text: root.text; color: root.foreground; font.family: root.fontFamily; font.pixelSize: root.fontSize }
  MouseArea { anchors.fill: parent; onClicked: root.clicked() }
}
