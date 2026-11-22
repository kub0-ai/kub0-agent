import QtQuick
import qs.Commons

// Offscreen stand-in for the shell's Ui/KeyboardPanel.qml. The real one is a
// PanelWindow, and the offscreen platform has no layer-shell backend ("No
// PanelWindow backend loaded"), so Panel.qml could not load in the runtime
// harness at all. Same properties and functions Panel.qml uses; the content
// is laid out in a plain Item so the panel's own logic runs unchanged.
Item {
  id: root

  required property Item anchorItem
  required property QtObject bar
  property var owner: null
  property int margin: 0
  property int padding: 0
  property int contentWidth: 280
  property int contentHeight: 200
  property bool centerOnBar: false
  property bool open: false
  property int gap: 0
  property bool popoutSwitching: false
  property bool popoutSwitchClosing: false
  property bool focusPrimed: false
  property Item focusTarget: null
  default property alias contentItem: contentHolder.children

  width: contentWidth
  height: contentHeight
  visible: open

  function close() { open = false }
  function beginFocusPrime() { focusPrimed = true }
  function fittedContentWidth(width, cap) { return cap ? Math.min(width, cap) : width }
  function fittedContentHeight(implicitHeight, cap) { return cap ? Math.min(implicitHeight, cap) : implicitHeight }
  function cappedContentHeight(height) { return height }

  Item {
    id: contentHolder
    anchors.fill: parent
  }
}
