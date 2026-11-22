pragma Singleton
import QtQuick
QtObject {
  property int cornerRadius: 6
  property QtObject font: QtObject {
    property string family: "sans-serif"
    property int display: 22
    property int subtitle: 15
    property int body: 13
    property int bodySmall: 12
    property int caption: 11
  }
  function space(n) { return n }
  function selectedFillFor(fg, accent) { return Qt.rgba(accent.r, accent.g, accent.b, 0.25) }
  function hoverFillFor(fg, accent) { return Qt.rgba(fg.r, fg.g, fg.b, 0.08) }
}
