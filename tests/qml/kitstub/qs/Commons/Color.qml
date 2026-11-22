pragma Singleton
import QtQuick
QtObject {
  property color foreground: "#e6e6e6"
  property color background: "#101418"
  property color accent: "#5aa0ff"
  property color urgent: "#ff5a5a"
  property QtObject popups: QtObject { property color background: "#181c22" }
}
