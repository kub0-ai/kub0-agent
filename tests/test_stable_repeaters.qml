import QtQuick
import QtQuick.Window

// Panel.qml feeds several Repeaters from functions that return a fresh array
// of row objects (Top destinations, the Settings fact lists). A Repeater does
// not diff objects: when any value moves -- a connection count, a heartbeat
// age -- every delegate is destroyed and rebuilt, and a click whose press and
// release straddle that lands on a MouseArea that is gone.
//
// The panel now gives those Repeaters a model that only changes when the ROWS
// change (a count, or a list of stable keys) and binds each row's values
// separately. This asserts the old shape rebuilds and the new one does not,
// while its values still update.
Window {
  id: probe
  width: 300
  height: 300
  visible: true

  property int fail: 0
  function check(name, cond, detail) {
    console.warn((cond ? "  ok   " : "  FAIL ") + name + (detail ? "  [" + detail + "]" : ""))
    if (!cond) probe.fail++
  }

  property int tick: 0
  function facts() {
    return [{ label: "Heartbeat", value: tick + "s ago" }, { label: "Node", value: "box" }]
  }
  readonly property var factRows: facts()

  property int oldCreated: 0
  property int newCreated: 0
  property var firstNewRow: null

  Column {
    Repeater {
      model: probe.facts()
      delegate: Text {
        required property var modelData
        text: modelData.value
        Component.onCompleted: probe.oldCreated++
      }
    }
    Repeater {
      model: probe.factRows.length
      delegate: Text {
        required property int index
        readonly property var fact: probe.factRows[index] || ({})
        text: fact.value || ""
        Component.onCompleted: {
          probe.newCreated++
          if (index === 0 && !probe.firstNewRow)
            probe.firstNewRow = this
        }
      }
    }
  }

  Timer {
    interval: 50
    running: true
    onTriggered: {
      var row = probe.firstNewRow
      for (var i = 1; i <= 3; i++)
        probe.tick = i
      probe.check("the old shape rebuilds on every value change", probe.oldCreated === 2 + 3 * 2,
                  "created " + probe.oldCreated)
      probe.check("the new shape keeps its rows", probe.newCreated === 2, "created " + probe.newCreated)
      probe.check("...the same row object", probe.firstNewRow === row)
      probe.check("...whose value still updates", row.text === "3s ago", row.text)
      console.warn(probe.fail === 0 ? "PROBE PASS" : "PROBE FAIL (" + probe.fail + ")")
      Qt.exit(probe.fail === 0 ? 0 : 1)
    }
  }
}
