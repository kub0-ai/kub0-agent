import QtQuick
import QtQuick.Window

// Panel.qml names an unknown peer in a text field on the selected app row.
// That field used to sit inside the Repeater of peers, whose model is rebuilt
// from the row on every sample (connPeers(row.appData)). Qt 6.11 keeps the
// delegates when the new array is equal item for item, but a Repeater does not
// diff anything finer: the moment any peer's details move -- a connection
// count, a new peer, a name arriving -- every delegate is destroyed and
// recreated. On a busy app that is most samples. The field died with them,
// focus fell out of it mid-word, and the next letters reached the panel's
// one-key shortcuts -- where `b` blocks the selected app.
//
// This mirrors that shape: one ListModel row synced in place with
// setProperty, as syncRows does, carrying both placements. It asserts the
// failure of the old one so the test cannot pass for the wrong reason, and
// the survival of the new one.
Window {
  id: probe
  width: 400
  height: 400
  visible: true

  property int fail: 0
  function check(name, cond, detail) {
    console.warn((cond ? "  ok   " : "  FAIL ") + name + (detail ? "  [" + detail + "]" : ""))
    if (!cond) probe.fail++
  }

  property int insideCreated: 0
  property var besideField: null

  function peers(app) {
    var out = []
    for (var i = 0; i < app.connections.length; i++)
      out.push({ networkKey: app.connections[i], count: app.tick + 1 })
    return out
  }

  function sample(n) {
    // A fresh object every time, as rowFor() builds, with a connection count
    // that moves, as a live app's does.
    return { id: "firefox", connections: ["a", "b"], tick: n }
  }

  ListModel { id: appModel; dynamicRoles: true }

  ListView {
    anchors.fill: parent
    model: appModel
    delegate: Column {
      id: row
      required property var model
      readonly property var appData: row.model.app
      width: 400

      Repeater {
        model: probe.peers(row.appData)
        delegate: TextInput {
          width: 200
          height: 20
          Component.onCompleted: probe.insideCreated++
        }
      }
      TextInput {
        id: beside
        width: 200
        height: 20
        Component.onCompleted: probe.besideField = beside
      }
    }
  }

  Timer {
    id: stepper
    interval: 100
    running: true
    property int step: 0
    onTriggered: {
      switch (step) {
      case 0:
        appModel.append({ app: probe.sample(0) })
        break
      case 1:
        probe.check("one delegate per peer to start", probe.insideCreated === 2,
                    "created " + probe.insideCreated)
        probe.besideField.forceActiveFocus()
        probe.besideField.text = "back"
        var before = probe.besideField
        for (var n = 1; n <= 3; n++)
          appModel.setProperty(0, "app", probe.sample(n))
        probe.check("the old placement is rebuilt by every sample that moves a count",
                    probe.insideCreated === 2 + 3 * 2, "created " + probe.insideCreated)
        probe.check("the new placement is the same field after three samples",
                    probe.besideField === before)
        probe.check("...and it still has focus", probe.besideField.activeFocus === true)
        probe.check("...and still holds what was typed", probe.besideField.text === "back",
                    probe.besideField.text)
        console.warn(probe.fail === 0 ? "PROBE PASS" : "PROBE FAIL (" + probe.fail + ")")
        Qt.exit(probe.fail === 0 ? 0 : 1)
        break
      }
      step++
      if (step < 3)
        restart()
    }
  }
}
