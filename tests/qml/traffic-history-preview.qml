import QtQuick
import QtQuick.Window
import Quickshell
import qs.Commons

Scope {
  id: harness
  property var view: null
  QtObject {
    id: fake
    property var historyEntries: []
    property bool historyMore: false
    property bool historyBusy: false
    property string historyError: ""
    property string lastQuery: ""
    function requestHistory(query, hours) {
      lastQuery = query
      var now = Date.now()
      var rows = [
        { key: "one", firstObserved: now - 180000, lastObserved: now - 120000, active: false,
          bytes: { tx: 65536, rx: 4194304 }, connection: { exe: "/usr/bin/browser", app: { name: "Browser", id: "/usr/bin/browser" },
          proto: "tcp", country: "DE", hostname: "probe.example", remote: { ip: "192.0.2.10", port: 443 } } },
        { key: "two", firstObserved: now - 90000, lastObserved: now - 60000, active: true,
          bytes: { tx: 1024, rx: 32768 }, connection: { exe: "/usr/bin/update-service", app: { name: "Update service", id: "/usr/bin/update-service" },
          proto: "tcp", country: "US", hostname: "updates.example", remote: { ip: "2001:db8::20", port: 443 } } },
        { key: "three", firstObserved: now - 30000, lastObserved: now - 15000, active: false,
          bytes: null, connection: { exe: "/usr/bin/resolver", app: { name: "Resolver", id: "/usr/bin/resolver" },
          proto: "udp", country: "", hostname: "", remote: { ip: "192.0.2.53", port: 53 } } }
      ]
      historyEntries = rows.filter(function(r) { return JSON.stringify(r).toLowerCase().indexOf(query.toLowerCase()) >= 0 })
    }
  }
  Window {
    id: window
    visible: true
    width: Number(Quickshell.env("VALLUM_PREVIEW_WIDTH")) || 560
    height: 740
    color: Color.background
    Item {
      id: surface
      anchors.fill: parent
      anchors.margins: 18
    }
  }
  function find(item, name) {
    if (item.objectName === name) return item
    for (var i = 0; i < item.children.length; i++) {
      var result = find(item.children[i], name)
      if (result) return result
    }
    return null
  }
  Timer {
    running: true
    interval: 100
    onTriggered: {
      var c = Qt.createComponent("file://" + Quickshell.env("VALLUM_CANDIDATE_DIR") + "/HistoryView.qml")
      if (c.status !== Component.Ready) { console.error("PREVIEW_FAILED", c.errorString()); Qt.quit(); return }
      harness.view = c.createObject(surface, { service: fake, width: surface.width, height: surface.height })
      if (!harness.view) { console.error("PREVIEW_FAILED", c.errorString()); Qt.quit(); return }
      render.start()
    }
  }
  Timer {
    id: render
    interval: 700
    onTriggered: {
      var list = harness.find(harness.view, "historyList")
      console.log("HISTORY_RENDER_COUNT", list ? list.count : -1)
      window.contentItem.grabToImage(function(result) {
        console.log("PREVIEW_SAVED", result.saveToFile(Quickshell.env("VALLUM_PREVIEW_FILE")))
        harness.find(harness.view, "historySearch").text = "probe.example"
        check.start()
      })
    }
  }
  Timer {
    id: check
    interval: 400
    onTriggered: {
      var list = harness.find(harness.view, "historyList")
      console.log("HISTORY_SEARCH", fake.lastQuery === "probe.example" && list.count === 1)
      var copy = harness.find(harness.view, "historyCopyButton")
      if (copy) copy.clicked()
      console.log("HISTORY_COPY", Quickshell.clipboardText.indexOf("probe.example") >= 0 && Quickshell.clipboardText.indexOf("updates.example") < 0)
      Qt.quit()
    }
  }
}
