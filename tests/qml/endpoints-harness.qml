import QtQuick
import QtQuick.Window
import Quickshell

Scope {
  id: harness
  property var view: null
  property int step: 0
  property bool finished: false
  property double expiryDeadline: 0
  property bool observedOnline: false
  property string preDeadlineRowText: ""
  property double clock: Date.parse("2026-10-04T01:00:00Z")
  property var fixtureRows: [
    {nodeName:"fixture-online", state:"enforcing", lastSeen:"2026-10-04T00:59:00Z", blocksActive:0, agentVer:"0.2.0", arch:"x86_64", kernelVersion:"Linux 6.12"},
    {nodeName:"fixture-offline", state:"down", lastSeen:"", blocksActive:null}
  ]
  Window { visible: true; width: 640; height: 740; Item { id: surface; anchors.fill: parent } }
  function texts(item) {
    var out = []
    if (item.visible && item.text !== undefined) out.push(String(item.text))
    if (!item.visible) return out
    for (var i = 0; i < item.children.length; i++) out = out.concat(texts(item.children[i]))
    return out
  }
  function check(ok, message) { if (!ok) throw new Error(message) }
  function observedEndpointState() {
    check(view.rows.length === 1 && view.rows[0].nodeName === "near-expiry", "unexpected expiry fixture rows")
    // Only the single fixture row has a kub0 status label; filter buttons do not.
    var labels = texts(view).filter(function(text) {
      return text.indexOf("Online · monitoring · kub0 ") === 0
        || text.indexOf("Offline · kub0 ") === 0
    })
    check(labels.length === 1, "missing or ambiguous near-expiry row status")
    return {offline:labels[0].indexOf("Offline · kub0 ") === 0, text:labels[0]}
  }
  function account(rows, timestamp, success, connected) {
    return {connected:connected !== false, endpoints:rows, endpointsUpdatedAt:timestamp, endpointsRefreshOk:success}
  }
  function finish(result) {
    if (finished) return
    endpointProbe.stop()
    finished = true
    console.log("ENDPOINT_NATIVE_RESULT " + JSON.stringify(result))
    Qt.quit()
  }
  Component.onCompleted: {
    try {
      var component = Qt.createComponent("file://" + Quickshell.env("VALLUM_CANDIDATE_DIR") + "/EndpointsView.qml")
      check(component.status === Component.Ready, component.errorString())
      view = component.createObject(surface, {width:640, height:740, now:clock, account:account(fixtureRows, clock - 60000, true)})
      check(view !== null, "view creation failed")
      view.now = clock // deterministic date/count checks only
    } catch (error) { finish({ok:false, error:String(error)}) }
  }
  Timer {
    id: endpointProbe
    interval: 150; running: !harness.finished; repeat: true
    onTriggered: {
      try {
        var visibleText = texts(view).join("\n")
        if (step === 0) {
          check(visibleText.indexOf("Online · enforcing") >= 0 && visibleText.indexOf("Offline") >= 0, "status wording")
          check(visibleText.indexOf("0 apps with endpoint-owner IP entries reported") >= 0, "zero count")
          check(visibleText.indexOf("Apps with endpoint-owner IP entries not reported") >= 0, "unreported count")
          view.toggleEndpoint("fixture-online")
          check(view.selectedName === "fixture-online", "selection")
          view.toggleEndpoint("fixture-online")
          check(view.selectedName === "", "deselection")
          view.account = account(fixtureRows, clock - 60000, false)
          view.now = clock // retain the deterministic inventory fixture clock
        } else if (step === 1) {
          check(visibleText.indexOf("Inventory refresh failed.") >= 0, "failed refresh")
          check(visibleText.indexOf(new Date(clock - 60000).toLocaleString()) >= 0 && visibleText.indexOf("60 seconds ago") >= 0, "full retained date and age")
          view.account = account(fixtureRows, clock + 60001, true)
          view.now = clock // retain the deterministic inventory fixture clock
        } else if (step === 2) {
          check(visibleText.indexOf("Inventory freshness unknown.") >= 0 && visibleText.indexOf("seconds ago") < 0, "future date")
          view.account = account([], clock, true)
          view.now = clock // retain the deterministic inventory fixture clock
        } else if (step === 3) {
          check(view.rows.length === 0 && visibleText.indexOf("0 kub0 endpoints.") >= 0, "empty inventory")
          view.account = account(fixtureRows, clock, true, false)
          view.now = clock // retain the deterministic inventory fixture clock
        } else if (step === 4) {
          check(view.rows.length === 0, "disconnected rows")
          view.destroy()
          var liveNow = Date.now()
          expiryDeadline = liveNow + 1500
          var liveRows = [{nodeName:"near-expiry", state:"monitoring",
            lastSeen:new Date(expiryDeadline - 600000).toISOString()}]
          var component = Qt.createComponent("file://" + Quickshell.env("VALLUM_CANDIDATE_DIR") + "/EndpointsView.qml")
          check(component.status === Component.Ready, component.errorString())
          // Use the actual view's default Date.now clock and its own Timer.
          view = component.createObject(surface, {width:640, height:740,
            account:account(liveRows, liveNow, true)})
          check(view !== null, "live view creation failed")
        } else {
          var rowState = observedEndpointState()
          var observedAt = Date.now()
          if (!observedOnline) {
            check(observedAt < expiryDeadline, "missed pre-deadline observation")
            check(!rowState.offline, "near-expiry row not Online")
            preDeadlineRowText = rowState.text
            observedOnline = true
          }
          if (rowState.offline) {
            check(observedOnline && observedAt >= expiryDeadline, "premature Offline")
            check(observedAt - expiryDeadline < 1000, "expiry update was not prompt")
            finish({ok:true, checks:10, preDeadlineRowText:preDeadlineRowText,
              observedRowText:rowState.text, expiryLagMs:observedAt - expiryDeadline})
            return
          }
          check(observedAt < expiryDeadline + 1000, "view remained Online after deadline")
          return
        }
        step++
      } catch (error) { finish({ok:false, error:String(error)}) }
    }
  }
}
