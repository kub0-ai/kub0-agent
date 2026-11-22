import QtQuick
import Quickshell
import "../../js/SystemStatus.js" as SystemStatus
import "../.." as Vallum
Scope {
  id: test
  Vallum.Service { id: service; shuttingDown: true }
  function check(ok, message) { if (!ok) throw new Error(message) }
  Component.onCompleted: Qt.callLater(function() {
    try {
      var epoch = 1791370000000
      var response = {mode:"system", producer_version:"0.1.0", observed_at:epoch,
        policy_refresh_ok:false, policy_known:true, reported_last_applied_at:epoch-10000,
        current_kernel_verification:"unknown"}
      var raw = JSON.stringify(response)
      service.healthTick = epoch
      service.systemDiagnostics = SystemStatus.finish(SystemStatus.empty(), raw, 0, false, epoch)
      check(service.healthTick === epoch, "Service clock truncated epoch")
      check(service.systemProtectionText.indexOf("System response observed 0s") === 0, "initial current binding")
      service.healthTick = epoch+5000
      check(service.systemProtectionText.indexOf("System response observed 5s") === 0, "5000ms current")
      service.healthTick = epoch+5001
      check(service.systemProtectionText.indexOf("System unavailable; last response 5s") === 0, "5001ms stale binding")
      service.healthTick = epoch+6600
      check(service.systemProtectionText.indexOf("last response 6s") >= 0, "6600ms age")
      var outcomes = [["{",0,false],[raw,1,false],[raw,0,true]]
      for (var i=0;i<outcomes.length;i++) {
        service.healthTick = epoch
        service.systemDiagnostics = SystemStatus.finish(SystemStatus.empty(), raw, 0, false, epoch)
        service.healthTick = epoch+1000
        service.systemDiagnostics = SystemStatus.finish(service.systemDiagnostics, outcomes[i][0], outcomes[i][1], outcomes[i][2], epoch+1000)
        check(service.systemProtectionText.indexOf("System unavailable; last response 1s") === 0, "failure retires current binding")
        service.healthTick = epoch+6600
        check(service.systemProtectionText.indexOf("last response 6s") >= 0, "failure retained response age")
        check(service.systemProtectionText.indexOf("reported last applied plan 16s") >= 0, "failure retained apply age")
      }
      service.healthTick = NaN
      check(service.systemProtectionText.indexOf("age unknown") >= 0, "invalid clock")
      service.healthTick = Infinity
      check(service.systemProtectionText.indexOf("age unknown") >= 0, "nonfinite clock")
      console.log("SERVICE_STATUS_PASS")
    } catch (e) { console.log("SERVICE_STATUS_FAIL", String(e)) }
    Qt.quit()
  })
  Timer { interval: 5000; running: true; onTriggered: Qt.quit() }
}
