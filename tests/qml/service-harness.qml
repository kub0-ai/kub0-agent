import QtQuick
import Quickshell

Scope {
  id: harness
  property var service: null
  property var initialService: null
  property int demoGeneration: 0
  property int demoRetries: 0
  // The sharing switch on the service's own daemon, before a system daemon is found.
  property bool sharingBefore: true
  function fixtureLine(id) {
    return JSON.stringify({type:"snapshot",ts:Date.now(),connections:[{
      id:id,proto:"tcp",inode:123,app:{id:id,name:id,icon:"",desktop:"",pid:1234,system:false},
      local:{ip:"192.0.2.254",port:45678},remote:{ip:"192.0.2.1",port:443},state:"ESTABLISHED",
      country:"",lat:0,lon:0,unresolved:false,newNetwork:false,networkKey:"192.0.2.0/24",hostname:""
    }]});
  }
  Timer {
    interval: 900
    running: Quickshell.env("VALLUM_CHECK") === "demo"
    onTriggered: {
      harness.service.ingest(harness.fixtureLine("manager-real"));
      harness.service.model.blocked["manager-session"] = { mechanism: "cgroup" };
      harness.service.ingest(JSON.stringify({type:"hello",mode:"system"}));
      harness.service.ingest(JSON.stringify({type:"fleet",connected:true,netpolicyRefreshOk:true,
        netpolicyEnforcement:{state:"enforcing",enforcing:true,appliedTs:1234}}));
      console.log("DEMO_SEEDED", JSON.stringify({role:harness.service.policyDaemonMode,enforcing:harness.service.kub0.netpolicyEnforcement.enforcing}));
      harness.service.enterDemo("on");
      console.log("DEMO_ENTER", JSON.stringify({
        role: harness.service.policyDaemonMode,
        enforcing: harness.service.kub0.netpolicyEnforcement.enforcing,
        count: harness.service.model.count,
        real: !!harness.service.model.apps["manager-real"],
        blocked: !!harness.service.model.blocked["manager-session"]
      }));
      harness.demoGeneration = harness.service.socketGeneration;
      harness.demoRetries = harness.service.socketRetryAttempts;
      demoExit.start();
    }
  }
  Timer {
    id: demoExit; interval: 1100
    onTriggered: {
      console.log("DEMO_PAUSED", JSON.stringify({generationStable:harness.service.socketGeneration === harness.demoGeneration, retriesStable:harness.service.socketRetryAttempts === harness.demoRetries, current:harness.service.dataCurrent, role:harness.service.policyDaemonMode, enforcing:harness.service.kub0.netpolicyEnforcement.enforcing, daemonRunning:harness.service.daemonRunning}));
      harness.service.ingest(harness.fixtureLine("manager-demo"));
      console.log("DEMO_FIXTURE", harness.service.model.count);
      harness.service.enterDemo("off");
      console.log("DEMO_EXIT", JSON.stringify({
        role: harness.service.policyDaemonMode,
        enforcing: harness.service.kub0.netpolicyEnforcement.enforcing,
        count: harness.service.model.count,
        demo: !!harness.service.model.apps["manager-demo"],
        blocked: !!harness.service.model.blocked["manager-session"],
        monitoring: harness.service.monitoring
      }));
      demoHello.start();
    }
  }
  // #61 step 1b: the request-only connection to the system socket, through
  // a real Quickshell Socket. A missing socket is unreachable (the helper
  // fallback); a greeting system daemon gets the block as a control request.
  property var systemProbe: ({})
  Timer {
    interval: 1500
    running: Quickshell.env("VALLUM_CHECK") === "system"
    onTriggered: {
      let started = Date.now();
      // No system daemon so far: the service is on the kub0d it started.
      harness.sharingBefore = harness.service.sharingDestinations;
      console.log("STREAM_BEFORE", JSON.stringify({ source: harness.service.eventSource, own: harness.service.ownDaemonRunning }));
      harness.service.systemSocketPath = Quickshell.env("VALLUM_SYSTEM_MISSING");
      harness.service.withSystem(function(ok) {
        console.log("SYSTEM_MISSING", JSON.stringify({ reachable: ok, ms: Date.now() - started }));
        systemBlock.start();
      });
    }
  }
  Timer {
    id: systemBlock; interval: 200
    onTriggered: {
      harness.service.systemSocketPath = Quickshell.env("VALLUM_SYSTEM_FIXTURE");
      harness.service.ingest(harness.fixtureLine("system-app"));
      let queued = harness.service.submitChange(["block-app", "system-app", "1234"]);
      console.log("SYSTEM_SUBMITTED", JSON.stringify({ queued: queued, busy: harness.service.helperBusy }));
      systemResult.start();
    }
  }
  Timer {
    id: systemResult; interval: 2500
    onTriggered: {
      console.log("SYSTEM_BLOCK", JSON.stringify({
        blocked: !!harness.service.model.blocked["system-app"],
        mechanism: harness.service.model.blocked["system-app"] ? harness.service.model.blocked["system-app"].mechanism : "",
        busy: harness.service.helperBusy,
        error: harness.service.lastBlockError,
        state: harness.service.sysState
      }));
      // #61 step 2: the account card and the policy list from the system daemon.
      harness.service.refreshSystemView();
      systemView.start();
    }
  }
  Timer {
    id: systemView; interval: 1500
    onTriggered: {
      console.log("SYSTEM_VIEW", JSON.stringify({
        user: harness.service.kub0.githubUsername,
        node: harness.service.kub0.nodeName,
        connected: harness.service.kub0Account.connected,
        policies: harness.service.kub0.netpolicies.length,
        snoozedUntil: harness.service.kub0.netpolicies.length ? harness.service.kub0.netpolicies[0].rules[0].snoozedUntil : 0
      }));
      // #61, one daemon: that read found a usable system daemon, so the service
      // reads its stream now and runs no kub0d of its own.
      console.log("STREAM_READ", JSON.stringify({
        source: harness.service.eventSource,
        own: harness.service.ownDaemonRunning,
        status: harness.service.daemonStatus,
        mode: harness.service.policyDaemonMode,
        row: !!harness.service.model.apps["whole-host-app"],
        uid: harness.service.sessionUid,
        view: harness.service.systemView !== null,
        sharing: harness.service.sharingDestinations
      }));
      harness.service.setSharing(false);
      harness.service.setWatch("asn", "64500", "fixture");
      harness.service.tagNetwork("203.0.113.0/24", "Fixture net", "service");
      harness.service.noteActivity("block", { id: "whole-host-app", name: "whole-host-app" }, {});
      streamWrites.start();
    }
  }
  Timer {
    id: streamWrites; interval: 1200
    onTriggered: console.log("STREAM_WRITES", JSON.stringify({ watchError: harness.service.watchError, tagNotice: harness.service.tagNotice, sharingBefore: harness.sharingBefore }))
  }
  Timer {
    id: demoHello; interval: 1000
    onTriggered: console.log("DEMO_FRESH_HELLO", harness.service.policyDaemonMode);
  }
  Timer {
    interval: 50
    running: true
    onTriggered: {
      let component = Qt.createComponent("file://" + Quickshell.env("VALLUM_CANDIDATE_DIR") + "/Service.qml");
      if (component.status !== Component.Ready) {
        console.error(component.errorString());
        Qt.quit();
        return;
      }
      harness.service = component.createObject(harness, {
        manifest: { __sourceDir: Quickshell.env("VALLUM_FAKE_PLUGIN") },
        // Service pins /usr/bin/pkexec, so the PATH-prepended fake alone no
        // longer intercepts it. Hand it the refusing fake explicitly.
        pkexecPath: Quickshell.env("VALLUM_FAKE_PLUGIN") + "/bin/pkexec"
      });
      harness.initialService = harness.service;
      harness.service.panelVisible = true;
    }
  }
  Timer {
    interval: 500
    running: true
    repeat: true
    onTriggered: if (harness.service)
      console.log("SERVICE_STATE", JSON.stringify({
        sameService: harness.service === harness.initialService,
        monitoring: harness.service.monitoring,
        socket: harness.service.socketConnected,
        daemon: harness.service.daemonStatus,
        daemonAvailable: harness.service.daemonAvailable,
        kub0d: harness.service.vallumdPath,
        restarts: harness.service.restarts,
        running: harness.service.daemonRunning,
        count: harness.service.activeCount,
        snapshot: harness.service.snapshotReady,
        current: harness.service.dataCurrent,
        fallback: harness.service.usingFallback,
        retries: harness.service.socketRetryAttempts,
        generation: harness.service.socketGeneration,
        uniqueRow: Object.keys(harness.service.model.connections || {}).some(function(k) { return k.indexOf("fixture-unique-") === 0; }),
        rowIds: Object.keys(harness.service.model.connections || {}),
        prefsLoaded: harness.service.prefsLoaded,
        prefs: harness.service.prefs
      }));
  }
  Timer {
    interval: 8500; running: true
    onTriggered: {
      if (harness.service) {
        harness.service.destroy();
        harness.service = null;
      }
    }
  }
  Timer { interval: 9100; running: true; onTriggered: console.log("SERVICE_DESTROYED"); }
  Timer { interval: 9500; running: true; onTriggered: Qt.quit(); }
}
