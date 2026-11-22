import QtQuick
import "../js/Health.js" as Health

// PanelHero.meta must spell all four postures from the helper's
// own reported state (blockingReady + recorded block count), never from a UI-side
// composite flag. Drive with /usr/lib/qt6/bin/qml — /usr/bin/qml is Qt5 and
// exits 0 on failure.

Item {
  id: probe

  property int fail: 0
  function check(name, cond, detail) {
    console.warn((cond ? "  ok   " : "  FAIL ") + name + (detail ? "  [" + detail + "]" : ""))
    if (!cond) probe.fail++
  }

  function posture(info) {
    return Health.heroPosture(info)
  }

  Component.onCompleted: {
    check("helper absent → Not installed",
          posture({
            helperInstalled: false,
            helperStatusFailed: false,
            blockingReady: false,
            blockCount: 0
          }) === "Not installed")

    check("status call failed → Not installed",
          posture({
            helperInstalled: true,
            helperStatusFailed: true,
            blockingReady: false,
            daemonReachable: true,
            blockCount: 0
          }) === "Not installed")

    check("daemon reachable, enforcement off → Inactive",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: false,
            daemonReachable: true,
            blockCount: 0
          }) === "Inactive")

    check("enforcement on, nothing blocked → Active",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: true,
            daemonReachable: true,
            blockCount: 0
          }) === "Active")

    check("paused, apps blocked → Paused, never Blocks recorded",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: true,
            paused: true,
            blockCount: 2
          }) === "Paused")

    check("paused, nothing blocked → Paused",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: true,
            paused: true,
            blockCount: 0
          }) === "Paused")

    check("paused but tools missing → Inactive",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: false,
            paused: true,
            blockCount: 0
          }) === "Inactive")

    check("enforcement on, apps blocked → Blocks recorded",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: true,
            daemonReachable: true,
            blockCount: 3
          }) === "Blocks recorded")

    // The count feeding blockCount has to see BOTH block arms. A cgroup block
    // writes nothing to status.owners, so an owners-only count reports 0 while
    // the kernel is dropping that app's traffic and the hero reads "Active".
    // Verified live: owners == {} with an app blocked, rule present in raw.
    var cgroupOnly = {
      owners: {},
      raw: 'table inet vallum {\n  chain out {\n    socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop\n  }\n}'
    }
    check("a cgroup-only block is counted (owners is empty)",
          Health.blockedAppCount(cgroupOnly) === 1)

    check("a cgroup-only block still reads Blocks recorded",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: true,
            daemonReachable: true,
            blockCount: Health.blockedAppCount(cgroupOnly)
          }) === "Blocks recorded")

    check("root-written marker counts without a readable nft table",
          Health.blockedAppCount({ owners: {}, table: false,
            cgroupBlocksSource: "marker", cgroupBlocks: ["firefox"] }) === 1)

    check("endpoint and cgroup blocks of the SAME app count once",
          Health.blockedAppCount({
            owners: { "firefox": "1.2.3.4" },
            raw: 'socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop'
          }) === 1)

    check("both arms, different apps, count separately",
          Health.blockedAppCount({
            owners: { "slack": "1.2.3.4" },
            raw: 'socket cgroupv2 level 2 "vallum.slice/vallum-firefox" drop'
          }) === 2)

    check("no blocks anywhere counts zero",
          Health.blockedAppCount({ owners: {}, raw: "table inet vallum { }" }) === 0)

    check("a UI-side ready flag cannot mint Blocks recorded",
          posture({
            helperInstalled: true,
            helperStatusFailed: false,
            blockingReady: false,
            uiBlockingReady: true,
            blockCount: 4
          }) === "Inactive")

    check("status failure beats a live block count",
          posture({
            helperInstalled: true,
            helperStatusFailed: true,
            blockingReady: true,
            blockCount: 2
          }) === "Not installed")

    console.warn(probe.fail === 0 ? "PROBE PASS" : "PROBE FAIL (" + probe.fail + ")")
    Qt.exit(probe.fail === 0 ? 0 : 1)
  }
}
