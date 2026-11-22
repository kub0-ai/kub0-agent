import QtQuick
import "../js/Prefs.js" as Prefs

// Prefs.js is unit-tested under Node, but the panel runs it inside QML's own
// JS engine. The two are not the same interpreter: `instanceof Array` across
// a context boundary and `hasOwnProperty` on an engine-created object are
// exactly the constructs that diverge, and both are load-bearing in sanitize()
// and withValue(). This re-runs the assertions that depend on them where they
// actually execute.
Item {
  id: probe

  property int fail: 0
  function check(name, cond, detail) {
    console.warn((cond ? "  ok   " : "  FAIL ") + name + (detail ? "  [" + detail + "]" : ""))
    if (!cond) probe.fail++
  }

  function keysOf(o) {
    var out = []
    for (var k in o) out.push(k)
    return out.sort().join(",")
  }

  Component.onCompleted: {
    var d = Prefs.defaults()

    check("defaults load under the QML engine", keysOf(d).length > 0, keysOf(d))
    check("blocking confirmation defaults ON", d.confirmBlocks === true)

    // `parsed instanceof Array` — the construct most likely to differ.
    var arr = Prefs.parse('["sortKey","activity"]')
    check("a JSON array root is still rejected in QML", arr.error === true,
          "error=" + arr.error + " sortKey=" + arr.prefs.sortKey)
    check("...and falls back to defaults", arr.prefs.sortKey === "name", arr.prefs.sortKey)

    // An object literal built by QML's engine, not Node's.
    var obj = Prefs.parse('{"sortKey":"connections","confirmBlocks":false}')
    check("valid values parse in QML", obj.prefs.sortKey === "connections", obj.prefs.sortKey)
    check("a real false survives", obj.prefs.confirmBlocks === false)

    var strFalse = Prefs.parse('{"confirmBlocks":"false"}')
    check("string 'false' still cannot disable the confirmation",
          strFalse.prefs.confirmBlocks === true, String(strFalse.prefs.confirmBlocks))

    // `hasOwnProperty` on an engine-created object, via withValue.
    var bad = Prefs.withValue(d, "evilKey", "payload")
    check("withValue still refuses an unknown key in QML",
          keysOf(bad) === keysOf(d), keysOf(bad))

    var good = Prefs.withValue(d, "sortKey", "activity")
    check("withValue returns a NEW object", good !== d)
    check("...the original is untouched", d.sortKey === "name", d.sortKey)
    check("...and the new value applied", good.sortKey === "activity", good.sortKey)

    var clamped = Prefs.withValue(d, "sortKey", "cpu")
    check("withValue clamps an invalid write", clamped.sortKey === "name", clamped.sortKey)

    check("changed() sees a real edit", Prefs.changed(d, good) === true)
    check("changed() ignores a no-op", Prefs.changed(d, Prefs.withValue(d, "sortKey", "name")) === false)

    // openingView must never hand the panel a non-view, or no section renders.
    for (var i = 0; i < Prefs.STARTUP_VIEWS.length; i++) {
      var sv = Prefs.STARTUP_VIEWS[i]
      var v = Prefs.openingView({ startupView: sv, lastView: "apps" })
      check("openingView(" + sv + ") resolves to a real view",
            Prefs.VIEWS.indexOf(v) >= 0 && v !== "last", v)
    }

    check("a corrupt lastView still opens somewhere real",
          Prefs.VIEWS.indexOf(Prefs.openingView({ startupView: "last", lastView: "atlantis" })) >= 0)

    var round = Prefs.parse(Prefs.serialize(good))
    check("serialize/parse round-trips under QML", round.prefs.sortKey === "activity", round.prefs.sortKey)

    console.warn(probe.fail === 0 ? "PROBE PASS" : "PROBE FAIL (" + probe.fail + ")")
    Qt.exit(probe.fail === 0 ? 0 : 1)
  }
}
