import QtQuick
import QtQuick.Window
import ".." as Kit
import "../js/Scroll.js" as Scroll

// WheelStep.qml on a real Flickable and a real ListView, driven through
// `apply(phase, pixelDelta.y, angleDelta.y)`: the same three numbers its
// onWheel takes from a wheel event. js/Scroll.js is unit-tested under Node;
// what only shows here is the part Qt does: contentY actually moving, the
// coast Flickable.flick() runs, and the view getting its own flick settings
// back. Run from the repository root:
//   /usr/lib/qt6/bin/qml -I tests/qml/kitstub tests/test_scroll_feel.qml
Window {
  id: probe
  visible: true
  width: 400
  height: 400

  property int fail: 0
  function check(name, cond, detail) {
    console.warn((cond ? "  ok   " : "  FAIL ") + name + (detail !== undefined ? "  [" + detail + "]" : ""))
    if (!cond) probe.fail++
  }
  function near(a, b, tol) { return Math.abs(a - b) <= (tol === undefined ? 0.5 : tol) }

  Flickable {
    id: page
    width: 400; height: 400
    contentWidth: width; contentHeight: 20000
    boundsBehavior: Flickable.StopAtBounds
    Rectangle { width: page.width; height: 20000; color: "#202020" }
    Kit.WheelStep { id: pageStep; flick: page }
  }

  // The furthest the list has been, to catch an overshoot between samples.
  property real peak: 0
  ListView {
    id: rows
    width: 400; height: 400
    model: 2000
    delegate: Item { width: rows.width; height: 40 }
    onContentYChanged: if (contentY > probe.peak) probe.peak = contentY
    Kit.WheelStep { id: rowsStep; flick: rows }
  }

  Flickable {
    id: fits
    width: 400; height: 400
    contentWidth: width; contentHeight: 300
    Kit.WheelStep { id: fitsStep; flick: fits }
  }

  // A swipe needs real time between its updates: the handler reads the clock.
  property var swipeDone: null
  property var swipeStep: null
  property int swipeLeft: 0
  property real swipePx: 0
  Timer {
    id: swipeTimer
    interval: 16
    repeat: true
    onTriggered: {
      if (probe.swipeLeft > 0) {
        probe.swipeLeft--
        probe.swipeStep.apply(Qt.ScrollUpdate, probe.swipePx, probe.swipePx * 12)
        return
      }
      stop()
      var out = probe.swipeStep.apply(Qt.ScrollEnd, 0, 0)
      var done = probe.swipeDone
      probe.swipeDone = null
      done(out)
    }
  }
  function swipe(step, px, count, done) {
    swipeStep = step; swipePx = px; swipeLeft = count; swipeDone = done
    step.apply(Qt.ScrollBegin, 0, 0)
    swipeTimer.start()
  }
  function later(ms, fn) {
    var t = Qt.createQmlObject('import QtQuick; Timer { repeat: false }', probe)
    t.interval = ms
    t.triggered.connect(function() { t.destroy(); fn() })
    t.start()
  }

  Component.onCompleted: {
    check("Qt's scroll phases are the numbers js/Scroll.js uses",
          Qt.NoScrollPhase === Scroll.PHASE_NONE && Qt.ScrollBegin === Scroll.PHASE_BEGIN
          && Qt.ScrollUpdate === Scroll.PHASE_UPDATE && Qt.ScrollEnd === Scroll.PHASE_END
          && Qt.ScrollMomentum === Scroll.PHASE_MOMENTUM,
          [Qt.NoScrollPhase, Qt.ScrollBegin, Qt.ScrollUpdate, Qt.ScrollEnd, Qt.ScrollMomentum].join(","))

    var notch = pageStep.notchPx
    check("one notch is three rows of the kit's spacing", notch === 120, notch)

    // ---- a wheel notch, as Wayland delivers it: no phase, both deltas set
    pageStep.apply(Qt.NoScrollPhase, -15, -120)
    check("a notch down moves the page one notch, not the 15 px it carries",
          near(page.contentY, notch), page.contentY)
    pageStep.apply(Qt.NoScrollPhase, 15, 120)
    check("a notch up moves it back", near(page.contentY, 0), page.contentY)
    pageStep.apply(Qt.NoScrollPhase, 15, 120)
    check("the top is a hard stop", page.contentY === 0, page.contentY)

    // ---- the speed choice
    pageStep.feel.lastNotchMs = 0
    pageStep.speed = "fastest"
    pageStep.apply(Qt.NoScrollPhase, -15, -120)
    check("Fastest moves a notch by its factor",
          near(page.contentY, notch * Scroll.speedFactor("fastest")), page.contentY)
    page.contentY = 0
    pageStep.feel.lastNotchMs = 0
    pageStep.speed = "slow"
    pageStep.apply(Qt.NoScrollPhase, -15, -120)
    check("Slow moves it less than one", near(page.contentY, notch * Scroll.speedFactor("slow")), page.contentY)
    page.contentY = 0
    pageStep.speed = "normal"

    // ---- the bottom
    page.contentY = page.contentHeight - page.height - 10
    pageStep.feel.lastNotchMs = 0
    pageStep.apply(Qt.NoScrollPhase, -15, -120)
    check("the bottom is a hard stop", page.contentY === page.contentHeight - page.height, page.contentY)
    page.contentY = 0

    // ---- a ListView moves the same way
    rowsStep.apply(Qt.NoScrollPhase, -15, -120)
    check("a ListView moves one notch too", near(rows.contentY - rows.originY, notch), rows.contentY)
    rows.contentY = rows.originY

    // ---- content that fits has nowhere to go
    var idle = fitsStep.apply(Qt.NoScrollPhase, -15, -120)
    check("a view whose content fits does not move", fits.contentY === 0 && idle.move === 0, fits.contentY)

    // ---- a swipe, then the coast
    var decel = page.flickDeceleration, cap = page.maximumFlickVelocity
    swipe(pageStep, -20, 8, function(out) {
      var atLift = page.contentY
      check("a swipe moves the page by the fingers' travel times the glide",
            near(atLift, 8 * 20 * Scroll.GLIDE, 1), atLift)
      check("lifting mid-swipe starts a coast", out.flick < -Scroll.COAST_MIN && page.flicking,
            "flick=" + Math.round(out.flick) + " flicking=" + page.flicking)
      check("the view has its own flick settings back at once",
            page.flickDeceleration === decel && page.maximumFlickVelocity === cap,
            page.flickDeceleration + "/" + page.maximumFlickVelocity)
      var expected = out.flick * out.flick / (2 * Scroll.COAST_DECEL)
      later(1800, function() {
        var coasted = page.contentY - atLift
        check("the coast runs on to v*v/2a and stops", !page.flicking && near(coasted, expected, 3),
              "coasted " + Math.round(coasted) + " of " + Math.round(expected))

        // ---- the same swipe on a ListView
        swipe(rowsStep, -20, 8, function(out2) {
          var listLift = rows.contentY
          check("a ListView coasts too", out2.flick < 0 && rows.flicking, "flick=" + Math.round(out2.flick))
          later(1800, function() {
            check("...and travels on past where the fingers left it", rows.contentY > listLift + 100,
                  Math.round(rows.contentY - listLift))

            // ---- a new touch stops a coast where it is
            page.contentY = 0
            swipe(pageStep, -40, 8, function(out3) {
              check("a hard swipe is coasting", page.flicking, "flick=" + Math.round(out3.flick))
              later(60, function() {
                pageStep.apply(Qt.ScrollBegin, 0, 0)
                var held = page.contentY
                check("fingers back on the pad stop it", !page.flicking, "flicking=" + page.flicking)
                later(200, function() {
                  check("...and it stays stopped", page.contentY === held, page.contentY + " vs " + held)

                  // ---- a swipe against the edge it is already on
                  page.contentY = 0
                  swipe(pageStep, 20, 8, function(outTop) {
                    check("a swipe up at the top has nothing to coast into",
                          outTop.flick === 0 && !page.flicking && page.contentY === 0,
                          "flick=" + outTop.flick + " y=" + page.contentY)

                    // ---- a coast that reaches the end stops there. This
                    // ListView keeps Qt's default bounds behaviour, which on
                    // its own would run past the end and spring back.
                    var listEnd = rows.originY + rows.contentHeight - rows.height
                    // Far enough back that the swipe itself (1200 px) does
                    // not reach the end; its coast (over 7000 px) would.
                    rows.contentY = listEnd - 3000
                    probe.peak = rows.contentY
                    check("the list under test overshoots by default",
                          rows.boundsBehavior === Flickable.DragAndOvershootBounds, rows.boundsBehavior)
                    swipe(rowsStep, -60, 8, function(outEnd) {
                      check("a hard swipe near the end is coasting", rows.flicking, "flick=" + Math.round(outEnd.flick))
                      check("...and the list has its own bounds behaviour back",
                            rows.boundsBehavior === Flickable.DragAndOvershootBounds, rows.boundsBehavior)
                      later(1500, function() {
                        var end = rows.originY + rows.contentHeight - rows.height
                        check("the coast stops at the end of the list", near(rows.contentY, end, 1) && !rows.flicking,
                              Math.round(rows.contentY) + " of " + Math.round(end))
                        check("...without running past it on the way", probe.peak <= end + 1,
                              "peak " + Math.round(probe.peak) + " end " + Math.round(end))

                        // ---- momentum off
                        page.contentY = 0
                        pageStep.momentum = false
                        swipe(pageStep, -20, 8, function(out4) {
                          var stopped = page.contentY
                          check("with momentum off the lift starts nothing", out4.flick === 0 && !page.flicking,
                                "flick=" + out4.flick)
                          later(300, function() {
                            check("...and the page stays where the fingers left it", page.contentY === stopped,
                                  page.contentY + " vs " + stopped)
                            console.warn(probe.fail === 0 ? "PROBE PASS" : "PROBE FAIL (" + probe.fail + ")")
                            Qt.exit(probe.fail === 0 ? 0 : 1)
                          })
                        })
                      })
                    })
                  })
                })
              })
            })
          })
        })
      })
    })
  }
}
