import QtQuick
import qs.Commons
import "js/Scroll.js" as Scroll

// The wheel handling for every scrolling view in the panel. Declare one inside
// each Flickable or ListView:
//
//   ListView { id: list; ...; WheelStep { flick: list; speed: root.scrollSpeed; momentum: root.scrollMomentum } }
//
// tests/test_scroll.js fails when a scrolling view in this directory has none:
// a list without it falls back to Qt's own handling, which on this desktop is
// 40% of the fingers' travel and no momentum (js/Scroll.js says why).
//
// `blocking` defaults true, so the event is consumed here and the Flickable
// does not also act on it. Verified against qquickwheelhandler.cpp at 6.12.0:
// a double-apply would read as the view moving twice as far as asked. The same
// file shows the handler stays active through a gesture, so the zero-delta
// ScrollEnd that starts the coast does reach onWheel.
WheelHandler {
  id: handler
  objectName: "wheelStep"

  required property var flick
  // "slow" | "normal" | "fast" | "fastest": the scrollSpeed preference.
  property string speed: "normal"
  // Keep moving after a touchpad swipe: the scrollMomentum preference.
  property bool momentum: true
  // One wheel notch at Normal: three rows, matching the rest of the desktop
  // (QStyleHints.wheelScrollLines is 3) against a row of about 40 px.
  property real notchPx: Style.space(120)

  // Mutated in place by Scroll.advance; nothing binds to it.
  readonly property var feel: Scroll.newState()

  // One wheel event, by its parts, so a test can drive the handler without a
  // real pointer. Returns what Scroll.advance decided.
  function apply(phase, px, ang) {
    var minY = flick.originY
    var maxY = flick.originY + Math.max(0, flick.contentHeight - flick.height)
    if (maxY <= minY)
      return { move: 0, flick: 0, stop: false }

    var out = Scroll.advance(feel, phase, px, ang, Date.now(), {
      notchPx: notchPx,
      factor: Scroll.speedFactor(speed),
      momentum: momentum
    })

    // Cancel first: assigning contentY under a live flick leaves the animator
    // running and it drags the view back out from under the step.
    if (out.stop)
      flick.cancelFlick()
    if (out.move !== 0)
      flick.contentY = Scroll.clampY(flick.contentY, out.move, minY, maxY)
    // Nothing to coast into when the view is already against the edge the
    // swipe was heading for.
    if (out.flick !== 0) {
      if ((out.flick > 0 && flick.contentY <= minY) || (out.flick < 0 && flick.contentY >= maxY))
        out.flick = 0
      else
        coast(out.flick)
    }
    return out
  }

  // Flickable.flick() reads the deceleration, the speed cap and the bounds
  // behaviour when it is called and keeps them for that flick (measured on Qt
  // 6.12: 6000 px/s at 6000 px/s per second stops after exactly 3000 px with
  // the properties already put back). So the view's own values, which a
  // drag-flick uses, are restored straight away.
  //
  // StopAtBounds for the coast: a list that reaches its end stops there. Left
  // to a view's default it would run past the end and spring back, in some
  // views and not in others.
  function coast(velocity) {
    var decel = flick.flickDeceleration
    var cap = flick.maximumFlickVelocity
    var bounds = flick.boundsBehavior
    flick.flickDeceleration = Scroll.COAST_DECEL
    flick.maximumFlickVelocity = Scroll.COAST_MAX
    flick.boundsBehavior = Flickable.StopAtBounds
    flick.flick(0, velocity)
    flick.flickDeceleration = decel
    flick.maximumFlickVelocity = cap
    flick.boundsBehavior = bounds
  }

  onWheel: function(event) {
    apply(event.phase, event.pixelDelta.y, event.angleDelta.y)
  }
}
