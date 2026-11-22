// Scroll feel for the kub0 panel: how far one wheel event moves a list, and
// whether the list keeps moving when a touchpad swipe ends.
//
// Pure, so it runs under Node like the rest of js/. WheelStep.qml is the thin
// QML half: it feeds this real wheel events and applies the answer to a
// Flickable.
//
// Why the panel does this itself. Qt Quick gives a wheel event to a Flickable
// in one of two ways and neither suits a long list:
//   - With a pixel delta it moves the content by exactly that delta and stops
//     dead when the fingers lift. Qt adds no momentum of its own; on macOS the
//     system sends momentum events, on Wayland nothing does.
//   - Without one it takes a flat step per notch. The accelerating mode sits
//     behind the private `wheelDeceleration`, whose only override is the
//     process-wide QT_QUICK_FLICKABLE_WHEEL_DECELERATION, and that would reach
//     every other plugin in the shell.
// On top of that the desktop scales the touchpad down before Qt sees it
// (Omarchy ships `scroll_factor = 0.4`), so the unassisted list moves at less
// than half the speed of the fingers.

// Qt::ScrollPhase. QML has these as Qt.NoScrollPhase and so on; the numbers
// are repeated here so Node can run this file. tests/test_scroll_feel.qml
// checks them against the Qt in use.
var PHASE_NONE = 0
var PHASE_BEGIN = 1
var PHASE_UPDATE = 2
var PHASE_END = 3
var PHASE_MOMENTUM = 4

// The choices offered in Settings, slowest first. `value` is what ui.json
// stores (js/Prefs.js SCROLL_SPEEDS is the same list); `factor` multiplies
// every distance below.
var SPEEDS = [
    { value: "slow", label: "Slow", factor: 0.6 },
    { value: "normal", label: "Normal", factor: 1 },
    { value: "fast", label: "Fast", factor: 1.7 },
    { value: "fastest", label: "Fastest", factor: 2.8 }
]

function speedFactor(value) {
    for (var i = 0; i < SPEEDS.length; i++) {
        if (SPEEDS[i].value === value)
            return SPEEDS[i].factor
    }
    return 1
}

// A touchpad swipe moves the content this many pixels per pixel the fingers
// report, at Normal. 2.5 undoes the desktop's 0.4.
var GLIDE = 2.5

// A fast run of wheel notches accelerates: each notch inside the window
// multiplies the step, up to the cap. One deliberate notch is always exactly
// one notch.
var BOOST_WINDOW_MS = 120
var BOOST_GROW = 1.3
var BOOST_MAX = 6

// Momentum. The list carries on at the speed it had when the fingers lifted
// and slows at COAST_DECEL, so the distance is v*v / (2 * COAST_DECEL): 2000
// px/s coasts 330 px, 6000 px/s coasts 3000 px.
var COAST_MIN = 500         // px/s; a slower release stays where it was put
var COAST_MAX = 16000       // px/s
var COAST_DECEL = 6000      // px/s per second
var RELEASE_IDLE_MS = 80    // fingers that stopped before lifting do not coast
var GLIDE_GAP_MS = 100      // a longer gap between updates is a new movement
var SPEED_WINDOW_MS = 100   // the stretch of a swipe its speed is measured over
var SPEED_MIN_SPAN_MS = 8   // never divide by less: one frame at 120 Hz

function newState() {
    return { boost: 1, lastNotchMs: 0, samples: [], lastGlideMs: 0 }
}

// The content's speed at the end of a swipe, in px/s: the distance covered
// over the last SPEED_WINDOW_MS, divided by the time it took.
//
// Measured over a window, never per event. When the shell stalls for a frame
// or two the queued updates arrive in the same millisecond, and distance over
// "time since the last event" turns 20 px into 20,000 px/s, which would send
// the list flying off a gentle swipe. Over the window the bunched events add
// their distance and the clock still shows the real time.
// `samples` is [[ms, move], ...], oldest first.
function swipeSpeed(samples) {
    if (!samples || samples.length < 2)
        return 0
    var last = samples[samples.length - 1][0]
    var first = samples.length - 1
    while (first > 0 && last - samples[first - 1][0] <= SPEED_WINDOW_MS)
        first -= 1
    if (first === samples.length - 1)
        return 0
    var distance = 0
    for (var i = first + 1; i < samples.length; i++)
        distance += samples[i][1]
    var span = Math.max(last - samples[first][0], SPEED_MIN_SPAN_MS)
    return distance / span * 1000
}

// What one wheel event is. The discriminator is the scroll PHASE, not which
// deltas are filled in.
//
// The handler this replaces asked "is there a pixel delta?" and called that a
// touchpad. On Wayland that is true of every event: Qt fills pixelDelta from
// the compositor's axis value for a mouse wheel as well (qwaylandinputdevice
// .cpp, flushScrollEvent, read at 6.12.0), so a wheel notch arrived as a
// 15-pixel "swipe" and moved one row instead of three, with no acceleration.
// Only a finger on a touchpad gets ScrollBegin / ScrollUpdate / ScrollEnd; a
// wheel has no phase.
function kind(phase, px, ang) {
    if (phase === PHASE_BEGIN)
        return "begin"
    if (phase === PHASE_END)
        return "end"
    if (phase === PHASE_UPDATE || phase === PHASE_MOMENTUM) {
        // Qt carries a sub-pixel remainder into the next event's pixel delta,
        // so an update that rounds to no pixels is not a small step to invent.
        return px !== 0 ? "glide" : "none"
    }
    if (ang !== 0)
        return "notch"
    return px !== 0 ? "glide" : "none"
}

// Feed one event. Returns what the view should do:
//   move   pixels to shift the content now; positive is towards the top
//   flick  a speed in px/s to hand to Flickable.flick(), same sign; 0 for none
//   stop   true when a movement in progress should be cancelled first
// `state` is one newState() per view and is updated in place.
// `cfg` is { notchPx, factor, momentum }.
function advance(state, phase, px, ang, nowMs, cfg) {
    var out = { move: 0, flick: 0, stop: false }
    var factor = cfg && cfg.factor > 0 ? cfg.factor : 1
    var k = kind(phase, px, ang)

    if (k === "none")
        return out

    if (k === "begin") {
        // Fingers back on the pad: a coast from the last swipe ends here.
        state.samples = []
        state.lastGlideMs = 0
        out.stop = true
        return out
    }

    if (k === "end") {
        var v = swipeSpeed(state.samples)
        var idle = nowMs - state.lastGlideMs
        state.samples = []
        state.lastGlideMs = 0
        if (cfg && cfg.momentum && idle <= RELEASE_IDLE_MS && Math.abs(v) >= COAST_MIN)
            out.flick = Math.max(-COAST_MAX, Math.min(COAST_MAX, v))
        return out
    }

    out.stop = true

    if (k === "glide") {
        var move = px * GLIDE * factor
        var n = state.samples.length
        // A pause, a change of direction, or momentum the system is already
        // supplying: what came before says nothing about the speed now.
        if (phase !== PHASE_UPDATE
                || (n > 0 && nowMs - state.lastGlideMs > GLIDE_GAP_MS)
                || (n > 0 && (state.samples[n - 1][1] > 0) !== (move > 0)))
            state.samples = []
        if (phase === PHASE_UPDATE) {
            state.samples.push([nowMs, move])
            // Keep what the window can use and a little more.
            while (state.samples.length > 2 && nowMs - state.samples[0][0] > 2 * SPEED_WINDOW_MS)
                state.samples.shift()
        }
        state.lastGlideMs = nowMs
        state.boost = 1
        out.move = move
        return out
    }

    // A wheel notch. `ang` is 120 per notch; a high-resolution wheel sends
    // fractions of that and moves in proportion.
    state.boost = (nowMs - state.lastNotchMs) < BOOST_WINDOW_MS
        ? Math.min(state.boost * BOOST_GROW, BOOST_MAX) : 1
    state.lastNotchMs = nowMs
    state.samples = []
    state.lastGlideMs = 0
    out.move = (ang / 120) * (cfg ? cfg.notchPx : 0) * factor * state.boost
    return out
}

// Where the content lands after a move, held inside the scrollable range.
function clampY(contentY, move, minY, maxY) {
    return Math.max(minY, Math.min(maxY, contentY - move))
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        PHASE_NONE: PHASE_NONE,
        PHASE_BEGIN: PHASE_BEGIN,
        PHASE_UPDATE: PHASE_UPDATE,
        PHASE_END: PHASE_END,
        PHASE_MOMENTUM: PHASE_MOMENTUM,
        SPEEDS: SPEEDS,
        speedFactor: speedFactor,
        GLIDE: GLIDE,
        BOOST_WINDOW_MS: BOOST_WINDOW_MS,
        BOOST_GROW: BOOST_GROW,
        BOOST_MAX: BOOST_MAX,
        COAST_MIN: COAST_MIN,
        COAST_MAX: COAST_MAX,
        COAST_DECEL: COAST_DECEL,
        RELEASE_IDLE_MS: RELEASE_IDLE_MS,
        SPEED_WINDOW_MS: SPEED_WINDOW_MS,
        newState: newState,
        swipeSpeed: swipeSpeed,
        kind: kind,
        advance: advance,
        clampY: clampY
    }
}
