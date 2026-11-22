"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const S = require("../js/Scroll.js");
const P = require("../js/Prefs.js");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log("  ok  " + name);
}

const NOTCH = 120;
function cfg(over) {
  return Object.assign({ notchPx: NOTCH, factor: 1, momentum: true }, over || {});
}
// A swipe: ScrollBegin, then one update every `everyMs` of `px` each.
function swipe(state, px, count, everyMs, startMs, c) {
  let t = startMs;
  let moved = 0;
  S.advance(state, S.PHASE_BEGIN, 0, 0, t, c);
  for (let i = 0; i < count; i++) {
    t += everyMs;
    moved += S.advance(state, S.PHASE_UPDATE, px, px * 12, t, c).move;
  }
  return { endMs: t, moved: moved };
}

// ------------------------------------------------------------ the choices

test("every speed the store accepts has a factor, slowest first", () => {
  assert.deepStrictEqual(S.SPEEDS.map((s) => s.value), P.SCROLL_SPEEDS,
    "js/Scroll.js SPEEDS and js/Prefs.js SCROLL_SPEEDS must list the same values in the same order");
  for (let i = 1; i < S.SPEEDS.length; i++)
    assert.ok(S.SPEEDS[i].factor > S.SPEEDS[i - 1].factor, S.SPEEDS[i].value + " is faster than the one before");
  assert.strictEqual(S.speedFactor("normal"), 1, "Normal is the tuned baseline");
  assert.strictEqual(S.speedFactor("warp"), 1, "an unknown value scrolls at Normal");
  for (const s of S.SPEEDS) assert.ok(s.label && s.label.length > 0, "a label to show");
});

test("the store defaults to Normal with momentum, and clamps a hand edit", () => {
  const d = P.defaults();
  assert.strictEqual(d.scrollSpeed, "normal");
  assert.strictEqual(d.scrollMomentum, true);
  assert.strictEqual(P.sanitize({ scrollSpeed: "ludicrous" }).scrollSpeed, "normal");
  assert.strictEqual(P.sanitize({ scrollSpeed: 3 }).scrollSpeed, "normal");
  assert.strictEqual(P.sanitize({ scrollSpeed: "fastest" }).scrollSpeed, "fastest");
  assert.strictEqual(P.sanitize({ scrollMomentum: "no" }).scrollMomentum, true, "a non-boolean falls back");
  assert.strictEqual(P.sanitize({ scrollMomentum: false }).scrollMomentum, false);
  const round = P.parse(P.serialize(P.withValue(d, "scrollSpeed", "fast"))).prefs;
  assert.strictEqual(round.scrollSpeed, "fast", "the choice survives a write and a read");
});

// ------------------------------------------------------- what an event is

test("a wheel notch on Wayland is a notch, though it carries a pixel delta", () => {
  // The regression. Qt on Wayland fills pixelDelta for a mouse wheel too (15
  // per notch from the compositor), and the handler this replaced keyed on
  // "has a pixel delta", so one notch moved 15 * 2.5 = 37.5 px: under one row.
  assert.strictEqual(S.kind(S.PHASE_NONE, 15, 120), "notch");
  const st = S.newState();
  assert.strictEqual(S.advance(st, S.PHASE_NONE, 15, 120, 1000, cfg()).move, NOTCH,
    "one notch moves one full notch");
  assert.strictEqual(S.advance(S.newState(), S.PHASE_NONE, -15, -120, 1000, cfg()).move, -NOTCH,
    "and the other way");
});

test("a touchpad swipe is told apart by its phase", () => {
  assert.strictEqual(S.kind(S.PHASE_BEGIN, 0, 0), "begin");
  assert.strictEqual(S.kind(S.PHASE_UPDATE, 8, 96), "glide");
  assert.strictEqual(S.kind(S.PHASE_END, 0, 0), "end");
  assert.strictEqual(S.kind(S.PHASE_MOMENTUM, 8, 96), "glide", "momentum the system supplies moves like a swipe");
});

test("an event with nothing vertical in it moves nothing", () => {
  assert.strictEqual(S.kind(S.PHASE_NONE, 0, 0), "none", "a sideways wheel");
  // Qt carries the sub-pixel remainder into the next event; an update that
  // rounds to no pixels still has a small angle delta and must not step.
  assert.strictEqual(S.kind(S.PHASE_UPDATE, 0, 4), "none");
  const out = S.advance(S.newState(), S.PHASE_UPDATE, 0, 4, 1000, cfg());
  assert.deepStrictEqual(out, { move: 0, flick: 0, stop: false });
});

test("a platform with no phases and no pixel delta still steps by the angle", () => {
  assert.strictEqual(S.kind(S.PHASE_NONE, 0, 120), "notch");
  assert.strictEqual(S.kind(S.PHASE_NONE, 9, 0), "glide", "pixels with no angle are a swipe");
});

// ------------------------------------------------------------- distances

test("a high-resolution wheel moves in proportion", () => {
  const out = S.advance(S.newState(), S.PHASE_NONE, 4, 30, 1000, cfg());
  assert.strictEqual(out.move, NOTCH / 4);
});

test("a fast run of notches accelerates, a deliberate one never does", () => {
  const st = S.newState();
  const first = S.advance(st, S.PHASE_NONE, 15, 120, 1000, cfg()).move;
  const second = S.advance(st, S.PHASE_NONE, 15, 120, 1050, cfg()).move;
  assert.strictEqual(first, NOTCH);
  assert.ok(Math.abs(second - NOTCH * S.BOOST_GROW) < 1e-9, "the second notch inside the window is boosted");
  let last = second;
  for (let i = 0; i < 40; i++) last = S.advance(st, S.PHASE_NONE, 15, 120, 1100 + i * 50, cfg()).move;
  assert.ok(Math.abs(last - NOTCH * S.BOOST_MAX) < 1e-9, "the boost stops at its cap");
  const later = S.advance(st, S.PHASE_NONE, 15, 120, 1100 + 40 * 50 + S.BOOST_WINDOW_MS + 1, cfg()).move;
  assert.strictEqual(later, NOTCH, "a notch after a pause is exactly one notch again");
});

test("a swipe moves the content by the fingers' travel times the glide", () => {
  const st = S.newState();
  const r = swipe(st, 10, 5, 16, 1000, cfg());
  assert.strictEqual(r.moved, 5 * 10 * S.GLIDE);
  const up = swipe(S.newState(), -10, 5, 16, 1000, cfg());
  assert.strictEqual(up.moved, -5 * 10 * S.GLIDE);
});

test("the speed choice scales a notch and a swipe alike", () => {
  for (const s of S.SPEEDS) {
    const c = cfg({ factor: s.factor });
    const notch = S.advance(S.newState(), S.PHASE_NONE, 15, 120, 1000, c).move;
    assert.ok(Math.abs(notch - NOTCH * s.factor) < 1e-9, s.value + " notch");
    const r = swipe(S.newState(), 10, 4, 16, 1000, c);
    assert.ok(Math.abs(r.moved - 4 * 10 * S.GLIDE * s.factor) < 1e-9, s.value + " swipe");
  }
  const slow = S.advance(S.newState(), S.PHASE_NONE, 15, 120, 1000, cfg({ factor: S.speedFactor("slow") })).move;
  const fastest = S.advance(S.newState(), S.PHASE_NONE, 15, 120, 1000, cfg({ factor: S.speedFactor("fastest") })).move;
  assert.ok(fastest > slow * 4, "the range is wide enough to feel: " + slow + " to " + fastest);
});

// --------------------------------------------------------------- momentum

test("lifting the fingers mid-swipe hands the list its speed", () => {
  const st = S.newState();
  // 20 px every 16 ms is 1250 px/s of finger, 3125 px/s of content.
  const r = swipe(st, 20, 8, 16, 1000, cfg());
  const out = S.advance(st, S.PHASE_END, 0, 0, r.endMs + 8, cfg());
  assert.strictEqual(out.move, 0);
  assert.ok(Math.abs(out.flick - 3125) < 1, "the coast starts at the speed the content had: " + out.flick);
  const up = S.newState();
  const ru = swipe(up, -20, 8, 16, 1000, cfg());
  assert.ok(S.advance(up, S.PHASE_END, 0, 0, ru.endMs + 8, cfg()).flick < -3000, "the same the other way");
});

test("a slow drag, or fingers that stopped before lifting, stays put", () => {
  const slow = S.newState();
  const r = swipe(slow, 1, 8, 16, 1000, cfg());   // about 156 px/s of content
  assert.strictEqual(S.advance(slow, S.PHASE_END, 0, 0, r.endMs + 8, cfg()).flick, 0, "under the threshold");

  const rested = S.newState();
  const r2 = swipe(rested, 20, 8, 16, 1000, cfg());
  assert.strictEqual(S.advance(rested, S.PHASE_END, 0, 0, r2.endMs + S.RELEASE_IDLE_MS + 1, cfg()).flick, 0,
    "a fast swipe that came to rest before the lift does not coast");
});

test("momentum off never coasts", () => {
  const st = S.newState();
  const off = cfg({ momentum: false });
  const r = swipe(st, 20, 8, 16, 1000, off);
  assert.strictEqual(S.advance(st, S.PHASE_END, 0, 0, r.endMs + 8, off).flick, 0);
});

test("the coast is capped, and a release is spent once", () => {
  const st = S.newState();
  const r = swipe(st, 400, 8, 8, 1000, cfg());
  const out = S.advance(st, S.PHASE_END, 0, 0, r.endMs + 4, cfg());
  assert.strictEqual(out.flick, S.COAST_MAX);
  assert.strictEqual(S.advance(st, S.PHASE_END, 0, 0, r.endMs + 6, cfg()).flick, 0, "a second end has nothing left");
});

test("updates that arrive bunched after a stall do not inflate the speed", () => {
  // The shell hitches for 60 ms and three queued updates land together. The
  // fingers did 20 px every 16 ms throughout: 3125 px/s of content. Speed
  // taken per event would read the bunched ones as 50,000 px/s and more.
  const st = S.newState();
  const c = cfg();
  S.advance(st, S.PHASE_BEGIN, 0, 0, 1000, c);
  for (const t of [1016, 1032, 1048]) S.advance(st, S.PHASE_UPDATE, 20, 240, t, c);
  for (const t of [1112, 1112, 1113]) S.advance(st, S.PHASE_UPDATE, 20, 240, t, c);
  const out = S.advance(st, S.PHASE_END, 0, 0, 1120, c);
  assert.ok(out.flick > 2000 && out.flick < 4000, "close to the real 3125 px/s: " + Math.round(out.flick));
});

test("one update is not a speed", () => {
  const st = S.newState();
  S.advance(st, S.PHASE_BEGIN, 0, 0, 1000, cfg());
  S.advance(st, S.PHASE_UPDATE, 200, 2400, 1016, cfg());
  assert.strictEqual(S.advance(st, S.PHASE_END, 0, 0, 1020, cfg()).flick, 0);
  assert.strictEqual(S.swipeSpeed([]), 0);
  assert.strictEqual(S.swipeSpeed([[1000, 50]]), 0);
});

test("a pause mid-swipe forgets the speed from before it", () => {
  const st = S.newState();
  const r = swipe(st, 20, 8, 16, 1000, cfg());
  // Fingers rest, then creep on by one pixel and lift.
  S.advance(st, S.PHASE_UPDATE, 1, 12, r.endMs + 400, cfg());
  assert.strictEqual(S.advance(st, S.PHASE_END, 0, 0, r.endMs + 408, cfg()).flick, 0);
});

test("reversing direction does not average the two ways into a coast", () => {
  const st = S.newState();
  const r = swipe(st, 20, 8, 16, 1000, cfg());
  let t = r.endMs;
  for (let i = 0; i < 2; i++) { t += 16; S.advance(st, S.PHASE_UPDATE, -20, -240, t, cfg()); }
  const out = S.advance(st, S.PHASE_END, 0, 0, t + 8, cfg());
  assert.ok(out.flick < -3000, "the coast follows the last direction at its own speed: " + out.flick);
});

test("anything that moves the view, and a new touch, stops a coast first", () => {
  assert.strictEqual(S.advance(S.newState(), S.PHASE_BEGIN, 0, 0, 1000, cfg()).stop, true);
  assert.strictEqual(S.advance(S.newState(), S.PHASE_UPDATE, 5, 60, 1000, cfg()).stop, true);
  assert.strictEqual(S.advance(S.newState(), S.PHASE_NONE, 15, 120, 1000, cfg()).stop, true);
  assert.strictEqual(S.advance(S.newState(), S.PHASE_END, 0, 0, 1000, cfg()).stop, false,
    "the end of a swipe must not cancel the coast it is about to start");
});

test("a move never leaves the scrollable range", () => {
  assert.strictEqual(S.clampY(100, 30, 0, 500), 70);
  assert.strictEqual(S.clampY(10, 30, 0, 500), 0, "stops at the top");
  assert.strictEqual(S.clampY(490, -30, 0, 500), 500, "stops at the bottom");
  assert.strictEqual(S.clampY(-40, 30, -50, 450), -50, "a ListView whose origin moved keeps its own range");
});

// ---------------------------------------------- every list has the handler

test("every scrolling view in the panel declares a WheelStep", () => {
  // The bug this guards: three of eleven lists had the tuned handler and the
  // rest fell back to Qt's own wheel handling, which on this desktop is 40% of
  // the fingers' travel and no momentum. A new list without one fails here.
  const root = path.join(__dirname, "..");
  const files = fs.readdirSync(root).filter((f) => f.endsWith(".qml") && f !== "WheelStep.qml");
  let views = 0;
  for (const f of files) {
    const lines = fs.readFileSync(path.join(root, f), "utf8").split("\n");
    for (let i = 0; i < lines.length; i++) {
      const open = /^(\s*)(ListView|Flickable) \{\s*$/.exec(lines[i]);
      if (!open) continue;
      views += 1;
      const indent = open[1];
      let end = i + 1;
      while (end < lines.length && lines[end] !== indent + "}") end += 1;
      const block = lines.slice(i, end);
      const id = block.map((l) => new RegExp("^" + indent + "  id: (\\w+)\\s*$").exec(l)).filter(Boolean)[0];
      assert.ok(id, f + ":" + (i + 1) + ": a scrolling view needs an id for its WheelStep to name");
      const step = new RegExp("^" + indent + "  WheelStep \\{ flick: " + id[1] + "; speed: root\\.scrollSpeed; momentum: root\\.scrollMomentum \\}\\s*$");
      assert.ok(block.some((l) => step.test(l)),
        f + ":" + (i + 1) + ": " + open[2] + " '" + id[1] + "' has no WheelStep of its own wired to the scroll preferences");
    }
  }
  assert.ok(views >= 11, "found the panel's scrolling views (" + views + ")");
});

test("the panel has one wheel handler, not a private copy", () => {
  const panel = fs.readFileSync(path.join(__dirname, "..", "Panel.qml"), "utf8");
  assert.ok(!/component WheelStep/.test(panel), "Panel.qml must use WheelStep.qml, which the sub-views can reach");
});

console.log(passed + " scroll tests passed");
