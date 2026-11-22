"use strict";
const assert = require("assert");
const fs = require("fs");
const path = require("path");
const U = require("../js/Ux.js");
const P = require("../js/Prefs.js");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log("  ok  " + name);
}

const KIT = { caption: 10, bodySmall: 11, body: 12, subtitle: 13, display: 24 };
const ROOT = path.join(__dirname, "..");
// The panel's own files. The bar widget sits in the bar and keeps the shell's sizes.
const PANEL_FILES = ["Panel.qml", "IntelView.qml", "HistoryView.qml", "EndpointsView.qml",
  "ConnectionEvidence.qml", "DestinationRules.qml"];
function lines(file) {
  return fs.readFileSync(path.join(ROOT, file), "utf8").split("\n");
}

// ------------------------------------------------------------ the choices

test("the store and the tables offer the same choices, in the same order", () => {
  assert.deepStrictEqual(U.values(U.TEXT_SIZES), P.TEXT_SIZES);
  assert.deepStrictEqual(U.values(U.DENSITIES), P.DENSITIES);
  assert.deepStrictEqual(U.values(U.PANEL_WIDTHS), P.PANEL_WIDTHS);
  assert.deepStrictEqual(U.values(U.PANEL_HEIGHTS), P.PANEL_HEIGHTS);
});

test("every table runs smallest first and has a normal that changes nothing", () => {
  for (const [table, key] of [[U.TEXT_SIZES, "factor"], [U.DENSITIES, "factor"],
    [U.PANEL_WIDTHS, "units"], [U.PANEL_HEIGHTS, "units"]]) {
    for (let i = 1; i < table.length; i++)
      assert.ok(table[i][key] > table[i - 1][key], table[i].value + " is more than " + table[i - 1].value);
    for (const row of table) assert.ok(row.label && row.label.length > 0, row.value + " has a label to show");
    assert.ok(table.some((r) => r.value === "normal"), "a normal row");
  }
  assert.strictEqual(U.textFactor("normal"), 1);
  assert.strictEqual(U.densityFactor("normal"), 1);
  assert.strictEqual(U.panelWidthUnits("normal"), 560, "the width the panel always had");
  assert.strictEqual(U.panelHeightUnits("normal"), 520, "the height the panel always had");
});

test("a value that is not on the list is normal", () => {
  assert.strictEqual(U.textFactor("enormous"), 1);
  assert.strictEqual(U.densityFactor(undefined), 1);
  assert.strictEqual(U.panelWidthUnits(42), 560);
  assert.strictEqual(U.panelHeightUnits(""), 520);
});

test("the store defaults to normal everywhere and clamps a hand edit", () => {
  const d = P.defaults();
  for (const k of ["textSize", "density", "panelWidth", "panelHeight"])
    assert.strictEqual(d[k], "normal", k);
  assert.strictEqual(P.sanitize({ textSize: "huge" }).textSize, "normal");
  assert.strictEqual(P.sanitize({ textSize: "larger" }).textSize, "larger");
  assert.strictEqual(P.sanitize({ density: 2 }).density, "normal");
  assert.strictEqual(P.sanitize({ density: "compact" }).density, "compact");
  assert.strictEqual(P.sanitize({ panelWidth: "narrow" }).panelWidth, "normal", "not a choice the panel offers");
  assert.strictEqual(P.sanitize({ panelHeight: "full" }).panelHeight, "full");
  const next = P.withValue(P.withValue(d, "textSize", "large"), "panelWidth", "widest");
  const round = P.parse(P.serialize(next)).prefs;
  assert.strictEqual(round.textSize, "large");
  assert.strictEqual(round.panelWidth, "widest");
});

// -------------------------------------------------------------- the sizes

test("normal is the kit's sizes, untouched", () => {
  const m = U.metrics(KIT, "normal", "normal");
  assert.deepStrictEqual(m, { text: 1, gap: 1, caption: 10, bodySmall: 11, body: 12, subtitle: 13, display: 24,
    time: null, bytes: null });
});

test("a text size scales every font and keeps their order", () => {
  for (const size of U.values(U.TEXT_SIZES)) {
    const m = U.metrics(KIT, size, "normal");
    assert.strictEqual(m.body, Math.round(12 * U.textFactor(size)), size + " body");
    assert.ok(m.caption <= m.bodySmall && m.bodySmall <= m.body && m.body <= m.subtitle && m.subtitle < m.display,
      size + " keeps caption <= bodySmall <= body <= subtitle < display");
    assert.strictEqual(m.gap, 1, "text size leaves the gaps alone");
  }
  assert.ok(U.metrics(KIT, "larger", "normal").caption > U.metrics(KIT, "small", "normal").body,
    "the range is wide enough to matter: the largest caption beats the smallest body text");
});

test("density moves the gaps and never the text", () => {
  for (const d of U.values(U.DENSITIES)) {
    const m = U.metrics(KIT, "normal", d);
    assert.strictEqual(m.gap, U.densityFactor(d));
    assert.strictEqual(m.body, 12);
  }
});

test("sizes follow the shell: a themed kit scales through", () => {
  const big = { caption: 12, bodySmall: 13, body: 14, subtitle: 16, display: 28 };
  assert.strictEqual(U.metrics(big, "large", "normal").body, Math.round(14 * 1.15));
});

test("a kit that reports nothing still gives usable sizes", () => {
  const m = U.metrics(undefined, "normal", "normal");
  assert.strictEqual(m.body, 12);
  assert.strictEqual(U.metrics({ body: 0 }, "normal", "normal").body, 12);
  assert.ok(U.metrics(KIT, "small", "compact").caption >= 1);
});

// ------------------------- the panel's files go through the two settings

test("no text in the panel takes its size straight from the kit", () => {
  // A text that reads Style.font.body ignores the Text size setting. The
  // family is the kit's to give; the five sizes are not.
  for (const f of PANEL_FILES) {
    lines(f).forEach((l, i) => {
      assert.ok(!/Style\.font\.(caption|bodySmall|body|subtitle|display)\b/.test(l),
        f + ":" + (i + 1) + ": use root.ux.<size>, not the kit's font size: " + l.trim());
    });
  }
});

test("no gap in the panel skips the density setting", () => {
  // Spacing, margins, paddings and the padding added to a row's own height are
  // gaps. Widths, fixed heights and indents are sizes and stay as they are.
  const gap = /^\s*(?:readonly property int )?(spacing|anchors\.margins|anchors\.topMargin|anchors\.bottomMargin|topPadding|bottomPadding|verticalPadding|padTight|padGroup|padSection|padEdge): Style\.space\(\d+\)/;
  const rowPad = /^\s*height: .*implicitHeight \+ Style\.space\(\d+\)/;
  let scaled = 0;
  for (const f of PANEL_FILES) {
    lines(f).forEach((l, i) => {
      assert.ok(!gap.test(l) && !rowPad.test(l),
        f + ":" + (i + 1) + ": a gap must be Style.space(N * root.ux.gap): " + l.trim());
      if (/Style\.space\(\d+ \* root\.ux\.gap\)/.test(l)) scaled += 1;
    });
  }
  assert.ok(scaled >= 100, "the gaps are there to check (" + scaled + ")");
});

test("every kit control that takes a text size is given the panel's", () => {
  // Button and PanelSectionHeader have fontSize; TextField has font.pixelSize.
  // Dropdown and PanelHero take none, which is why they are not listed.
  const want = { Button: /^\s*fontSize: root\.ux\.\w+/, PanelSectionHeader: /^\s*fontSize: root\.ux\.\w+/,
    TextField: /^\s*font\.pixelSize: root\.ux\.\w+/, ButtonGroup: /^\s*fontSize: root\.ux\.\w+/ };
  let seen = 0;
  for (const f of PANEL_FILES) {
    const ls = lines(f);
    for (let i = 0; i < ls.length; i++) {
      const open = /^(\s*)(Button|PanelSectionHeader|TextField|ButtonGroup) \{\s*$/.exec(ls[i]);
      if (open) {
        seen += 1;
        let end = i + 1;
        while (end < ls.length && ls[end] !== open[1] + "}") end += 1;
        const own = ls.slice(i + 1, end).filter((l) => l.startsWith(open[1] + "  ") && !l.startsWith(open[1] + "   "));
        assert.ok(own.some((l) => want[open[2]].test(l)),
          f + ":" + (i + 1) + ": " + open[2] + " has no text size from root.ux");
        continue;
      }
      const inline = /\bButton \{[^}]*\}/.exec(ls[i]);
      if (inline) {
        seen += 1;
        assert.ok(/fontSize: root\.ux\.\w+/.test(inline[0]), f + ":" + (i + 1) + ": a one-line Button has no text size from root.ux");
      }
    }
  }
  assert.ok(seen >= 50, "the controls are there to check (" + seen + ")");
});

test("every sub-view takes the sizes from the panel, and the panel hands them down", () => {
  const panel = fs.readFileSync(path.join(ROOT, "Panel.qml"), "utf8");
  assert.ok(panel.includes("readonly property var ux: Ux.metrics(Style.font, prefs.textSize, prefs.density, prefs.timeStyle, prefs.byteUnits)"),
    "Panel.qml computes ux from the preferences");
  for (const f of PANEL_FILES.slice(1)) {
    const text = fs.readFileSync(path.join(ROOT, f), "utf8");
    assert.ok(text.includes('\n  property var ux: Ux.metrics(Style.font, "normal", "normal", "mixed", "binary")\n'), f + " declares ux");
    const name = f.replace(".qml", "");
    const use = new RegExp("^(\\s*)" + name + " \\{\\n(?:\\1  .*\\n|\\n)*?\\1  ux: root\\.ux\\n", "m");
    assert.ok(use.test(panel), "Panel.qml gives " + name + " its ux");
  }
});

test("the panel asks the shell for the size the preferences name", () => {
  const panel = fs.readFileSync(path.join(ROOT, "Panel.qml"), "utf8");
  assert.ok(panel.includes("contentWidth: panel.fittedContentWidth(Style.space(Ux.panelWidthUnits(root.prefs.panelWidth)))"));
  assert.ok(panel.includes("contentHeight: panel.fittedContentHeight(Style.space(Ux.panelHeightUnits(root.prefs.panelHeight)))"));
});

console.log(passed + " ux tests passed");
