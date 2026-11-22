// User preferences for the kub0 panel.
//
// Omarchy renders NO settings UI for a plugin: `barWidget.schema` and
// `settingsForm` in manifest.json are written into the registry by shell.qml
// and never read back by anything, so a plugin that wants preferences has to
// own both the store and the editor. This module is the store's pure half —
// defaults, parsing, and clamping — kept out of the QML so it is testable
// under Node like the rest of js/.
//
// The file this serializes lives at ~/.config/kub0/ui.json and is expected
// to be hand-edited. Everything below therefore treats the parsed object as
// untrusted input: unknown keys are dropped and every known key is clamped to
// its domain on LOAD. Validating at the point of use instead would let a bad
// value reach a control that cannot represent it, leaving the user with no way
// to set it back.

var VIEWS = ["overview", "apps", "intel", "history", "endpoints", "settings"]
// "last" is not a view — it means "restore whichever view was open at close".
var STARTUP_VIEWS = ["last", "overview", "apps", "intel", "history", "endpoints"]

// Views that existed before Overview/Apps. Old ui.json files still carry them.
function aliasView(value) {
    if (value === "activity")
        return "overview"
    if (value === "protection")
        return "apps"
    return value
}

var SORT_KEYS = ["name", "activity", "connections", "blocked", "bandwidth"]
var FILTER_KEYS = ["all", "live", "blocked", "unknown"]
// How fast the lists scroll. js/Scroll.js holds what each one multiplies by.
var SCROLL_SPEEDS = ["slow", "normal", "fast", "fastest"]
// Look and feel. js/Ux.js holds what each one means; tests/test_ux.js keeps
// these lists and its tables the same.
var TEXT_SIZES = ["small", "normal", "large", "larger"]
var DENSITIES = ["compact", "normal", "roomy"]
var PANEL_WIDTHS = ["normal", "wide", "widest"]
var PANEL_HEIGHTS = ["normal", "tall", "full"]
var TIME_STYLES = ["mixed", "relative", "clock"]
var BYTE_UNITS = ["binary", "decimal"]

var SCHEMA_VERSION = 1

function defaults() {
    return {
        startupView: "overview",
        lastView: "overview",
        sortKey: "name",
        filterKey: "all",
        // Blocking is a privileged, kernel-enforced act dispatched from a
        // single click on a row that can move. Defaulting the confirmation ON
        // is the conservative choice: the cost of a wrong block (an app
        // silently loses the network) is much higher than one extra keypress.
        confirmBlocks: true,
        showWorldMap: true,
        captureEnabled: false,
        // A desktop notification for a watch-rule hit or a warning-level
        // indicator. On by default: the user wrote the watch rule, and a
        // warning is rare by construction (docs/INTEL.md).
        notifyIntel: true,
        // Send the /24 and /48 network keys of public destinations on the kub0
        // heartbeat so the org can answer "how many other endpoints reached
        // this". Off by default: it is the one thing in the Intel layer that
        // leaves the machine, and only an account holder can want it.
        shareDestinations: false,
        // How far a wheel notch or a touchpad swipe moves a list.
        scrollSpeed: "normal",
        // A list keeps moving when a touchpad swipe ends, and slows to a
        // stop. On by default: without it a long list is all finger work.
        scrollMomentum: true,
        // Text size and the room between rows, on top of the shell's own.
        textSize: "normal",
        density: "normal",
        // How wide and how tall the panel opens. The shell still fits it to
        // the screen.
        panelWidth: "normal",
        panelHeight: "normal",
        // How timestamps and byte counts read. The defaults are what the
        // panel always printed.
        timeStyle: "mixed",
        byteUnits: "binary"
    }
}

function oneOf(value, domain, fallback) {
    for (var i = 0; i < domain.length; i++) {
        if (domain[i] === value)
            return value
    }
    return fallback
}

function asBool(value, fallback) {
    if (value === true || value === false)
        return value
    return fallback
}

// Clamp an arbitrary object to a valid prefs object. Always returns a complete
// object — a caller never has to null-check an individual key.
function sanitize(raw) {
    var d = defaults()
    if (!raw || typeof raw !== "object")
        return d
    return {
        startupView: oneOf(aliasView(raw.startupView), STARTUP_VIEWS, d.startupView),
        lastView: oneOf(aliasView(raw.lastView), VIEWS, d.lastView),
        sortKey: oneOf(raw.sortKey, SORT_KEYS, d.sortKey),
        filterKey: oneOf(raw.filterKey, FILTER_KEYS, d.filterKey),
        confirmBlocks: asBool(raw.confirmBlocks, d.confirmBlocks),
        showWorldMap: asBool(raw.showWorldMap, d.showWorldMap),
        captureEnabled: asBool(raw.captureEnabled, d.captureEnabled),
        notifyIntel: asBool(raw.notifyIntel, d.notifyIntel),
        shareDestinations: asBool(raw.shareDestinations, d.shareDestinations),
        scrollSpeed: oneOf(raw.scrollSpeed, SCROLL_SPEEDS, d.scrollSpeed),
        scrollMomentum: asBool(raw.scrollMomentum, d.scrollMomentum),
        textSize: oneOf(raw.textSize, TEXT_SIZES, d.textSize),
        density: oneOf(raw.density, DENSITIES, d.density),
        panelWidth: oneOf(raw.panelWidth, PANEL_WIDTHS, d.panelWidth),
        panelHeight: oneOf(raw.panelHeight, PANEL_HEIGHTS, d.panelHeight),
        timeStyle: oneOf(raw.timeStyle, TIME_STYLES, d.timeStyle),
        byteUnits: oneOf(raw.byteUnits, BYTE_UNITS, d.byteUnits)
    }
}

// Parse the on-disk text. Never throws: a truncated or corrupt file must
// degrade to defaults rather than leaving the panel without preferences, and
// `error` lets the caller log the reason without blocking startup.
//
// An absent file arrives here as "" (FileView reports empty rather than
// failing), which is a normal first run and NOT an error.
function parse(raw) {
    var text = raw === null || raw === undefined ? "" : String(raw).trim()
    if (!text)
        return { prefs: defaults(), error: false, errorMessage: "", firstRun: true }
    var parsed = null
    try {
        parsed = JSON.parse(text)
    } catch (e) {
        return {
            prefs: defaults(),
            error: true,
            errorMessage: String(e && e.message ? e.message : e),
            firstRun: false
        }
    }
    if (!parsed || typeof parsed !== "object" || parsed instanceof Array) {
        return {
            prefs: defaults(),
            error: true,
            errorMessage: "settings root is not an object",
            firstRun: false
        }
    }
    return {
        prefs: sanitize(parsed),
        error: false,
        errorMessage: "",
        firstRun: false
    }
}

// Which text the settings are read from at startup. `text` is ui.json where
// it lives now and `legacyText` the one 0.4.6 and earlier kept in the old
// settings folder; each is null when that file does not exist. The file in
// the new place always wins, even when it is empty or broken: once it
// exists, the old one is history. `carried` says the settings came from the
// old folder and must be written to the new one.
function startupSource(text, legacyText) {
    if (typeof text === "string")
        return { raw: text, carried: false }
    if (typeof legacyText === "string" && legacyText.replace(/\s/g, "") !== "")
        return { raw: legacyText, carried: true }
    return { raw: "", carried: false }
}

function serialize(prefs) {
    var p = sanitize(prefs)
    p.version = SCHEMA_VERSION
    return JSON.stringify(p, null, 2) + "\n"
}

// The view the panel should open on. Kept here rather than in the QML so the
// "last" indirection has one definition and one test.
function openingView(prefs) {
    var p = sanitize(prefs)
    if (p.startupView === "last")
        return oneOf(p.lastView, VIEWS, "overview")
    return p.startupView
}

// Apply one change and return a NEW object. The panel binds to the prefs
// object, so mutating in place would not re-evaluate those bindings — the same
// same-reference trap that froze the row model (see test_row_sync.qml).
function withValue(prefs, key, value) {
    var next = sanitize(prefs)
    if (!next.hasOwnProperty(key))
        return next
    next[key] = value
    return sanitize(next)
}

function changed(a, b) {
    var x = sanitize(a)
    var y = sanitize(b)
    for (var k in x) {
        if (x[k] !== y[k])
            return true
    }
    return false
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        SCHEMA_VERSION: SCHEMA_VERSION,
        VIEWS: VIEWS,
        STARTUP_VIEWS: STARTUP_VIEWS,
        aliasView: aliasView,
        SORT_KEYS: SORT_KEYS,
        FILTER_KEYS: FILTER_KEYS,
        SCROLL_SPEEDS: SCROLL_SPEEDS,
        TEXT_SIZES: TEXT_SIZES,
        DENSITIES: DENSITIES,
        PANEL_WIDTHS: PANEL_WIDTHS,
        PANEL_HEIGHTS: PANEL_HEIGHTS,
        TIME_STYLES: TIME_STYLES,
        BYTE_UNITS: BYTE_UNITS,
        defaults: defaults,
        sanitize: sanitize,
        parse: parse,
        startupSource: startupSource,
        serialize: serialize,
        openingView: openingView,
        withValue: withValue,
        changed: changed
    }
}
