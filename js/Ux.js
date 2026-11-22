// Look and feel of the kub0 panel: the choices Settings offers for text size,
// density and panel size, and what each one means in numbers.
//
// Pure, so it runs under Node like the rest of js/. js/Prefs.js stores the
// `value` of each choice and clamps a hand edit to these lists.
//
// The panel takes its sizes from the shell's kit (Style.font.*, Style.space):
// 12 px body text and 10 px captions unless the shell is themed otherwise.
// Everything here multiplies those, so a shell-wide change still carries
// through and these choices sit on top of it.

// Every table is ordered smallest first; Settings shows them in this order.
var TEXT_SIZES = [
    { value: "small", label: "Small", factor: 0.9 },
    { value: "normal", label: "Normal", factor: 1 },
    { value: "large", label: "Large", factor: 1.15 },
    { value: "larger", label: "Larger", factor: 1.3 }
]

// How much room rows and sections get: the gaps between things, never the
// things themselves.
var DENSITIES = [
    { value: "compact", label: "Compact", factor: 0.6 },
    { value: "normal", label: "Normal", factor: 1 },
    { value: "roomy", label: "Roomy", factor: 1.4 }
]

// In the kit's spacing units. The kit fits whatever is asked for to the
// screen, so "full" is simply more than any screen has.
var PANEL_WIDTHS = [
    { value: "normal", label: "Normal", units: 560 },
    { value: "wide", label: "Wide", units: 720 },
    { value: "widest", label: "Widest", units: 900 }
]
var PANEL_HEIGHTS = [
    { value: "normal", label: "Normal", units: 520 },
    { value: "tall", label: "Tall", units: 760 },
    { value: "full", label: "Full screen", units: 10000 }
]

// How a timestamp reads. "mixed" is the panel's own choice and the default:
// how long ago for what is live, a full date for what is logged.
var TIME_STYLES = [
    { value: "mixed", label: "Mixed" },
    { value: "relative", label: "How long ago" },
    { value: "clock", label: "Clock time" }
]

// How a byte count reads. Binary is what the panel always printed.
var BYTE_UNITS = [
    { value: "binary", label: "KiB, MiB" },
    { value: "decimal", label: "kB, MB" }
]

function values(table) {
    var out = []
    for (var i = 0; i < table.length; i++)
        out.push(table[i].value)
    return out
}

// The row for `value`, or the "normal" row when the value is not one of ours.
function choice(table, value) {
    var normal = table[0]
    for (var i = 0; i < table.length; i++) {
        if (table[i].value === value)
            return table[i]
        if (table[i].value === "normal")
            normal = table[i]
    }
    return normal
}

function textFactor(value) { return choice(TEXT_SIZES, value).factor }
function densityFactor(value) { return choice(DENSITIES, value).factor }
function panelWidthUnits(value) { return choice(PANEL_WIDTHS, value).units }
function panelHeightUnits(value) { return choice(PANEL_HEIGHTS, value).units }

function pad2(n) { return (n < 10 ? "0" : "") + n }

var MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

// "3h ago", "in 25m". One spelling for every view: seconds under a minute,
// minutes under an hour, hours under a day, then days.
function relativeTime(ts, now) {
    if (typeof ts !== "number" || !isFinite(ts) || ts <= 0)
        return "unknown"
    var s = Math.round(((typeof now === "number" ? now : Date.now()) - ts) / 1000)
    if (s === 0)
        return "just now"
    var a = Math.abs(s)
    var span = a < 60 ? a + "s"
        : a < 3600 ? Math.round(a / 60) + "m"
        : a < 86400 ? Math.round(a / 3600) + "h"
        : Math.round(a / 86400) + "d"
    return s > 0 ? span + " ago" : "in " + span
}

// The shortest clock reading that is still unambiguous: the time for today,
// the day for this year, the full date before that. Local time, 24 hours.
function clockTime(ts, now) {
    if (typeof ts !== "number" || !isFinite(ts) || ts <= 0)
        return "unknown"
    var d = new Date(ts)
    var n = new Date(typeof now === "number" ? now : Date.now())
    var hm = pad2(d.getHours()) + ":" + pad2(d.getMinutes())
    if (d.getFullYear() === n.getFullYear() && d.getMonth() === n.getMonth() && d.getDate() === n.getDate())
        return hm + ":" + pad2(d.getSeconds())
    if (d.getFullYear() === n.getFullYear())
        return MONTHS[d.getMonth()] + " " + d.getDate() + " " + hm
    return d.getFullYear() + "-" + pad2(d.getMonth() + 1) + "-" + pad2(d.getDate()) + " " + hm
}

// Powers of 1000: kB, MB. Same shape as the binary form in js/Traffic.js.
function decimalBytes(n) {
    if (typeof n !== "number" || !isFinite(n) || n < 0)
        return "unknown"
    var units = ["B", "kB", "MB", "GB", "TB"]
    var u = 0
    while (n >= 1000 && u < units.length - 1) { n /= 1000; u++ }
    return (u ? n.toFixed(1) : Math.round(n)) + " " + units[u]
}

// The formatter for a preference, or null when the preference is the panel's
// own default. Null is the point: every formatter in js/ takes this object as
// an optional last argument and prints what it always printed without one.
function timeFormatter(timeStyle) {
    return timeStyle === "relative" ? relativeTime : timeStyle === "clock" ? clockTime : null
}
function bytesFormatter(byteUnits) {
    return byteUnits === "decimal" ? decimalBytes : null
}

// What the panel and its sub-views lay themselves out with.
//   caption .. display   font sizes in pixels: the kit's, times the text size
//   gap                  multiply a spacing by this before Style.space()
//   time(ts, now)        a timestamp as text, or null for the panel's default
//   bytes(n)             a byte count as text, or null for the panel's default
// `fonts` is the kit's Style.font (or any object with the same five sizes).
// A missing size falls back to the kit's defaults so a stub kit still works.
function metrics(fonts, textSize, density, timeStyle, byteUnits) {
    var f = fonts || {}
    var t = textFactor(textSize)
    function px(base, fallback) {
        var n = typeof base === "number" && base > 0 ? base : fallback
        return Math.max(1, Math.round(n * t))
    }
    return {
        text: t,
        gap: densityFactor(density),
        caption: px(f.caption, 10),
        bodySmall: px(f.bodySmall, 11),
        body: px(f.body, 12),
        subtitle: px(f.subtitle, 13),
        display: px(f.display, 24),
        time: timeFormatter(timeStyle),
        bytes: bytesFormatter(byteUnits)
    }
}

if (typeof module !== "undefined" && module.exports) {
    module.exports = {
        TEXT_SIZES: TEXT_SIZES,
        DENSITIES: DENSITIES,
        PANEL_WIDTHS: PANEL_WIDTHS,
        PANEL_HEIGHTS: PANEL_HEIGHTS,
        TIME_STYLES: TIME_STYLES,
        BYTE_UNITS: BYTE_UNITS,
        relativeTime: relativeTime,
        clockTime: clockTime,
        decimalBytes: decimalBytes,
        timeFormatter: timeFormatter,
        bytesFormatter: bytesFormatter,
        values: values,
        choice: choice,
        textFactor: textFactor,
        densityFactor: densityFactor,
        panelWidthUnits: panelWidthUnits,
        panelHeightUnits: panelHeightUnits,
        metrics: metrics
    }
}
