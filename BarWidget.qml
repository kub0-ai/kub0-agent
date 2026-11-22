import QtQuick
import qs.Ui
import qs.Commons
import "js/Health.js" as Health

BarWidget {
  id: root
  moduleName: "ai.kub0.agent"

  property var shell: null

  Kub0Adapter { id: adapter }

  property var vallum: null

  readonly property string monitoring: vallum ? String(vallum.monitoring || "") : ""
  readonly property bool enforcementPaused: vallum ? vallum.enforcementPaused === true : false
  readonly property string stateLabel: {
    if (!vallum)
      return "…"
    return Health.barPostureLabel(String(vallum.barLabel || "Off"), enforcementPaused)
  }
  readonly property bool dataCurrent: vallum ? vallum.dataCurrent === true : false

  // A wall, not a shield: kub0 is a rampart, and another bar widget
  // already renders the shield (U+F0483) in this same bar. The wall stays the "fully protecting" glyph;
  // the other three are what that rampart looks like when it is not holding.
  //
  // All four codepoints are verified present in JetBrainsMono Nerd Font, the face
  // fontconfig already resolves for the wall. A codepoint the face lacks renders as
  // tofu, which is strictly worse than no icon — do not add a state here without
  // checking `fc-list ":charset=<cp>"` first.
  readonly property string glyphWall: "󰟾"          // U+F07FE  enforcing
  readonly property string glyphShield: "󰒘"        // U+F0498  watching, not blocking
  readonly property string glyphShieldPaused: "󰒙"  // U+F0499  paused: rules held, none enforced
  readonly property string glyphShieldOff: "󰦞"     // U+F099E  off
  // U+F099E is md-shield_off. This was U+F099D, which the face resolves to
  // md-shield_LOCK — a padlock, i.e. the opposite reading on a bar that is
  // telling you protection is OFF. The block above checks each codepoint is
  // PRESENT (`fc-list :charset=`); presence is not identity. Resolve the name
  // too: `TTFont(face).getBestCmap()[0xF099E]`.
  readonly property string glyphShieldAlert: "󰻌"   // U+F0ECC  stale / demo / no service

  // The bar is one glyph now, so this binding carries the whole state readout.
  readonly property string glyph: {
    if (!vallum)
      return glyphShieldAlert
    var s = stateLabel.toLowerCase()
    if (s === "off")
      return glyphShieldOff
    if (monitoring === "stale" || monitoring === "unavailable" || monitoring === "demo")
      return glyphShieldAlert
    // Hollow, not the filled Idle shield: a pause leaves every block in place
    // and enforces none of them, which a glance at the bar should show.
    if (s === "paused")
      return glyphShieldPaused
    if (s === "on")
      return glyphWall
    // Idle, Wait, connecting, awaiting_snapshot: the service is up and
    // looking, it just is not blocking. `degraded` already dims the monitoring
    // states, so they do not need a louder glyph as well.
    return glyphShield
  }

  readonly property bool degraded: !vallum
    || !dataCurrent
    || monitoring === "demo"
    || monitoring === "unavailable"
    || monitoring === "connecting"
    || monitoring === "awaiting_snapshot"
    || monitoring === "stale"

  // A bar tooltip is a glance, not a paragraph. Two constraints force that:
  //
  // The shell's PanelToolTip renders `text` in a bare Text with no wrapMode and
  // no width cap (shell/Ui/PanelToolTip.qml), so whatever is returned here is
  // laid out on ONE line. A right-anchored widget then hangs it off the screen
  // edge. Until that component learns to wrap, length here is a layout bug, not
  // a style preference — so TOOLTIP_MAX is enforced, not merely intended.
  //
  // And every fact cut from this string already has a home one click away:
  // coverage renders in the panel ("Coverage: …", Panel.qml), and the keybind
  // offer renders there in full as its own card. The bar answers "what is the
  // state right now"; the panel answers "why, and what do I do". Restating the
  // panel in the bar is what produced the run-on this replaced —
  // `offerNote` is already a whole sentence ("Set Super+Alt+S to open kub0"),
  // so appending " to open the panel." to it read as
  // "…to open kub0 to open the panel."
  readonly property int tooltipMax: 40

  function glance(text) {
    var s = String(text || "kub0")
    return s.length > tooltipMax ? s.slice(0, tooltipMax - 1) + "…" : s
  }

  readonly property string tooltip: {
    if (!vallum)
      return glance("kub0—waiting for service")
    var detail = String(vallum.barTooltip || "kub0")
    // The state label used to sit on the bar beside the glyph. It does not any more,
    // so it has to lead here: glance() clamps from the RIGHT, so whatever leads is
    // what survives the tooltipMax truncation.
    if (stateLabel && detail.indexOf(stateLabel) !== 0)
      detail = stateLabel + " — " + detail
    return glance(detail)
  }

  function refreshService() {
    vallum = adapter.findService(root.bar, root.shell, null)
  }

  readonly property bool opened: panelLoader.item ? panelLoader.item.opened === true : false
  readonly property bool popoutSwitchClosing: panelLoader.item ? panelLoader.item.popoutSwitchClosing === true : false

  function open() {
    if (panelLoader.item)
      panelLoader.item.open()
  }

  function close() {
    if (panelLoader.item)
      panelLoader.item.close()
  }

  function toggle() {
    if (panelLoader.item)
      panelLoader.item.toggle()
  }

  function closeForPopoutSwitch() {
    if (panelLoader.item)
      panelLoader.item.closeForPopoutSwitch()
  }

  function injectPanel() {
    var target = panelLoader.item
    if (!target)
      return
    if ("bar" in target)
      target.bar = root.bar
    if ("anchorItem" in target)
      target.anchorItem = button
    if ("hostWidget" in target)
      target.hostWidget = root
    if ("vallum" in target)
      target.vallum = root.vallum
    if ("pluginDir" in target)
      target.pluginDir = root.vallum && root.vallum.pluginDir ? root.vallum.pluginDir : ""
  }

  implicitWidth: row.implicitWidth
  implicitHeight: row.implicitHeight

  onBarChanged: {
    refreshService()
    injectPanel()
  }
  onVallumChanged: injectPanel()

  Component.onCompleted: refreshService()

  Timer {
    interval: 400
    running: root.vallum === null
    repeat: true
    onTriggered: root.refreshService()
  }

  Loader {
    id: panelLoader
    active: true
    source: Qt.resolvedUrl("Panel.qml")
    visible: false
    onLoaded: {
      root.injectPanel()
      Qt.callLater(root.injectPanel)
    }
  }

  Row {
    id: row
    spacing: Style.space(4)

    WidgetButton {
      id: button
      bar: root.bar
      text: root.stateLabel
      labelVisible: false
      hasVisualContent: true
      dimmed: root.degraded
      tooltipText: root.tooltip
      fontFamily: root.bar && root.bar.fontFamily ? root.bar.fontFamily : Style.font.family
      fontSize: Style.font.body
      // Was: max(space(36), innerRow + space(16)) — sized to hold the WIDEST state
      // word ("Stale"/"Demo"), which is exactly what left dead space on the right
      // whenever the state was the short "On". One glyph is fixed-width, so the
      // widget can size to its real content without the bar reflowing on each change.
      fixedWidth: vertical ? -1 : Math.max(Style.space(24), glyphText.implicitWidth + Style.space(12))
      onPressed: function(buttonCode) {
        if (buttonCode === Qt.LeftButton || buttonCode === Qt.RightButton)
          root.toggle()
      }

      Text {
        id: glyphText
        anchors.centerIn: parent
        text: root.glyph
        color: button.foreground
        font.family: button.fontFamily
        font.pixelSize: button.fontSize
        renderType: Text.NativeRendering
      }
    }
  }
}
