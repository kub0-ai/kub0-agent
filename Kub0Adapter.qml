import QtQuick
import Quickshell

// Isolates shell-injection and Quickshell APIs we're not 100% sure of.
// See ASSUMPTIONS.md. Service and BarWidget both instantiate this.
Item {
  id: adapter

  readonly property string pluginId: "ai.kub0.agent"
  readonly property string socketName: "kub0.sock"

  function pluginDir(manifest) {
    if (manifest && manifest.__sourceDir)
      return String(manifest.__sourceDir).replace(/\/$/, "")
    return localPluginDir()
  }

  function localPluginDir() {
    var u = String(Qt.resolvedUrl("."))
    if (u.indexOf("file://") === 0)
      u = u.substring(7)
    return u.replace(/\/$/, "")
  }

  function socketPath() {
    var xdg = ""
    try { xdg = Quickshell.env("XDG_RUNTIME_DIR") || "" } catch (e) { xdg = "" }
    if (xdg)
      return xdg.replace(/\/$/, "") + "/" + socketName
    var home = ""
    try { home = Quickshell.env("HOME") || "" } catch (e2) { home = "" }
    if (home)
      return home + "/.kub0.sock"
    return "/tmp/" + socketName
  }

  function stateDir() {
    var home = ""
    try { home = Quickshell.env("HOME") || "" } catch (e) { home = "" }
    var xdg = ""
    try { xdg = Quickshell.env("XDG_STATE_HOME") || "" } catch (e2) { xdg = "" }
    if (xdg)
      return xdg.replace(/\/$/, "") + "/kub0"
    if (home)
      return home + "/.local/state/kub0"
    return "/tmp/kub0-state"
  }

  // User preferences, as opposed to stateDir()'s machine-generated state.
  // Kept under XDG_CONFIG_HOME because ui.json is meant to be hand-edited and
  // carried between machines; nothing in it is reconstructible from the host.
  function configDir() {
    return configDirNamed("kub0")
  }

  // ~/.config/vallum: where 0.4.6 and earlier kept ui.json. Service reads it
  // once, when the file in configDir() does not exist yet, and never writes it.
  function legacyConfigDir() {
    return configDirNamed("vallum")
  }

  function configDirNamed(name) {
    var xdg = ""
    try { xdg = Quickshell.env("XDG_CONFIG_HOME") || "" } catch (e) { xdg = "" }
    if (xdg)
      return xdg.replace(/\/$/, "") + "/" + name
    var home = ""
    try { home = Quickshell.env("HOME") || "" } catch (e2) { home = "" }
    if (home)
      return home + "/.config/" + name
    return "/tmp/" + name + "-config"
  }

  function findService(bar, shell, pluginRegistry) {
    var sh = shell || (bar && bar.shell) || null
    if (sh && typeof sh.serviceFor === "function") {
      var s = sh.serviceFor(pluginId)
      if (s)
        return s
    }
    if (sh && typeof sh.firstPartyServiceFor === "function") {
      var s2 = sh.firstPartyServiceFor(pluginId)
      if (s2)
        return s2
    }
    return null
  }

  function binaryCandidates(dir, name) {
    var out = []
    if (dir) {
      out.push(dir + "/bin/" + name)
      out.push(dir + "/target/release/" + name)
      out.push(dir + "/target/debug/" + name)
    }
    out.push("/usr/lib/kub0/" + name)
    out.push("/usr/local/lib/kub0/" + name)
    out.push("/usr/local/bin/" + name)
    return out
  }

  function iconSource(desktopId, iconName) {
    try {
      if (desktopId && typeof DesktopEntries !== "undefined") {
        var id = String(desktopId).replace(/\.desktop$/, "")
        var entry = DesktopEntries.heuristicLookup ? DesktopEntries.heuristicLookup(id) : DesktopEntries.byId(id)
        if (entry && entry.icon && typeof Quickshell.iconPath === "function")
          return Quickshell.iconPath(entry.icon, true)
      }
      if (iconName && typeof Quickshell.iconPath === "function")
        return Quickshell.iconPath(iconName, true)
    } catch (e) { }
    return ""
  }

  function polkitEnabled(pluginRegistry) {
    try {
      if (pluginRegistry && typeof pluginRegistry.isEnabled === "function")
        return pluginRegistry.isEnabled("omarchy.polkit") === true
    } catch (e) { }
    return false
  }
}
