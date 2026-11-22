import QtQuick
import Quickshell
import Quickshell.Io
Scope {
  id: root
  // The parent has a real LD_PRELOAD constructor canary. Only a Python child
  // marks the private file; loading it in Quickshell itself does not mark it.
  Process {
    command: ["/usr/bin/python3", "-I", "-S", "-c", "import os; print('ISOLATED' if 'LD_PRELOAD' not in os.environ else 'LEAKED')"]
    clearEnvironment: true
    environment: ({ "LANG": "C", "LC_ALL": "C" })
    running: true
    stdout: StdioCollector { id: output }
    onExited: function(code) {
      console.log("LOADER_PROBE", code, output.text.trim())
      Qt.quit()
    }
  }
  Timer { interval: 3000; running: true; onTriggered: Qt.quit() }
}
