# Stub UI kit for loading the panel's sub-views without Omarchy

`tests/qml/run-runtime.sh` loads the panel through quickshell against the real
shell at /usr/share/omarchy/shell. This directory is the other half: a minimal
`qs.Commons`, `qs.Ui` and `Quickshell` import path with just the members the
sub-views reference (Color, Style, Button, Dropdown, PanelSeparator,
Quickshell.clipboardText), so `IntelView.qml`, `HistoryView.qml`,
`ConnectionEvidence.qml` and `DestinationRules.qml` can be instantiated by the
plain Qt6 `qml` runtime on a machine with neither Omarchy nor quickshell
installed. It proves the QML parses, every binding resolves against the real
js/ modules, and the delegates render rows from fixture data. It does not
prove the views look right in the shell; that is still the runtime harness.

Run: `/usr/lib/qt6/bin/qml -I tests/qml/kitstub tests/qml/kit-harness.qml`
(tests/run.sh does this when a Qt6 runtime is present).
