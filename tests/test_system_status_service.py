#!/usr/bin/env python3
"""Run the real Service property/binding in private Quickshell, without startup I/O.
The private copy disables Component.onCompleted and automatic running bindings;
SystemStatus imports, property types and systemProtectionText stay verbatim.
"""
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
repo = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='vallum-service-status-') as tmp:
    root = Path(tmp)
    for name in ('js', 'tests/qml'):
        shutil.copytree(repo / name, root / name)
    for path in repo.glob('*.js'):
        shutil.copy(path, root / path.name)
    shutil.copy(repo / 'Kub0Adapter.qml', root / 'Kub0Adapter.qml')
    source = (repo / 'Service.qml').read_text()
    start = source.index('  Component.onCompleted: {')
    end = source.index('\n  function refreshSystemDiagnostics()', start)
    source = source[:start] + source[end:]
    source = re.sub(r'(?m)^(\s*)running:.*$', r'\1running: false', source)
    (root / 'Service.qml').write_text(source)
    harness = (root / 'tests/qml/system-status-service.qml').read_text()
    (root / 'status-test.qml').write_text(harness.replace('../../js/', 'js/').replace('import "../.."', 'import "."'))
    env = dict(os.environ, QT_QPA_PLATFORM='offscreen', XDG_RUNTIME_DIR=tmp,
               XDG_CACHE_HOME=tmp, QT_QPA_PLATFORMTHEME='generic',
               QT_QUICK_BACKEND='software', XDG_CURRENT_DESKTOP='')
    run = subprocess.run(['quickshell', '-p', str(root / 'status-test.qml')],
                         env=env, capture_output=True, text=True, timeout=15)
    output = run.stdout + run.stderr
    print(output)
    assert run.returncode == 0 and 'SERVICE_STATUS_PASS' in output and 'SERVICE_STATUS_FAIL' not in output
print('private actual Service clock and binding passed')
