#!/usr/bin/env python3
"""Private LD_PRELOAD constructor canary; no service/account/firewall access."""
import os
from pathlib import Path
import subprocess
import tempfile
with tempfile.TemporaryDirectory(prefix='vallum-loader-') as tmp:
    root = Path(tmp)
    marker = root / 'loaded'
    source = root / 'probe.c'
    library = root / 'probe.so'
    source.write_text(r'''
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
__attribute__((constructor)) static void probe(void) {
 char exe[4096]={0}; readlink("/proc/self/exe",exe,sizeof(exe)-1);
 if(strstr(exe,"python")) {
  const char *p=getenv("VALLUM_LOADER_MARKER");
  if(p) { int fd=open(p,O_WRONLY|O_CREAT,0600); if(fd>=0) close(fd); }
 }
}
''')
    subprocess.run(['cc','-shared','-fPIC','-o',str(library),str(source)],check=True)
    env = dict(os.environ, LD_PRELOAD=str(library), VALLUM_LOADER_MARKER=str(marker))
    subprocess.run(['/usr/bin/python3','-I','-S','-c','pass'],env=env,check=True)
    assert marker.exists(), 'positive loader control did not execute constructor'
    marker.unlink()
    env.update(QT_QPA_PLATFORM='offscreen', XDG_RUNTIME_DIR=tmp, XDG_CACHE_HOME=tmp, QT_QPA_PLATFORMTHEME='generic', QT_QUICK_BACKEND='software', XDG_CURRENT_DESKTOP='')
    run = subprocess.run(['quickshell','-p',str(Path('tests/qml/system-status-loader.qml').resolve())],env=env,capture_output=True,text=True,timeout=10)
    print(run.stdout,run.stderr)
    assert run.returncode == 0
    assert 'LOADER_PROBE 0 ISOLATED' in run.stdout + run.stderr
    assert not marker.exists(), 'isolated child executed inherited loader canary'
print('private inherited loader isolation passed')
