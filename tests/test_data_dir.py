#!/usr/bin/env python3
"""A database is read from the data dir the daemon was given, and nowhere else.

The loaders had a third place to look: data/geoip/<name> under the working
directory. A system daemon's working directory is /, so one whose data dir
had no database would read /data/geoip/..., a path it does not own, and
build an org's country and network rules from it, with nothing in its log to
say where the database had come from. The unit test that says "the enforcer
applies nothing without the country database" only passed because cargo runs
tests from daemon/, where there is no data/geoip: run from the repository
root it failed every time.

Here the daemon is started in a directory that has both databases under
data/geoip, with a data dir that has neither. It must come up without them,
and say so: before the fix it loaded them and logged neither line.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from test_traffic_history_live import Client, BIN, ROOT

NO_COUNTRY = "kub0d: no MMDB loaded; country/arcs will be empty until {}/geoip/dbip-country-lite.mmdb is present"
NO_ASN = "kub0d: no ASN database; block rules will not be enforced until {}/geoip/dbip-asn-lite.mmdb is present"


def start(td, cwd, data_dir, tag):
    """Run the daemon in `cwd` with `data_dir` until it serves a snapshot;
    return what it wrote to stderr."""
    private = Path(td) / tag
    private.mkdir()
    env = dict(os.environ, HOME=str(private), XDG_STATE_HOME=str(private), XDG_CONFIG_HOME=str(private),
               XDG_RUNTIME_DIR=str(private), KUB0_NO_PTR="1")
    log_path = private / "daemon.log"
    with open(log_path, "w") as log:
        p = subprocess.Popen([str(BIN), "--socket", str(private / "ipc"), "--interval-ms", "150",
                              "--data-dir", str(data_dir)],
                             cwd=str(cwd), env=env, stdout=subprocess.DEVNULL, stderr=log)
        ipc = None
        try:
            ipc = Client(private / "ipc")
            ipc.until(lambda v: v.get("type") == "snapshot")
            assert p.poll() is None, "the daemon runs without a database"
        except BaseException:
            # A daemon that never came up says why in its own log.
            log.flush()
            print("daemon log:\n" + log_path.read_text())
            raise
        finally:
            if ipc:
                ipc.sock.close()
            p.terminate()
            p.wait(timeout=5)
    return log_path.read_text()


with tempfile.TemporaryDirectory(prefix="kub0-data-dir-") as td:
    cwd = Path(td) / "cwd"
    geo = cwd / "data" / "geoip"
    geo.mkdir(parents=True)
    for name in ("dbip-country-lite.mmdb", "dbip-asn-lite.mmdb"):
        shutil.copy(ROOT / "data" / "geoip" / name, geo / name)
    empty = Path(td) / "empty"
    empty.mkdir()

    # The databases are under the working directory and not in the data dir.
    said = start(td, cwd, empty, "elsewhere")
    assert NO_COUNTRY.format(empty) in said, "a country database outside the data dir was read:\n" + said
    assert NO_ASN.format(empty) in said, "an ASN database outside the data dir was read:\n" + said

    # The same files, as the data dir: they load (so the lines above are about
    # where they were, and not about files the daemon cannot read at all).
    said = start(td, cwd, cwd / "data", "given")
    assert "no MMDB loaded" not in said and "no ASN database" not in said, said

    print(json.dumps(dict(databasesOutsideTheDataDirIgnored=True, sameFilesLoadAsTheDataDir=True)))
