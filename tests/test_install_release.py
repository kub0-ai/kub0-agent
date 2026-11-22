#!/usr/bin/env python3
"""scripts/install-release.sh, run for real against a release made of stubs.

The release is a directory of files (file://) or a local plain-HTTP server,
`uname` and `id` are stubs first on PATH, the program that would become root
is a stub named by KUB0_INSTALL_SUDO, and the "kub0" in the tarball is a shell
script that records how it was called. Nothing is downloaded from outside this
machine, nothing runs as root, and no kub0 binary is executed.
"""

import functools
import hashlib
import http.server
import io
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "install-release.sh")
VERSION = json.load(open(os.path.join(ROOT, "manifest.json"), encoding="utf-8"))["version"]
X86 = "x86_64-unknown-linux-musl"


class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


def stub(path, body):
    with open(path, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)


def tarball(path, name, marker, with_kub0=True):
    """A release tarball whose kub0 writes its arguments to `marker`."""
    with tarfile.open(path, "w:gz") as t:
        def add(member, data, mode):
            info = tarfile.TarInfo(member)
            info.size = len(data)
            info.mode = mode
            t.addfile(info, io.BytesIO(data))
        if with_kub0:
            add(f"{name}/kub0", f'#!/bin/sh\necho "$@" > "{marker}"\n'.encode(), 0o755)
        add(f"{name}/INSTALL.md", b"stub\n", 0o644)


def sha(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def release(tmp, target, label, version=VERSION, **kw):
    """A release directory for `target`; returns (dir, marker, tarball name)."""
    d = os.path.join(tmp, label)
    os.makedirs(d)
    name = f"kub0-agent-{version}-{target}"
    marker = os.path.join(tmp, label + ".ran")
    tar = os.path.join(d, name + ".tar.gz")
    tarball(tar, name, marker, **kw)
    with open(os.path.join(d, f"SHA256SUMS-{target}"), "w", encoding="utf-8") as f:
        f.write(f"{sha(tar)}  {name}.tar.gz\n{'0' * 64}  kub0-{target}\n")
    return d, marker, name


def stubs(tmp, machine):
    """A bin dir whose uname reports `machine` and whose id reports the
    groups the test names, plus the stand-in for sudo (not on PATH)."""
    bindir = os.path.join(tmp, "stubs-" + machine)
    if not os.path.isdir(bindir):
        os.makedirs(bindir)
        stub(os.path.join(bindir, "uname"), f'[ "$1" = "-m" ] && echo {machine} || exec /usr/bin/uname "$@"\n')
        stub(os.path.join(bindir, "id"),
             'if [ "$1" = "-un" ]; then echo alice; exit 0; fi\n'
             'if [ "$1" = "-Gn" ] && [ -n "$2" ]; then echo "$ID_ACCOUNT"; exit 0; fi\n'
             'if [ "$1" = "-Gn" ]; then echo "$ID_SESSION"; exit 0; fi\nexit 2\n')
        # A sudo on PATH must never be the one that runs: it says so if it is.
        stub(os.path.join(bindir, "sudo"), f'echo path-sudo > "{tmp}/path-sudo-ran"\nexec "$@"\n')
    fake_sudo = os.path.join(tmp, "as-root")
    if not os.path.exists(fake_sudo):
        # Runs the command as the caller: the test never has root.
        stub(fake_sudo, f'echo "$@" >> "{tmp}/as-root.log"\nexec "$@"\n')
    return bindir, fake_sudo


def run(tmp, base, machine="x86_64", script=SCRIPT, session="alice wheel", account="alice wheel kub0", env=None, path=None):
    bindir, fake_sudo = stubs(tmp, machine)
    work = tempfile.mkdtemp(dir=tmp, prefix="work-")
    e = dict(os.environ, PATH=path or (bindir + os.pathsep + os.environ["PATH"]), KUB0_INSTALL_SUDO=fake_sudo,
             TMPDIR=work, ID_SESSION=session, ID_ACCOUNT=account)
    e.pop("KUB0_RELEASE_BASE", None)
    if base is not None:
        e["KUB0_RELEASE_BASE"] = base if "://" in base else "file://" + base
    e.update(env or {})
    r = subprocess.run([shutil.which("bash"), script], capture_output=True, text=True, env=e)
    r.left_behind = os.listdir(work)
    return r


def main():
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        # The good path, on both architectures a release is built for.
        for machine, target in (("x86_64", X86), ("aarch64", "aarch64-unknown-linux-musl")):
            d, marker, name = release(tmp, target, "good-" + machine)
            r = run(tmp, d, machine)
            assert r.returncode == 0, r.stdout + r.stderr
            assert open(marker, encoding="utf-8").read().strip() == "install", "kub0 is run as `kub0 install`, nothing else"
            assert "checksum ok" in r.stdout and f"kub0 {VERSION} for {target}" in r.stdout, r.stdout
            assert r.left_behind == [], f"the download and the unpacked release are removed: {r.left_behind}"
        out["installsOnBothArchitectures"] = True

        # The step that becomes root is run by path, never found through PATH.
        assert not os.path.exists(os.path.join(tmp, "path-sudo-ran")), "a sudo found on PATH ran"
        log = open(os.path.join(tmp, "as-root.log"), encoding="utf-8").read().splitlines()
        assert len(log) == 2 and all(line.endswith(f"/kub0-agent-{VERSION}-{t}/kub0 install") for line, t in zip(log, (X86, "aarch64-unknown-linux-musl"))), log
        text = open(SCRIPT, encoding="utf-8").read()
        assert 'sudo="${KUB0_INSTALL_SUDO:-/usr/bin/sudo}"' in text and '"$sudo" "$tmp/$name/kub0" install' in text
        out["rootStepIsByPath"] = True

        # What it says afterwards depends on the session, not on a fixed line.
        d, marker, name = release(tmp, X86, "said")
        said = run(tmp, d, session="alice wheel kub0", account="alice wheel kub0").stdout
        assert "already in the kub0 group" in said and "Log out" not in said, said
        said = run(tmp, d, session="alice wheel", account="alice wheel kub0").stdout
        assert "Log out and back in once" in said and "reboot" in said, said
        said = run(tmp, d, session="alice kub0-admins", account="alice kub0-admins").stdout
        assert "not in the kub0 group" in said and "sudo gpasswd -a alice kub0" in said, said
        out["closingLineMatchesTheSession"] = True

        # A tarball that is not the one the checksum file lists never runs.
        d, marker, name = release(tmp, X86, "tampered")
        tarball(os.path.join(d, name + ".tar.gz"), name, marker + ".other")
        r = run(tmp, d)
        assert r.returncode == 1 and "does not match its checksum" in r.stderr, r.stdout + r.stderr
        assert not os.path.exists(marker) and not os.path.exists(marker + ".other"), "a tampered release ran"
        assert r.left_behind == [], f"a refused download is removed too: {r.left_behind}"
        out["tamperedTarballRefused"] = True

        # A checksum file that does not name the tarball is not a pass.
        d, marker, name = release(tmp, X86, "unlisted")
        sums = os.path.join(d, f"SHA256SUMS-{X86}")
        good = sha(os.path.join(d, name + ".tar.gz"))
        with open(sums, "w", encoding="utf-8") as f:
            f.write(f"{'0' * 64}  something-else.tar.gz\n")
        r = run(tmp, d)
        assert r.returncode == 1 and "does not list" in r.stderr, r.stdout + r.stderr
        assert not os.path.exists(marker)
        # Nor is one that names it twice with different sums.
        with open(sums, "w", encoding="utf-8") as f:
            f.write(f"{good}  {name}.tar.gz\n{'0' * 64}  {name}.tar.gz\n")
        r = run(tmp, d)
        assert r.returncode == 1 and "does not list" in r.stderr and not os.path.exists(marker), r.stdout + r.stderr
        out["unlistedOrAmbiguousChecksumRefused"] = True

        # The name is matched whole. A release that also lists a signature or
        # a longer name beside the tarball still has exactly one line for it;
        # and a line for the longer name alone is not a line for the tarball.
        with open(sums, "w", encoding="utf-8") as f:
            f.write(f"{'1' * 64}  {name}.tar.gz.sig\n{good}  {name}.tar.gz\n{'2' * 64}  x{name}.tar.gz\n")
        r = run(tmp, d)
        assert r.returncode == 0 and os.path.exists(marker), "a .sig line beside the tarball's is not a second listing:\n" + r.stdout + r.stderr
        os.unlink(marker)
        with open(sums, "w", encoding="utf-8") as f:
            f.write(f"{good}  {name}.tar.gz.sig\n")
        r = run(tmp, d)
        assert r.returncode == 1 and "does not list" in r.stderr and not os.path.exists(marker), r.stdout + r.stderr
        out["checksumNameMatchedWhole"] = True

        # No release for this version: it says so and installs nothing.
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        r = run(tmp, empty)
        assert r.returncode == 1 and "could not download" in r.stderr and "nothing was installed" in r.stderr, r.stderr
        out["missingReleaseSaysSo"] = True

        # A release with no kub0 in it.
        d, marker, _ = release(tmp, X86, "hollow", with_kub0=False)
        r = run(tmp, d)
        assert r.returncode == 1 and "has no kub0 in it" in r.stderr, r.stdout + r.stderr
        out["hollowReleaseRefused"] = True

        # An architecture no release is built for names the way out.
        d, marker, _ = release(tmp, X86, "riscv")
        r = run(tmp, d, "riscv64")
        assert r.returncode == 1 and "no release is built for riscv64" in r.stderr and "build.sh" in r.stderr, r.stderr
        assert not os.path.exists(marker)
        out["unknownArchitectureSaysSo"] = True

        # Plain HTTP is refused, by curl and not by the text of the script: a
        # complete, correct release served over http:// is still not installed.
        d, marker, name = release(tmp, X86, "plain-http")
        handler = functools.partial(Quiet, directory=d)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            # The server does serve it (or the refusal below proves nothing).
            got = subprocess.run(["curl", "--fail", "--silent", "-o", os.devnull, f"{url}/{name}.tar.gz"])
            assert got.returncode == 0, "the test's own server is not serving the release"
            r = run(tmp, url)
            assert r.returncode == 1 and "could not download" in r.stderr, r.stdout + r.stderr
            assert not os.path.exists(marker), "a release fetched over plain HTTP was installed"
        finally:
            server.shutdown()
        out["plainHttpRefused"] = True

        # The version comes from manifest.json and goes into a URL and a path,
        # so anything that is not three numbers stops it before either.
        plug = os.path.join(tmp, "plugin")
        os.makedirs(os.path.join(plug, "scripts"))
        copy = os.path.join(plug, "scripts", "install-release.sh")
        shutil.copy(SCRIPT, copy)
        for bad in ("../../etc", "0.5", "0.5.1-rc1", "1.0.0/../../x", ""):
            with open(os.path.join(plug, "manifest.json"), "w", encoding="utf-8") as f:
                json.dump({"id": "ai.kub0.agent", "version": bad}, f, indent=2)
            r = run(tmp, empty, script=copy)
            assert r.returncode == 1 and "no usable version" in r.stderr, f"{bad!r}: {r.stdout}{r.stderr}"
            assert "could not download" not in r.stderr and "from file://" not in r.stdout, f"{bad!r} reached the download: {r.stdout}{r.stderr}"
        # The copy does work with a real version (so the refusals above are the check's).
        with open(os.path.join(plug, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump({"id": "ai.kub0.agent", "version": "9.8.7"}, f, indent=2)
        d, marker, _ = release(tmp, X86, "ver-good", version="9.8.7")
        r = run(tmp, d, script=copy)
        assert r.returncode == 0 and os.path.exists(marker), r.stdout + r.stderr
        out["versionMustBeThreeNumbers"] = True

        # A missing tool is named, instead of "could not download".
        lean = os.path.join(tmp, "lean")
        os.makedirs(lean)
        for tool in ("dirname", "awk", "mktemp", "sha256sum", "tar", "rm", "grep", "tr", "gzip", "cat"):
            os.symlink(shutil.which(tool), os.path.join(lean, tool))
        bindir, _ = stubs(tmp, "x86_64")
        d, marker, _ = release(tmp, X86, "no-curl")
        r = run(tmp, d, path=bindir + os.pathsep + lean)
        assert r.returncode == 1 and "this needs curl" in r.stderr and "could not download" not in r.stderr, r.stdout + r.stderr
        assert not os.path.exists(marker)
        out["missingToolIsNamed"] = True

        # An override is said out loud: the checksum then proves less.
        d, marker, _ = release(tmp, X86, "override")
        assert "KUB0_RELEASE_BASE is set" in run(tmp, d).stdout
        out["overrideIsAnnounced"] = True

    # Left to itself it asks GitHub for this panel's version.
    text = open(SCRIPT, encoding="utf-8").read()
    assert 'https://github.com/kub0-ai/kub0-agent/releases/download/v$version' in text
    assert shutil.which("curl"), "curl is what the script downloads with"
    print(json.dumps(out))


if __name__ == "__main__":
    main()
