#!/usr/bin/env python3
"""scripts/install-release.sh, run for real against a release made of stubs.

The script is run from a copy of the plugin: manifest.json, the script, and a
scripts/release-digests the test writes, which is where the script takes the
digest a tarball must have. The release is a directory of files (file://) or
a local plain-HTTP server, `uname` and `id` are stubs first on PATH, the
program that would become root is a stub named by KUB0_INSTALL_SUDO, and the
"kub0" in the tarball is a shell script that records how it was called.
Nothing is downloaded from outside this machine, nothing runs as root, and no
kub0 binary is executed.
"""

import functools
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "install-release.sh")
PINS = os.path.join(ROOT, "scripts", "release-digests")
VERSION = json.load(open(os.path.join(ROOT, "manifest.json"), encoding="utf-8"))["version"]
X86 = "x86_64-unknown-linux-musl"
ARM = "aarch64-unknown-linux-musl"


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


def write_sums(d, target, name):
    """The release's own checksum file, agreeing with whatever tarball is in `d`."""
    with open(os.path.join(d, f"SHA256SUMS-{target}"), "w", encoding="utf-8") as f:
        f.write(f"{sha(os.path.join(d, name + '.tar.gz'))}  {name}.tar.gz\n{'0' * 64}  kub0-{target}\n")


def release(tmp, target, label, version=VERSION, **kw):
    """A release directory for `target`; returns (dir, marker, tarball name).
    Its SHA256SUMS agrees with its tarball, as a real release's does."""
    d = os.path.join(tmp, label)
    os.makedirs(d)
    name = f"kub0-agent-{version}-{target}"
    marker = os.path.join(tmp, label + ".ran")
    tarball(os.path.join(d, name + ".tar.gz"), name, marker, **kw)
    write_sums(d, target, name)
    return d, marker, name


def pin(d, name):
    """The line scripts/release-digests carries for the tarball now in `d`."""
    return f"{sha(os.path.join(d, name + '.tar.gz'))}  {name}.tar.gz\n"


def plugin(tmp, pins, version=VERSION):
    """A copy of the plugin as far as the script reads it: the manifest, the
    script itself, and the digests this checkout pins (`pins`, the file's
    text; None for a checkout with no such file)."""
    d = tempfile.mkdtemp(dir=tmp, prefix="plugin-")
    os.makedirs(os.path.join(d, "scripts"))
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump({"id": "ai.kub0.agent", "version": version}, f, indent=2)
    shutil.copy(SCRIPT, os.path.join(d, "scripts", "install-release.sh"))
    if pins is not None:
        with open(os.path.join(d, "scripts", "release-digests"), "w", encoding="utf-8") as f:
            f.write(pins)
    return os.path.join(d, "scripts", "install-release.sh")


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


def run(tmp, base, machine="x86_64", pins="", version=VERSION, session="alice wheel", account="alice wheel kub0", env=None, path=None):
    script = plugin(tmp, pins, version)
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
        # What the pin is for. The panel was reviewed with one tarball in the
        # release. Whoever can write to the release then replaces the tarball
        # and its SHA256SUMS together, so the two still agree with each other.
        d, marker, name = release(tmp, X86, "replaced")
        reviewed = pin(d, name)
        tarball(os.path.join(d, name + ".tar.gz"), name, marker + ".theirs")
        write_sums(d, X86, name)
        r = run(tmp, d, pins=reviewed)
        assert not os.path.exists(marker + ".theirs"), \
            "a tarball that replaced the reviewed one, with a checksum file replaced to match, was run as root:\n" + r.stdout + r.stderr
        assert r.returncode == 1 and "is not the file this checkout pins" in r.stderr, r.stdout + r.stderr
        assert not os.path.exists(marker) and r.left_behind == [], f"a refused download is removed too: {r.left_behind}"
        out["replacedReleaseRefused"] = True

        # The good path, on both architectures a release is built for.
        for machine, target in (("x86_64", X86), ("aarch64", ARM)):
            d, marker, name = release(tmp, target, "good-" + machine)
            r = run(tmp, d, machine, pins=pin(d, name))
            assert r.returncode == 0, r.stdout + r.stderr
            assert open(marker, encoding="utf-8").read().strip() == "install", "kub0 is run as `kub0 install`, nothing else"
            assert "digest ok" in r.stdout and f"kub0 {VERSION} for {target}" in r.stdout, r.stdout
            assert r.left_behind == [], f"the download and the unpacked release are removed: {r.left_behind}"
        out["installsOnBothArchitectures"] = True

        # The step that becomes root is run by path, never found through PATH.
        assert not os.path.exists(os.path.join(tmp, "path-sudo-ran")), "a sudo found on PATH ran"
        log = open(os.path.join(tmp, "as-root.log"), encoding="utf-8").read().splitlines()
        assert len(log) == 2 and all(line.endswith(f"/kub0-agent-{VERSION}-{t}/kub0 install") for line, t in zip(log, (X86, ARM))), log
        text = open(SCRIPT, encoding="utf-8").read()
        assert 'sudo="${KUB0_INSTALL_SUDO:-/usr/bin/sudo}"' in text and '"$sudo" "$tmp/$name/kub0" install' in text
        out["rootStepIsByPath"] = True

        # What it says afterwards depends on the session, not on a fixed line.
        d, marker, name = release(tmp, X86, "said")
        said = run(tmp, d, pins=pin(d, name), session="alice wheel kub0", account="alice wheel kub0").stdout
        assert "already in the kub0 group" in said and "Log out" not in said, said
        said = run(tmp, d, pins=pin(d, name), session="alice wheel", account="alice wheel kub0").stdout
        assert "Log out and back in once" in said and "reboot" in said, said
        said = run(tmp, d, pins=pin(d, name), session="alice kub0-admins", account="alice kub0-admins").stdout
        assert "not in the kub0 group" in said and "sudo gpasswd -a alice kub0" in said, said
        out["closingLineMatchesTheSession"] = True

        # The release's own checksum file is not asked: one that agrees with
        # the tarball adds nothing, and one that is missing takes nothing away.
        d, marker, name = release(tmp, X86, "no-sums")
        os.unlink(os.path.join(d, f"SHA256SUMS-{X86}"))
        r = run(tmp, d, pins=pin(d, name))
        assert r.returncode == 0 and os.path.exists(marker), r.stdout + r.stderr
        out["releaseChecksumFileIsNotTrusted"] = True

        # A checkout that pins nothing for this tarball downloads nothing.
        # `gone` holds no release at all: reaching it would say "could not
        # download", so the refusal below came first.
        gone = os.path.join(tmp, "gone")
        os.makedirs(gone)
        d, marker, name = release(tmp, X86, "unpinned")
        other = f"{'0' * 64}  kub0-agent-{VERSION}-{ARM}.tar.gz\n"
        for label, pins in (("no file", None), ("an empty file", ""), ("another architecture's line", other),
                            ("another version's line", pin(d, name).replace(VERSION, "9.8.7")),
                            ("a commented-out line", "# " + pin(d, name)),
                            ("a digest that is not 64 hex digits", f"{'0' * 63}  {name}.tar.gz\n"),
                            ("the release's own format, which lists more than tarballs", f"{'0' * 64}  kub0-{X86}\n")):
            r = run(tmp, gone, pins=pins)
            assert r.returncode == 1 and "pins no digest" in r.stderr, f"{label}: {r.stdout}{r.stderr}"
            assert "could not download" not in r.stderr and "omarchy plugin update" in r.stderr and "build.sh" in r.stderr, f"{label}: {r.stderr}"
            assert not os.path.exists(marker), label
        # Nor is one that names it twice with different digests.
        r = run(tmp, d, pins=pin(d, name) + f"{'0' * 64}  {name}.tar.gz\n")
        assert r.returncode == 1 and "pins no digest" in r.stderr and not os.path.exists(marker), r.stdout + r.stderr
        out["unpinnedOrAmbiguousRefusedBeforeDownload"] = True

        # The name is matched whole. A line for a signature or a longer name
        # beside the tarball's is not a second pin; and a line for the longer
        # name alone is not a pin for the tarball.
        good = sha(os.path.join(d, name + ".tar.gz"))
        r = run(tmp, d, pins=f"# kub0 {VERSION}\n{'1' * 64}  {name}.tar.gz.sig\n{good}  {name}.tar.gz\n{'2' * 64}  x{name}.tar.gz\n")
        assert r.returncode == 0 and os.path.exists(marker), "a .sig line beside the tarball's is not a second pin:\n" + r.stdout + r.stderr
        os.unlink(marker)
        r = run(tmp, d, pins=f"{good}  {name}.tar.gz.sig\n")
        assert r.returncode == 1 and "pins no digest" in r.stderr and not os.path.exists(marker), r.stdout + r.stderr
        out["pinNameMatchedWhole"] = True

        # No release for this version: it says so and installs nothing.
        r = run(tmp, gone, pins=pin(d, name))
        assert r.returncode == 1 and "could not download" in r.stderr and "nothing was installed" in r.stderr, r.stderr
        out["missingReleaseSaysSo"] = True

        # A release with no kub0 in it.
        d, marker, name = release(tmp, X86, "hollow", with_kub0=False)
        r = run(tmp, d, pins=pin(d, name))
        assert r.returncode == 1 and "has no kub0 in it" in r.stderr, r.stdout + r.stderr
        out["hollowReleaseRefused"] = True

        # An architecture no release is built for names the way out.
        d, marker, name = release(tmp, X86, "riscv")
        r = run(tmp, d, "riscv64", pins=pin(d, name))
        assert r.returncode == 1 and "no release is built for riscv64" in r.stderr and "build.sh" in r.stderr, r.stderr
        assert not os.path.exists(marker)
        out["unknownArchitectureSaysSo"] = True

        # Plain HTTP is refused, by curl and not by the text of the script: a
        # complete, correct, pinned release served over http:// is still not
        # installed.
        d, marker, name = release(tmp, X86, "plain-http")
        handler = functools.partial(Quiet, directory=d)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{server.server_address[1]}"
            # The server does serve it (or the refusal below proves nothing).
            got = subprocess.run(["curl", "--fail", "--silent", "-o", os.devnull, f"{url}/{name}.tar.gz"])
            assert got.returncode == 0, "the test's own server is not serving the release"
            r = run(tmp, url, pins=pin(d, name))
            assert r.returncode == 1 and "could not download" in r.stderr, r.stdout + r.stderr
            assert not os.path.exists(marker), "a release fetched over plain HTTP was installed"
        finally:
            server.shutdown()
        out["plainHttpRefused"] = True

        # The version comes from manifest.json and goes into a URL and a path,
        # so anything that is not three numbers stops it before either.
        for bad in ("../../etc", "0.5", "0.5.1-rc1", "1.0.0/../../x", ""):
            r = run(tmp, gone, version=bad)
            assert r.returncode == 1 and "no usable version" in r.stderr, f"{bad!r}: {r.stdout}{r.stderr}"
            assert "could not download" not in r.stderr and "from file://" not in r.stdout, f"{bad!r} reached the download: {r.stdout}{r.stderr}"
        # It does work with another real version (so the refusals above are the check's).
        d, marker, name = release(tmp, X86, "ver-good", version="9.8.7")
        r = run(tmp, d, pins=pin(d, name), version="9.8.7")
        assert r.returncode == 0 and os.path.exists(marker), r.stdout + r.stderr
        out["versionMustBeThreeNumbers"] = True

        # A missing tool is named, instead of "could not download".
        lean = os.path.join(tmp, "lean")
        os.makedirs(lean)
        for tool in ("dirname", "awk", "mktemp", "sha256sum", "tar", "rm", "grep", "tr", "gzip", "cat"):
            os.symlink(shutil.which(tool), os.path.join(lean, tool))
        bindir, _ = stubs(tmp, "x86_64")
        d, marker, name = release(tmp, X86, "no-curl")
        r = run(tmp, d, pins=pin(d, name), path=bindir + os.pathsep + lean)
        assert r.returncode == 1 and "this needs curl" in r.stderr and "could not download" not in r.stderr, r.stdout + r.stderr
        assert not os.path.exists(marker)
        out["missingToolIsNamed"] = True

        # Another place to fetch from is said out loud, and changes where the
        # tarball comes from, not what it must be: every refusal above was
        # made with KUB0_RELEASE_BASE set.
        d, marker, name = release(tmp, X86, "override")
        said = run(tmp, d, pins=pin(d, name)).stdout
        assert "KUB0_RELEASE_BASE is set" in said and "same pinned digest" in said, said
        out["overrideIsAnnouncedAndPinned"] = True

    # Left to itself it asks GitHub for this panel's version.
    text = open(SCRIPT, encoding="utf-8").read()
    assert 'https://github.com/kub0-ai/kub0-agent/releases/download/v$version' in text
    assert "SHA256SUMS" not in text.replace("SHA256SUMS-<target>", ""), "the release's checksum file is not something this script fetches or trusts"
    assert shutil.which("curl"), "curl is what the script downloads with"

    # The file this checkout ships: every line that is not a comment is one
    # digest and one tarball name, no tarball is named twice, and a version
    # that is pinned at all is pinned for both architectures.
    seen = {}
    for n, line in enumerate(open(PINS, encoding="utf-8").read().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.fullmatch(r"([0-9a-f]{64})  kub0-agent-(\d+\.\d+\.\d+)-(x86_64|aarch64)-unknown-linux-musl\.tar\.gz", line)
        assert m, f"scripts/release-digests line {n} is not '<sha256>  <tarball>': {line!r}"
        key = (m.group(2), m.group(3))
        assert key not in seen, f"scripts/release-digests names {key} twice"
        seen[key] = m.group(1)
    for version in {v for v, _ in seen}:
        assert (version, "x86_64") in seen and (version, "aarch64") in seen, f"{version} is pinned for one architecture only"
    out["shippedPinsAreWellFormed"] = sorted({v for v, _ in seen})
    print(json.dumps(out))


if __name__ == "__main__":
    main()
