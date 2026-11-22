#!/usr/bin/env python3
"""The three scripts a release is made with, run for real on fixtures.

- scripts/third-party-licenses.py: which crates get a notice, and that a crate
  it cannot print a license for stops it instead of being left out.
- scripts/package-release.sh: what is in the tarball, that it installs from
  where it unpacks, and that the same inputs give the same bytes.
- scripts/release-notes.sh: the right section, or a failure.

Nothing here builds, installs or runs a kub0 binary: the "binaries" are three
shell stubs, and cargo is never called (the notices come from a fixture).
"""

import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LICENSES = os.path.join(ROOT, "scripts", "third-party-licenses.py")
PACKAGE = os.path.join(ROOT, "scripts", "package-release.sh")
NOTES = os.path.join(ROOT, "scripts", "release-notes.sh")
TARGET = "x86_64-unknown-linux-musl"

MIT_A = "MIT License\n\nCopyright (c) Ann\n\nPermission is hereby granted.\n"
APACHE = "Apache License\nVersion 2.0, January 2004\n\nFIXTURE SHARED TERMS\n"


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def crate(root, name, version, license_, files, deps=()):
    """One fixture crate on disk and its `cargo metadata` package entry."""
    d = os.path.join(root, f"{name}-{version}")
    os.makedirs(d)
    for fname, text in files.items():
        os.makedirs(os.path.dirname(os.path.join(d, fname)), exist_ok=True)
        with open(os.path.join(d, fname), "w", encoding="utf-8") as f:
            f.write(text)
    pid = f"registry+https://example.invalid#{name}@{version}"
    return {
        "id": pid,
        "name": name,
        "version": version,
        "license": license_,
        "repository": f"https://example.invalid/{name}",
        "manifest_path": os.path.join(d, "Cargo.toml"),
        "_deps": list(deps),
    }


def metadata(root, packages, member):
    """A `cargo metadata` document: `member` is the workspace, the rest crates.io."""
    nodes = []
    for p in packages:
        nodes.append({
            "id": p["id"],
            "deps": [{"pkg": pid, "dep_kinds": [{"kind": kind}]} for pid, kind in p["_deps"]],
        })
    doc = {
        "packages": [{k: v for k, v in p.items() if k != "_deps"} for p in packages],
        "workspace_members": [member["id"]],
        "resolve": {"nodes": nodes},
    }
    path = os.path.join(root, "metadata.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    return path


def test_notices(tmp):
    root = os.path.join(tmp, "crates")
    os.makedirs(root)
    ann = crate(root, "ann", "1.0.0", "MIT", {"LICENSE-MIT": MIT_A})
    # Two crates, one Apache text, wrapped differently: printed once.
    bob = crate(root, "bob", "2.0.0", "Apache-2.0", {"LICENSE": APACHE})
    rewrapped = APACHE.replace("Version 2.0, January 2004", "   Version 2.0,\n   January 2004")
    assert rewrapped != APACHE
    cat = crate(root, "cat", "3.0.0", "Apache-2.0", {"LICENSE-APACHE": rewrapped})
    # Reached only through a dev edge: not in the binary, not in the notices.
    dev = crate(root, "devonly", "0.1.0", "MIT", {"LICENSE": "MIT\nCopyright (c) Dev\n"})
    # A build dependency of a linked crate is compiled for the build: listed.
    bld = crate(root, "buildtool", "0.2.0", "MIT", {"COPYING": "MIT\nCopyright (c) Build\n"})
    ann["_deps"] = [(bob["id"], None), (bld["id"], "build")]
    # A crate that carries someone else's code keeps that code's license
    # beside it, below its own top directory (ring does). Its tests' fixture
    # licenses are not about anything it compiles.
    ven = crate(root, "vendor", "4.0.0", "MIT", {
        "LICENSE": "MIT\nCopyright (c) Vendor\nsee third_party/fiat/LICENSE\n",
        "third_party/fiat/LICENSE": "Apache License\nCopyright the fiat authors\n",
        "tests/data/LICENSE": "a fixture, not a license of this crate\n",
    })
    me = crate(root, "kub0", "0.0.0", "MIT", {}, deps=[(ann["id"], None), (cat["id"], None), (ven["id"], None), (dev["id"], "dev")])
    out = os.path.join(tmp, "notices.md")
    r = run([sys.executable, LICENSES, "--metadata", metadata(root, [me, ann, bob, cat, dev, bld, ven], me), "--out", out])
    assert r.returncode == 0, r.stderr
    text = open(out, encoding="utf-8").read()
    assert "Copyright the fiat authors" in text, "a license below the crate's top directory is printed"
    assert "vendor 4.0.0 (third_party/fiat/LICENSE)" in text, "and says where it came from"
    assert "a fixture, not a license" not in text, "a tests/ directory is not walked"
    # What every static binary links and no crate graph lists.
    assert "## Toolchain" in text and "musl as a whole is licensed" in text and "The Rust Project" in text, "the toolchain's notices are printed"
    for name in ("ann", "bob", "cat", "buildtool", "vendor"):
        assert f"| {name} |" in text, f"{name} is linked and must be listed:\n{text}"
    assert "devonly" not in text, "a dev-dependency is not in the binary"
    assert "| kub0 |" not in text, "the workspace's own crates are not third-party"
    assert text.count("FIXTURE SHARED TERMS") == 1, "one text for the two crates that share it"
    assert "bob 2.0.0, cat 3.0.0" in text, "and it names both"
    assert "Copyright (c) Ann" in text and "Copyright (c) Build" in text

    # A crate with no license text stops the run and leaves no file behind.
    bare = crate(root, "bare", "9.0.0", "MIT", {"README.md": "no license here"})
    me2 = dict(me, _deps=me["_deps"] + [(bare["id"], None)])
    out2 = os.path.join(tmp, "notices2.md")
    r = run([sys.executable, LICENSES, "--metadata", metadata(root, [me2, ann, bob, cat, dev, bld, ven, bare], me2), "--out", out2])
    assert r.returncode == 1, "a crate it cannot print a license for is a failure"
    assert "bare 9.0.0: ships no license text" in r.stderr, r.stderr
    assert not os.path.exists(out2), "nothing is written when a crate is missing"

    # A NOTICE or a COPYRIGHT that points at a license is not the license.
    note = crate(root, "noteonly", "9.2.0", "Apache-2.0", {"NOTICE": "see the LICENSE file", "COPYRIGHT": "see LICENSE-MIT"})
    me4 = dict(me, _deps=me["_deps"] + [(note["id"], None)])
    r = run([sys.executable, LICENSES, "--metadata", metadata(root, [me4, ann, bob, cat, dev, bld, ven, note], me4), "--out", out2])
    assert r.returncode == 1 and "noteonly 9.2.0: ships no license text" in r.stderr, r.stderr
    assert not os.path.exists(out2)

    # So does one that declares none.
    mute = crate(root, "mute", "9.1.0", None, {"LICENSE": "something"})
    me3 = dict(me, _deps=me["_deps"] + [(mute["id"], None)])
    r = run([sys.executable, LICENSES, "--metadata", metadata(root, [me3, ann, bob, cat, dev, bld, ven, mute], me3), "--out", out2])
    assert r.returncode == 1 and "mute 9.1.0: declares no license" in r.stderr, r.stderr
    return {"listed": 5, "devDependencyLeftOut": True, "sharedTextPrintedOnce": True, "nestedLicensePrinted": True,
            "toolchainPrinted": True, "missingLicenseFails": True, "noticeAloneFails": True}


def package(tmp, bindir, outname, epoch="1700000000", umask="022", licenses=None):
    out = os.path.join(tmp, outname)
    env = dict(os.environ, KUB0_PACKAGE_BIN_DIR=bindir, SOURCE_DATE_EPOCH=epoch,
               KUB0_PACKAGE_LICENSES=licenses or os.path.join(tmp, "fixture-licenses.md"))
    return out, run(["bash", "-c", f'umask {umask}; exec bash "$0" "$@"', PACKAGE, TARGET, out], env=env)


def test_package(tmp):
    bindir = os.path.join(tmp, "bin")
    os.makedirs(bindir)
    with open(os.path.join(tmp, "fixture-licenses.md"), "w", encoding="utf-8") as f:
        f.write("# Third-party licenses\nfixture\n")
    for b in ("kub0", "kub0d"):
        p = os.path.join(bindir, b)
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"#!/bin/sh\necho stub {b}\n")
        os.chmod(p, 0o755)

    # One binary short: it says which, and writes nothing.
    out, r = package(tmp, bindir, "short")
    assert r.returncode == 1 and "kub0-block is missing" in r.stderr, r.stderr
    assert not os.path.exists(out), "a failed package writes nothing to the out dir"

    p = os.path.join(bindir, "kub0-block")
    with open(p, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\necho stub kub0-block\n")
    os.chmod(p, 0o755)
    # A failure after the binaries were found (here: the notices) still
    # leaves nothing behind: no loose binaries without a checksum file.
    out, r = package(tmp, bindir, "nolicenses", licenses=os.path.join(tmp, "there-is-no-such-file.md"))
    assert r.returncode != 0, "a missing notices file is a failure"
    assert not os.path.exists(out), "and leaves no half release: " + str(os.path.exists(out) and os.listdir(out))

    out, r = package(tmp, bindir, "dist")
    assert r.returncode == 0, r.stderr

    version = next(l.split('"')[1] for l in open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") if l.startswith("version = "))
    name = f"kub0-agent-{version}-{TARGET}"
    tarball = os.path.join(out, name + ".tar.gz")
    assert sorted(os.listdir(out)) == sorted([
        name + ".tar.gz", f"kub0-{TARGET}", f"kub0d-{TARGET}", f"kub0-block-{TARGET}",
        "THIRD-PARTY-LICENSES.md", f"SHA256SUMS-{TARGET}",
    ]), os.listdir(out)

    with tarfile.open(tarball) as t:
        members = {m.name: m for m in t.getmembers()}
    want = {
        name: None,
        f"{name}/kub0": 0o755, f"{name}/kub0d": 0o755, f"{name}/kub0-block": 0o755,
        f"{name}/geoip": None,
        f"{name}/geoip/dbip-country-lite.mmdb": 0o644, f"{name}/geoip/dbip-asn-lite.mmdb": 0o644,
        f"{name}/geoip/ATTRIBUTION.txt": 0o644,
        f"{name}/INSTALL.md": 0o644, f"{name}/LICENSE": 0o644, f"{name}/THIRD-PARTY.md": 0o644,
        f"{name}/THIRD-PARTY-LICENSES.md": 0o644,
    }
    assert set(members) == set(want), sorted(set(members) ^ set(want))
    for path, mode in want.items():
        m = members[path]
        assert m.uid == 0 and m.gid == 0, f"{path} is owned by {m.uid}:{m.gid}, not root"
        assert m.mtime == 1700000000, f"{path} carries the build's clock"
        if mode is not None:
            assert m.isfile() and (m.mode & 0o777) == mode, f"{path} mode {oct(m.mode)}"
        else:
            assert m.isdir() and (m.mode & 0o777) == 0o755, f"{path} is a directory of mode {oct(m.mode)}"

    # `kub0 install` looks for the geo databases in ./geoip beside itself
    # (cli/src/install.rs geo_source). Keep the tarball's layout in step.
    install_rs = open(os.path.join(ROOT, "cli", "src", "install.rs"), encoding="utf-8").read()
    assert 'src.join("geoip")' in install_rs, "kub0 install no longer looks in ./geoip: move the tarball's databases"

    # The checksum file covers everything a release attaches, and verifies.
    r = run(["sha256sum", "-c", f"SHA256SUMS-{TARGET}"], cwd=out)
    assert r.returncode == 0, r.stdout + r.stderr
    sums = open(os.path.join(out, f"SHA256SUMS-{TARGET}"), encoding="utf-8").read()
    for f in os.listdir(out):
        assert f.startswith("SHA256SUMS") or f in sums, f"{f} is attached with no checksum"

    # Same inputs, same bytes: a second run in another directory, and a third
    # under a umask that would make the directories 0700 if it were let.
    digest = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
    for outname, umask in (("dist2", "022"), ("dist3", "077"), ("dist4", "002")):
        out2, r = package(tmp, bindir, outname, umask=umask)
        assert r.returncode == 0, r.stderr
        assert digest(tarball) == digest(os.path.join(out2, name + ".tar.gz")), f"the tarball differs under umask {umask}"
    # Another commit date is another archive: the clock is an input, not noise.
    out5, r = package(tmp, bindir, "dist5", epoch="1700000001")
    assert r.returncode == 0 and digest(tarball) != digest(os.path.join(out5, name + ".tar.gz"))
    return {"members": len(want), "checksumsVerify": True, "reproducibleAcrossUmasks": True, "missingBinaryFails": True,
            "failureLeavesNothing": True}


def test_notes(tmp):
    log = os.path.join(tmp, "CHANGELOG.md")
    with open(log, "w", encoding="utf-8") as f:
        f.write("# Changelog\n\n## Unreleased\n\n## 1.2.0 (2026-01-02)\n\n- second\n  line\n\n## 1.1.0 (2026-01-01)\n\n- first\n\n## 1.0.0 (2025-12-31)\n\n")
    r = run(["bash", NOTES, "1.2.0", log])
    assert r.returncode == 0 and r.stdout == "- second\n  line\n", repr(r.stdout) + r.stderr
    assert run(["bash", NOTES, "v1.2.0", log]).stdout == r.stdout, "a tag name works too"
    assert run(["bash", NOTES, "1.1.0", log]).stdout == "- first\n", "one version only, and the right one"
    # No such version, a version with nothing under it, and the Unreleased
    # heading with nothing under it: none of them is a release's notes.
    for missing in ("9.9.9", "1.0.0", "Unreleased"):
        bad = run(["bash", NOTES, missing, log])
        assert bad.returncode == 1 and "has no notes" in bad.stderr and not bad.stdout, f"{missing}: {bad.stdout}{bad.stderr}"
    # The repository's own changelog has the version Cargo.toml names, or a
    # tag of it could not be released.
    version = next(l.split('"')[1] for l in open(os.path.join(ROOT, "Cargo.toml"), encoding="utf-8") if l.startswith("version = "))
    r = run(["bash", NOTES, version])
    assert r.returncode == 0 and r.stdout.strip(), f"CHANGELOG.md has no notes for {version}: {r.stderr}"
    return {"oneSection": True, "missingOrEmptyFails": True, "currentVersionHasNotes": True}


def main():
    with tempfile.TemporaryDirectory() as tmp:
        result = {"notices": test_notices(tmp), "package": test_package(tmp), "notes": test_notes(tmp)}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
