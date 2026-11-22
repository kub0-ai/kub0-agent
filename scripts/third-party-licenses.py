#!/usr/bin/env python3
"""Write the license notices that travel with the release binaries.

A release binary is a redistribution of what is compiled into it, and MIT,
Apache-2.0, BSD and ISC all ask that their notice travels with the copy. This
reads the resolved dependency graph for one or more targets, takes every
crate that is not a workspace member and not a dev-dependency, and writes one
file: a table of the crates, then each distinct license text once, with the
crates it covers, then the toolchain's own (Rust's standard library and musl
libc are linked into every static binary and are in no dependency graph).

The crate list is the build graph, which is wider than what is linked: it
includes build scripts' helpers and procedural macros. Listing a crate that is
only used at build time costs nothing; leaving out one that is linked would.

  scripts/third-party-licenses.py --target x86_64-unknown-linux-musl --out THIRD-PARTY-LICENSES.md

It fails, writing nothing, when a crate declares no license or ships no
license text and is not listed in NO_TEXT below with the reason, or when a
toolchain text is missing. A notice file that silently left something out
would be worse than none.

`--metadata FILE` reads `cargo metadata` output from a file instead of running
cargo (the tests use it).
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

# Files that carry a license, a copyright line, or a notice, by name.
LICENSE_NAME = re.compile(r"^(licen[sc]e|copying|copyright|notice|unlicense|patents)([-_.].*)?$", re.I)
# The ones that are a license text. A crate with only a NOTICE, or a COPYRIGHT
# that points elsewhere, has not shipped its license.
LICENSE_TEXT = re.compile(r"^(licen[sc]e|copying|unlicense)([-_.].*)?$", re.I)
# Directories whose license files are not about code the crate compiles.
SKIP_DIRS = {"tests", "test", "benches", "examples", "fuzz", "target", ".git"}

# Crates that ship no license text of their own. Each needs a reason a reader
# can check; the declared expression and the link are printed in their place.
NO_TEXT = {}

# What every static musl binary links that no crate graph lists. The texts
# are kept in the repository so a release does not depend on a download.
TOOLCHAIN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "packaging", "release", "toolchain")
TOOLCHAIN = [
    ("The Rust standard library (std, core, alloc and the crates they bundle)", "MIT OR Apache-2.0",
     "https://github.com/rust-lang/rust", ["rust-COPYRIGHT", "rust-LICENSE-MIT", "rust-LICENSE-APACHE"]),
    ("musl libc, linked statically", "MIT", "https://musl.libc.org", ["musl-COPYRIGHT"]),
]

FENCE = "`" * 3


def metadata(target, path):
    if path:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    cmd = ["cargo", "metadata", "--format-version", "1", "--locked"]
    if target:
        cmd += ["--filter-platform", target]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def linked(meta):
    """Ids of every non-workspace package reachable without a dev edge."""
    members = set(meta["workspace_members"])
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    seen, stack = set(), list(members)
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for dep in nodes[pid]["deps"]:
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [{"kind": None}])}
            if kinds - {"dev"}:
                stack.append(dep["pkg"])
    return seen - members


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def texts(package):
    """(path within the crate, text) for each license file the crate ships.

    The whole crate is walked, not only its top directory: a crate that
    vendors someone else's code keeps that code's license beside it (ring's
    `third_party/fiat/LICENSE`), and its own top-level file only points there.
    """
    root = os.path.dirname(package["manifest_path"])
    found = []
    for directory, subdirs, names in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS)
        for name in sorted(names):
            path = os.path.join(directory, name)
            if LICENSE_NAME.match(name) and os.path.isfile(path):
                found.append((os.path.relpath(path, root), read(path)))
    declared = package.get("license_file")
    if declared:
        rel = os.path.normpath(declared)
        path = os.path.join(root, rel)
        if os.path.isfile(path) and not any(r == rel for r, _ in found):
            found.append((rel, read(path)))
    return found


def has_license_text(package, found):
    """Whether one of the files is a license, not only a notice about one."""
    declared = os.path.normpath(package["license_file"]) if package.get("license_file") else None
    return any(LICENSE_TEXT.match(os.path.basename(rel)) or rel == declared for rel, _ in found)


def toolchain():
    """The fixed texts, and the names of any that are missing."""
    out, missing = [], []
    for title, license_, link, files in TOOLCHAIN:
        parts = []
        for name in files:
            path = os.path.join(TOOLCHAIN_DIR, name)
            if os.path.isfile(path):
                parts.append((name, read(path)))
            else:
                missing.append(f"toolchain text {name} is not in packaging/release/toolchain")
        out.append((title, license_, link, parts))
    return out, missing


def normal(text):
    """A text's identity: what it says, whatever its line endings and wrapping."""
    return hashlib.sha256(" ".join(text.split()).encode()).hexdigest()


def collect(metas):
    crates, problems = {}, []
    for meta in metas:
        packages = {p["id"]: p for p in meta["packages"]}
        for pid in linked(meta):
            p = packages[pid]
            key = (p["name"], p["version"])
            if key in crates:
                continue
            found = texts(p)
            if not p.get("license") and not p.get("license_file"):
                problems.append(f"{p['name']} {p['version']}: declares no license")
            if not has_license_text(p, found) and p["name"] not in NO_TEXT:
                problems.append(f"{p['name']} {p['version']}: ships no license text (declared: {p.get('license')})")
            crates[key] = {
                "name": p["name"],
                "version": p["version"],
                "license": p.get("license") or "see the text below",
                "link": p.get("repository") or p.get("homepage") or f"https://crates.io/crates/{p['name']}",
                "texts": found,
            }
    return [crates[k] for k in sorted(crates)], problems


def block(text):
    return [FENCE + "text", text.replace(FENCE, "'''").rstrip(), FENCE, ""]


def render(crates, targets, tools):
    by_text, order = {}, []
    for c in crates:
        for name, text in c["texts"]:
            h = normal(text)
            if h not in by_text:
                by_text[h] = {"text": text, "crates": []}
                order.append(h)
            # A file below the crate's top directory is named: it is the
            # license of something the crate carries, not of the crate.
            label = f"{c['name']} {c['version']}"
            if os.sep in name:
                label += f" ({name})"
            if label not in by_text[h]["crates"]:
                by_text[h]["crates"].append(label)
    out = [
        "# Third-party licenses",
        "",
        "The kub0 release binaries (`kub0`, `kub0d`, `kub0-block`) are built from this",
        "repository, from the Rust crates below, and from the toolchain named after",
        "them. The crates are every one in the build graph, which includes a few that",
        "only run at build time. Each is used under the license it declares; the texts",
        "follow the table, each printed once with the crates it came from.",
        "",
        "Built for: " + ", ".join(f"`{t}`" for t in targets) + ".",
        "What this repository itself took from other projects is in `THIRD-PARTY.md`.",
        "",
        f"## Crates ({len(crates)})",
        "",
        "| Crate | Version | License | Source |",
        "|---|---|---|---|",
    ]
    for c in crates:
        out.append(f"| {c['name']} | {c['version']} | {c['license']} | {c['link']} |")
    missing = [c for c in crates if not c["texts"]]
    if missing:
        out += ["", "## Crates that ship no license text", ""]
        for c in missing:
            out.append(f"- {c['name']} {c['version']} ({c['license']}): {NO_TEXT[c['name']]}")
    out += ["", f"## License texts ({len(order)})", ""]
    for n, h in enumerate(order, 1):
        entry = by_text[h]
        out += [f"### {n}. {', '.join(entry['crates'])}", ""] + block(entry["text"])
    out += ["## Toolchain", "", "Linked into every binary, and in no crate graph.", ""]
    for title, license_, link, parts in tools:
        out += [f"### {title}", "", f"{license_}. {link}", ""]
        for name, text in parts:
            out += [f"`{name}`", ""] + block(text)
    return "\n".join(out).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", action="append", default=[], help="a target triple; repeat for several")
    ap.add_argument("--metadata", action="append", default=[], help="read cargo metadata JSON from this file")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.metadata:
        metas = [metadata(None, m) for m in args.metadata]
    else:
        metas = [metadata(t, None) for t in (args.target or [None])]
    crates, problems = collect(metas)
    tools, missing = toolchain()
    problems += missing
    if problems:
        for p in problems:
            print(f"third-party-licenses: {p}", file=sys.stderr)
        print(f"third-party-licenses: {len(problems)} notice(s) it cannot print; nothing written", file=sys.stderr)
        return 1
    if not crates:
        print("third-party-licenses: no third-party crates found; nothing written", file=sys.stderr)
        return 1
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(render(crates, args.target or ["the host"], tools))
    print(f"third-party-licenses: {len(crates)} crates, {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
