"use strict";
// The CI workflows, read as text: what a full artifact store must not break.
//
// 2026-11-16: the account's artifact storage filled up and every
// `actions/upload-artifact` was refused. In build.yml that turned a musl build
// that had linked into a failed check. In release.yml the upload sat ahead of
// the steps that attach the binaries to the GitHub Release, so a tag would
// have published a release with nothing in it.
const assert = require("assert");
const fs = require("fs");
const path = require("path");

let passed = 0;
function test(name, fn) {
  fn();
  passed += 1;
  console.log("  ok  " + name);
}

const WF = path.join(__dirname, "..", ".github", "workflows");
function read(file) {
  return fs.readFileSync(path.join(WF, file), "utf8");
}

// The steps of a workflow's job, each as its own text: a step starts at a
// "      - " line and runs to the next one.
function steps(text) {
  const out = [];
  let cur = null;
  for (const line of text.split("\n")) {
    if (/^ {6}- /.test(line)) {
      if (cur !== null) out.push(cur);
      cur = line + "\n";
    } else if (cur !== null) {
      // A comment above the next step belongs to that step, not this one.
      cur += line + "\n";
    }
  }
  if (cur !== null) out.push(cur);
  return out.map((s) => s.split("\n").filter((l) => !/^\s*#/.test(l)).join("\n"));
}

function uploads(file) {
  return steps(read(file)).filter((s) => s.includes("uses: actions/upload-artifact@"));
}

test("a build's artifact upload cannot fail the build, and is kept three days", () => {
  const ups = uploads("build.yml");
  assert.strictEqual(ups.length, 1, "one upload step");
  assert.ok(/^\s+continue-on-error: true$/m.test(ups[0]), "a refused upload is a warning:\n" + ups[0]);
  assert.ok(/^\s+retention-days: 3$/m.test(ups[0]), "not the 90-day default:\n" + ups[0]);
});

test("a release attaches its files before it uploads the spare copy", () => {
  const all = steps(read("release.yml"));
  const attach = all.map((s, i) => (s.includes("uses: softprops/action-gh-release@") ? i : -1)).filter((i) => i >= 0);
  const upload = all.map((s, i) => (s.includes("uses: actions/upload-artifact@") ? i : -1)).filter((i) => i >= 0);
  assert.strictEqual(attach.length, 2, "the tarball and binaries, then the license notices");
  assert.strictEqual(upload.length, 1, "one upload step");
  assert.ok(upload[0] > Math.max(...attach), "the upload is the last of the three: a refused one stops nothing");
});

test("on a tag a refused upload is not a failed release; without one it still fails the run", () => {
  const up = uploads("release.yml")[0];
  assert.ok(
    up.includes("continue-on-error: ${{ startsWith(github.ref, 'refs/tags/') }}"),
    "tolerated only where the Release already has the files:\n" + up
  );
  assert.ok(/^\s+retention-days: 3$/m.test(up), "not the 90-day default:\n" + up);
});

test("every attach step still runs only on a tag", () => {
  for (const s of steps(read("release.yml")).filter((x) => x.includes("uses: softprops/action-gh-release@")))
    assert.ok(s.includes("startsWith(github.ref, 'refs/tags/')"), s);
});

// The kub0 self-hosted runner is a machine on our network. These workflows
// ask for it only on a private repository, and this pins every `runs-on` in
// the directory to an exact list, so a new job, a new file or a reworded
// expression fails until it is added here on purpose. (It cannot stop a
// fork's pull request from bringing its own workflow file: the runner group,
// closed to public repositories, is what refuses that.)
const GUARD = "(github.event.repository.private && vars.KUB0_LINUX_RUNNER)";
const RUNS_ON = {
  "build.yml": [
    "${{ " + GUARD + " || 'ubuntu-latest' }}",
    "${{ matrix.cross && 'ubuntu-latest' || " + GUARD + " || 'ubuntu-latest' }}",
  ],
  "release.yml": ["${{ matrix.cross && 'ubuntu-latest' || " + GUARD + " || 'ubuntu-latest' }}"],
  "build-darwin.yml": ["${{ matrix.runner }}"],
};
function workflowFiles() {
  return fs.readdirSync(WF).filter((f) => /\.ya?ml$/.test(f));
}
function code(text) {
  return text.split("\n").filter((l) => !/^\s*#/.test(l));
}

test("every runs-on is one of the exact expressions listed here", () => {
  assert.deepStrictEqual(workflowFiles().sort(), Object.keys(RUNS_ON).sort(), "a new workflow file needs an entry in RUNS_ON");
  for (const file of workflowFiles()) {
    const lines = code(read(file));
    const found = [];
    lines.forEach((l, i) => {
      const m = /^\s+runs-on:(.*)$/.exec(l);
      if (!m) return;
      assert.ok(m[1].trim() !== "", file + ": runs-on has its value on the same line, not a list below it:\n" + l + "\n" + (lines[i + 1] || ""));
      found.push(m[1].trim());
    });
    assert.deepStrictEqual(found, RUNS_ON[file], file);
  }
  // The darwin matrix is the one indirection: its runners are named here too.
  assert.ok(/^\s+runner: \[macos-26-intel, macos-26\]$/m.test(read("build-darwin.yml")), "the darwin matrix names GitHub's runners and nothing else");
});

test("the self-hosted runner is named nowhere, and its variable is read only behind the private check", () => {
  for (const file of workflowFiles()) {
    for (const line of code(read(file))) {
      assert.ok(!/self-hosted/.test(line), file + " names a self-hosted label:\n" + line);
      const bare = line.split(GUARD).join("");
      assert.ok(!/KUB0_LINUX_RUNNER|\bvars\./.test(bare), file + " reads a variable outside the guard:\n" + line);
    }
  }
});

test("no checkout leaves a token behind for the build to find", () => {
  for (const file of workflowFiles()) {
    const co = steps(read(file)).filter((s) => s.includes("uses: actions/checkout@"));
    assert.ok(co.length > 0, file);
    for (const s of co) assert.ok(/^\s+persist-credentials: false$/m.test(s), file + ":\n" + s);
  }
});

// A tag is not a commit: `uses: owner/action@v4` runs whatever that tag points
// at on the day. Every action is pinned to a commit, with the tag in a comment.
test("every action is pinned to a commit", () => {
  for (const file of workflowFiles()) {
    const uses = read(file).split("\n").filter((l) => /^\s+(- )?uses:/.test(l));
    assert.ok(uses.length > 0, file + " uses an action");
    for (const line of uses)
      assert.ok(/uses: [\w.-]+\/[\w.-]+@[0-9a-f]{40} # \S+/.test(line), file + ": pinned by commit, tag in a comment:\n" + line);
  }
});

test("a release is packaged by the script a pull request also runs, and attests only a tag on a public repository", () => {
  for (const file of ["build.yml", "release.yml"])
    assert.ok(read(file).includes('run: bash scripts/package-release.sh "${{ matrix.target }}" dist'), file);
  const text = read("release.yml");
  const all = steps(text);
  const attest = all.filter((s) => s.includes("uses: actions/attest-build-provenance@"));
  assert.strictEqual(attest.length, 1, "one attest step");
  // A run started by hand from a branch must not mint a provenance that
  // verifies as a release's.
  assert.ok(attest[0].includes("if: ${{ startsWith(github.ref, 'refs/tags/') && !github.event.repository.private }}"), attest[0]);
  for (const subject of ["dist/kub0-agent-*.tar.gz", "dist/kub0-${{ matrix.target }}", "dist/kub0d-${{ matrix.target }}",
    "dist/kub0-block-${{ matrix.target }}", "dist/SHA256SUMS-${{ matrix.target }}", "dist/THIRD-PARTY-LICENSES.md"])
    assert.ok(attest[0].includes(subject), "attested: " + subject);
  for (const perm of ["contents: write", "id-token: write", "attestations: write"])
    assert.ok(new RegExp("^  " + perm + "$", "m").test(text), "the workflow may " + perm);
  const pkg = all.findIndex((s) => s.includes("scripts/package-release.sh"));
  const first = all.findIndex((s) => s.includes("uses: softprops/action-gh-release@"));
  assert.ok(pkg >= 0 && pkg < all.indexOf(attest[0]) && all.indexOf(attest[0]) < first, "package, attest, then attach");
  assert.ok(all[first].includes("body_path: release-notes.md"), "the release carries its changelog section");
  assert.ok(all[first].includes("dist/kub0-agent-*-${{ matrix.target }}.tar.gz"), "and the tarball");
});

test("the cross compiler is a named version, not whatever is newest on the day", () => {
  for (const file of ["build.yml", "release.yml"])
    assert.ok(/cargo install cross --locked --version \d+\.\d+\.\d+$/m.test(read(file)), file);
});

test("a tag that is not Cargo.toml's version stops before anything is built", () => {
  const all = steps(read("release.yml"));
  const guard = all.findIndex((s) => s.includes('"v$v" != "$GITHUB_REF_NAME"'));
  const build = all.findIndex((s) => /name: Build/.test(s));
  assert.ok(guard >= 0 && guard < build, "the version check runs first");
  assert.ok(all[guard].includes("startsWith(github.ref, 'refs/tags/')"), all[guard]);
});

// The panel's Install button downloads the release manifest.json names, and
// the panel's version notice compares that number with the daemon's, which is
// Cargo.toml's. Nothing tied the two files together: a release that bumped one
// would have installed the old daemon and then reported it as out of date.
test("manifest.json and Cargo.toml are one version, and a release checks it before building", () => {
  const root = path.join(__dirname, "..");
  const cargo = /^version = "([^"]+)"/m.exec(fs.readFileSync(path.join(root, "Cargo.toml"), "utf8"));
  const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8")).version;
  assert.ok(cargo && /^\d+\.\d+\.\d+$/.test(cargo[1]), "Cargo.toml has a version");
  assert.strictEqual(manifest, cargo[1], "manifest.json and Cargo.toml name the same version");

  const all = steps(read("release.yml"));
  const guard = all.findIndex((s) => s.includes('if [ "$v" != "$m" ]'));
  const build = all.findIndex((s) => /name: Build/.test(s));
  assert.ok(guard >= 0 && guard < build, "the release compares them before it builds");
  assert.ok(all[guard].includes("Cargo.toml") && all[guard].includes("manifest.json"), all[guard]);
  assert.ok(!/^\s+if:/m.test(all[guard]), "on a dispatched dry run too, not only on a tag:\n" + all[guard]);
});

console.log(passed + " workflow tests passed");
