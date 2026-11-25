# Contributing

Issues and pull requests are welcome. A few things are not negotiable, and
knowing them first saves a round trip.

## Build and test

```sh
./build.sh                    # kub0d, kub0-block and kub0 into ./bin
timeout 900 ./tests/run.sh    # Rust, Node and Qt6 QML suites, kub0d --self-test
```

`tests/run.sh` needs `cargo`, `node` and `python3`; its live tests bind
loopback sockets, and the network-policy ones use `nft`, `ip` and an
unprivileged user namespace. It skips the QML suites when no Qt6 `qml` runtime
is installed and says so.

The runtime harness (`tests/qml/run-runtime.sh`) is separate and is not part
of `run.sh`. It runs the real `Service.qml` and `Panel.qml` under `quickshell`
inside `bwrap`, and it masks the installed helper, so it needs Omarchy's
shell, user namespaces and `/usr/lib/kub0/kub0-block` in place. Where any of
those is missing it stops before QML runs, which is a run that did not happen,
not a pass.

## Never run a built binary against your own machine's state

`kub0d`, `kub0` and `kub0-block` read and write real state: the account file,
block records, nftables. Run a build only with `HOME`, `XDG_STATE_HOME` and
`XDG_RUNTIME_DIR` pointing at a fresh temporary directory, and never with
`--system`. The test suites already do this.

## Every bug gets a test

A fix comes with a regression test that fails on the code before the fix. Say
in the pull request how you saw it fail.

## Taking code from elsewhere

Record it in [`THIRD-PARTY.md`](THIRD-PARTY.md) in the same commit. One rule
there is binding: **do not read OpenSnitch's implementation source to write
code here.** Its protocol, schema and documentation are fine. OpenSnitch is
GPL-3.0 and this repository is MIT.

## Names

Everything a user types or sees is `kub0`. `daemon/tests/rename_guard.rs`
fails on a 0.4.x name outside its allowlist.

## Your commit identity

A git author field ships in every clone and is never unpublished. If you do
not want your address public, commit with GitHub's
`<id>+<login>@users.noreply.github.com` alias before you push.

## Wire and command changes

`docs/SCHEMA.md` is the wire contract. `daemon/tests/parity.rs` requires a
`kub0` command for every control verb that changes something, and a route for
every change the panel can make, so a new one of either fails until it has
both.

## Releasing

A tag `vX.Y.Z` on `main` builds and publishes the release
(`.github/workflows/release.yml`). The release is not finished at the tag:
the panel's Install kub0 button installs only a tarball whose sha256 is in
`scripts/release-digests`, and a tarball's digest cannot be in the commit it
was built from. So the order is always:

1. Tag. Wait for the release to publish.
2. Download both tarballs, check that each was built by the release workflow
   at that tag, and append their digests:

   ```sh
   v=X.Y.Z
   for t in x86_64 aarch64; do
     f=kub0-agent-$v-$t-unknown-linux-musl.tar.gz
     curl -fsSLO "https://github.com/kub0-ai/kub0-agent/releases/download/v$v/$f"
     gh attestation verify "$f" --repo kub0-ai/kub0-agent \
       --signer-workflow kub0-ai/kub0-agent/.github/workflows/release.yml \
       --source-ref "refs/tags/v$v" || exit 1
     sha256sum "$f"
   done   # paste the two lines under a "# X.Y.Z" comment in scripts/release-digests
   ```

3. Merge that as its own pull request. `python3 tests/test_install_release.py`
   checks the file's shape; running `./scripts/install-release.sh` from the
   branch, with `KUB0_INSTALL_SUDO` set to a script that only prints its
   arguments, checks it against the real release.
4. That commit, not the tag, is the one to name in a plugin listing's update
   request: it is the first at which the button works for the new version.

Between steps 1 and 3 a panel at `main` (or at the tag) has the new version
and no digest for it, so the button refuses and says to update the plugin or
build from source. Keep that window short.

Lines are only ever added. Do not run the release workflow again for a tag
whose digests are pinned: it replaces the tarballs, the builds are not
bit-for-bit reproducible, and every panel that pins the old ones would refuse
the new ones. Cut a new version instead.

## Issue numbers

Numbers such as `(#61)` in comments and in changelog entries through 0.5.0
are from the private repository this was developed in.
