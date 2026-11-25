# Changelog

Issue and pull request numbers in entries through 0.5.0, such as `(#61)`, are
from the private repository this was developed in before it was published.

## Unreleased

- **Install kub0** installs 0.5.2. The panel now carries the digests of the
  two 0.5.2 tarballs, taken from downloads whose build provenance for the
  0.5.2 tag verified. Between the tag and this change the button downloaded
  nothing and said so.

## 0.5.2 (2026-11-25)

Four security fixes, all found in the Omarchy plugin marketplace's review of
0.5.1 and reported privately. Update the plugin, then use **Install kub0**
again (or run `sudo ./kub0 install` from this release): the new daemon closes
an existing install's state directories the first time it starts.

- **Install kub0** checks the download against a digest the panel carries,
  not one from the release. The script fetched the tarball and the checksum
  file it was checked against from the same GitHub release, so anyone able
  to replace that release's files could replace both, and the tarball's
  `kub0 install` then ran as root. The sha256 of each release tarball is now
  a line in `scripts/release-digests`, in the plugin's own source: what the
  button runs is fixed by the commit the panel is at. A tarball with any
  other digest is refused, `KUB0_RELEASE_BASE` changes where it is fetched
  from and not what it must be, and the release's checksum file is no longer
  downloaded. A panel with no digest for its version downloads nothing and
  says to update the plugin or build from source. The two 0.5.1 tarballs
  are pinned; both carry a build provenance for the 0.5.1 tag, and nothing
  suggests either was ever replaced.
- The system daemon's records could be read by every account on the machine,
  not only by root and the `kub0` group. `/var/lib/kub0/daemon` and
  `/var/lib/kub0/execgate` were created 0755 and most files in them 0644:
  the log of unattributed connections (account, address, host name), the
  activity timeline, network names, and the exec gate's frame with the path
  and digest of everything it stopped. The history database beside them was
  already private. Now `daemon/` is root's alone (0700), `execgate/` is
  root's and the `kub0` group's (2750, `state.json` 0640), and the helper's
  `cgroup-restore/` is root's alone. The daemon applies this at every start,
  so an existing install is closed by the first start after updating; the
  journal says once what it closed. Without a usable `kub0` group
  `execgate/` is root's alone. The per-user daemon closes
  `~/.local/state/kub0` the same way. `SECURITY.md` has the table of what is
  where and who reads it.
  - Still readable by every account, on purpose: which apps are blocked, the
    addresses of "endpoints only" blocks, and whether enforcement is paused.
    The panel reads those through `kub0-block status` as whoever runs it.
  - One thing a session outside the group loses: a per-user daemon there
    (source build, before the first login after `kub0 install`) no longer
    mirrors the exec gate, so that panel shows no exec gate until you log
    in again. `kub0 doctor` says the file is the group's when it cannot
    read it.
- An "endpoints only" block could be lifted by another app's unblock. The
  helper keeps one file that says which app blocked which address, and it
  read a file it could not understand (damaged, or empty after a crash in
  the middle of a write) as "no blocks". The next block then saved that
  near-empty record over the real one, and unblocking that app released an
  address a different app still had blocked. Now only a missing file means
  no blocks. A file that is there and unreadable stops the block or unblock
  before anything changes, and the message names the way out: `sudo kub0
  teardown --yes` lifts every block and starts again. The file is also
  written so that a crash leaves the old record or the new one, with its
  mode set rather than left to the caller's umask, and `kub0-block status`
  says `ownersKnown: false` instead of showing an unreadable record as empty.
- On the system daemon, one file in another account's
  `~/.local/share/applications` could stop monitoring for everyone. The
  daemon reads those `.desktop` files, as root, to name that account's apps,
  and it read whatever was there: a named pipe ending in `.desktop` made it
  wait for ever, on the thread that samples connections, and a link to a
  device such as `/dev/zero` was read without end. It now reads only regular
  files that the account itself owns, each up to 256 KiB, and at most 1,024
  entries or 8 MiB for one account. Anything else is skipped, and that app
  takes its name from the shared directories or from its binary.
- Development: two of the daemon's tests could be handed the same temporary
  directory when they started in the same tick of the clock, and then read or
  removed each other's files. It showed up as two different tests failing now
  and then on the Intel macOS runner. Each test now gets a directory of its
  own. No shipped code changes.

## 0.5.1 (2026-11-22)

The release the public repository starts from. A panel added with `omarchy
plugin add` says what is missing and installs kub0 in one step; a release is
one tarball per architecture with its license notices; and the daemon reads
the databases it enforces from, from its data dir only.

- `preview.png`, the picture a plugin listing shows, is this panel: the
  Overview and Apps views, rendered from a fixture by
  `tests/qml/make-preview.sh`. It was the upstream project's picture. Nothing
  in it is a real connection: every address is from a documentation range
  and every host name ends in `.example`, and a test holds the fixture to
  that.
- The plugin's description, the sentence a listing shows under its name, says
  what this panel does: where each app connects by country and network,
  per-app blocks, traffic history, and the `kub0` command. It was the
  upstream project's sentence.
- The panel installs with `omarchy plugin add
  https://github.com/kub0-ai/kub0-agent --enable`, and a panel with no daemon
  says what to do next. Before, all it said was "kub0d is not available".
  - **First run.** The Overview opens with what is missing and why: kub0 is
    not installed; or it is and this session has not joined the `kub0` group
    yet (log out and back in once, or reboot where the user service manager
    outlives a logout); or the account is not in the group; or it is all in
    place and the daemon is stopped or too old for the panel. Before, the
    second of these read "the system daemon is not answering", and a panel
    that had said "not built" kept offering to build after kub0 was
    installed.
  - **Install kub0** (Overview, Settings, or `i`) opens a terminal that
    downloads the release matching the panel for this architecture, refuses
    it unless its sha256 is the one the release's checksum file lists, and
    runs its `sudo ./kub0 install` (`scripts/install-release.sh`). **Build
    from source** is still there.
  - **A setup terminal that fails no longer locks the setup buttons.** They
    stayed disabled for ten minutes after any setup terminal was opened,
    unless it succeeded. They work again as soon as its command ends.
  - **Versions.** The panel and the daemon are installed separately, so they
    can differ. When they do, the Overview names both versions and the one
    command that fixes it: `omarchy plugin update` when the panel is behind,
    `./scripts/install-release.sh` when the daemon is. `omarchy-shell
    ai.kub0.agent status ''` reports `panelVersion`, `daemonVersion` and
    `setup`. A release whose `manifest.json` and `Cargo.toml` versions differ
    is refused: the panel would install one and compare itself with the
    other.
- The README and the release's `INSTALL.md` say that kub0 accounts are not
  open to the public yet, and that everything except connecting to an org
  works without one. `kub0 install` no longer ends by telling everyone to
  log in: "With a kub0 account, `sudo kub0 login` joins your org".

- The tree is ready to be read by someone outside the org. The README opens
  with what the agent is, under its name (`kub0 agent`), and no longer says the
  project is private; what was verified on a real machine moved to
  `docs/VERIFICATION.md`. `THIRD-PARTY.md` describes the published history
  (upstream's 13 commits unchanged, then kub0's work), states where
  `data/country-centroids.json` comes from and what the capture program is
  licensed under, and `LICENSE` carries kub0's copyright line under
  upstream's. New: `SECURITY.md` (how to report a vulnerability, and what
  runs as root) and `CONTRIBUTING.md`.
  - The capture program declares `Dual MIT/GPL` to the kernel instead of
    `GPL`, which is what its license is. The kernel treats both as
    GPL-compatible, so what it may call does not change.
  - Nine run journals left `docs/` (the Darwin, endpoint, policy, recovery,
    roadmap, system-status and v0.2 verification notes, and the 2026-10-04
    enhancement list): they recorded who ran which check during development,
    not how the agent behaves. `docs/system-status.md` and
    `docs/ENDPOINT-INVENTORY.md` keep their contract and lose the same kind of
    text; `docs/FLEET-NETWORK-POLICY.md` no longer describes the server's
    tables.
  - Test fixtures and comments name no machine, account or address of ours:
    the fixture account is `alice`, the route fixtures use `10.20.0.0/24` and
    `10.99.0.0/16`, and the server is "the kub0 API".
- A release is something a stranger can install. Each architecture gets one
  tarball, `kub0-agent-<version>-<target>.tar.gz`: unpack it and run
  `sudo ./kub0 install`. It holds the three binaries, the two geo databases
  (so country rules work on a server with no panel), a short `INSTALL.md` and
  the license notices. The loose binaries are still attached, and
  `SHA256SUMS-<target>` now covers the tarball too. The same inputs give the
  same tarball, byte for byte.
  - `THIRD-PARTY-LICENSES.md`, new in every release, is the license text of
    each Rust crate in the build graph (96 crates, each text printed once,
    including the ones a crate carries for code it vendors), and of what
    every static binary links besides: Rust's standard library and musl
    libc. A release fails rather than leave one out.
  - The release's notes are that version's section of this file, and a tag
    that does not match `Cargo.toml`'s version stops before it builds.
  - On a public repository the tarball, the binaries and the checksum file
    of a tagged release each carry a signed build provenance
    (`gh attestation verify <file> --repo kub0-ai/kub0-agent`).
- No workflow here asks for the kub0 self-hosted runner on a public
  repository, whatever the runner variable says, and every action is pinned
  to a commit. Both are tested. (What refuses a fork's own workflow is the
  runner group, which is closed to public repositories.)
- `kub0 install` points at `github.com/kub0-ai/kub0-agent/releases` when it
  says where a newer release is.
- **The daemon reads the databases it enforces from, from its data dir
  only.** The country and ASN loaders had a third place to look, `data/geoip/`
  under the working directory. A system daemon's working directory is `/`,
  so one whose data dir had no database would read `/data/geoip/…`, a path it
  does not own and another account may be able to write, and build an org's
  country and network rules from it. Nothing in its log said where the
  database had come from. It took a missing database and a writable `/data`
  to reach, and it is gone. Without an ASN database in its data dir the
  daemon applies no block rules; without a country database it applies none
  while the org has a country rule. Either way it says so, and rules already
  in the kernel stay.
  The panel's own daemon is given its data dir, and a bare `kub0d` defaults
  to `data`, so neither used the third place. (`--mmdb` can still name the
  map's country database anywhere. Nothing that enforces a rule reads it.)
- The optional kernel capture builds with clang 21 and 22, which is what
  Ubuntu 26.04 installs. `capture/build.sh` stopped there with "BPF stack
  limit is exceeded": the DNS response program needed 584 bytes of stack
  where the kernel allows 512. It needs 384 now. With clang 23 the program
  that is built is the same, instruction for instruction.

## 0.5.0 (2026-11-20)

One daemon (#61). Where the system daemon is installed it is the only daemon:
the panel reads it and starts none of its own, and `kub0` has one route.

- `kub0` has one route (#61, one daemon). Every command goes to the system
  daemon when its socket lets the caller in, and to their own otherwise.
  - `kub0 watches` and `kub0 watch add|rm` no longer go to the user daemon
    first, and `kub0 tag` no longer goes to both and prints an outcome for
    each. They see and change the list the panel shows.
  - The help names no daemon per command. `kub0 watch --help` says whose the
    rules are.
  - `kub0 tag <network> --clear` takes a name away; the CLI had no way to.
    `kub0 tag` prints one line. With `--json` it prints the daemon's reply
    (`networkKey`, `label`, `deleted`), where it printed one object per
    daemon (`system`, `user`); a refusal is exit 1 with the reason on stderr.
  - A name given to your own daemon while a system daemon is installed (you
    are not in the `kub0` group, or you passed `--user`) is said to stay on
    this machine: that daemon reports nothing to the org.
  - `kub0 doctor` no longer warns about a user daemon that nobody is
    listening on beside a system daemon that answers: that is how it should
    be. One that is there and does not answer is still a warning.
  - A panel with capture on still keeps its watch rules and names in its own
    daemon; `kub0 --user watches` and `kub0 --user tag` reach it.

- `kub0 install` carries a person's watch rules and network names over to the
  system daemon (#61, one daemon). They lived in the panel's own daemon, which
  the panel no longer starts on a system install.
  - Once per person: `sudo kub0 install` reads `watchlist.json` and
    `tags.json` of whoever ran it from `~/.local/state/kub0` (or
    `~/.local/state/vallum`, where 0.4.4 and earlier kept them), as that user
    and not as root, and sends each entry to the system daemon as a request.
    A marker in the daemon's state directory keeps a later install from
    bringing back a rule they deleted.
  - Nothing already on the system daemon is overwritten: a rule or a name
    that is there, whoever set it, is left as it is and listed.
  - A person is noted as carried over only when it is done. If a file could
    not be read or the daemon stopped answering, the install says so and the
    next one carries over the rest.
  - A carried name keeps the reverse-DNS suffix it was given under, so the
    org can still tell when the network has changed hands. Names are sent to
    the org with the heartbeat, as `kub0 tag` names are; the install says so.
  - Names the org sent are not carried (the org sends them), and neither are
    history, the activity log or the seen-set: the system daemon has kept its
    own since it was installed.
  - A watch rule root sets for someone is theirs. `watch-set` with `as_uid`
    recorded root as the owner, so the person could neither rename nor remove
    it without root. This also applies to `sudo kub0 watch add`, which acts
    for the sudo caller; root can still change any rule.

- Destination sharing is a setting of the system daemon (#61, one daemon). It
  was a start-up flag that only the panel's own daemon was ever given, and
  next to a logged-in system daemon that daemon defers its heartbeat and
  drops what it collected: the panel's switch had no effect there.
  - `sudo kub0 share on` and `kub0 share off` (`share-on` is root's, since it
    decides what leaves the machine; a member may turn it off). Bare
    `kub0 share` and a new row in `kub0 status` show it.
  - The choice is saved in the daemon's state directory before it takes
    effect and read at the next start. `--share-destinations` still turns it
    on for one run.
  - Off means off at once. The keys queued for the next heartbeat are
    dropped when sharing is switched off, a batch a failed heartbeat had in
    flight is not put back, and no key is collected while logged out (it would
    have gone to whichever org logged in next).
  - The panel's switch drives that setting whenever the system daemon has
    said what it is, also while the panel runs its own daemon for capture
    (turning it on asks for an administrator), and shows what the daemon
    reports. With no system daemon to ask it stays the panel's preference,
    which follows the last choice made on the system daemon.

- The panel reads the system daemon and starts no daemon of its own (#61, one
  daemon). Until now it took its whole event stream from a `kub0d` it spawned
  and only sent changes to the system daemon.
  - When the system daemon is installed and the session is in group `kub0`,
    the panel connects to `/run/kub0/kub0.sock` for its rows, history, watch
    rules, activity and exec gate. It shows the whole host, as `kub0 apps`
    does: system services and other accounts' connections are listed.
  - The panel still starts its own daemon when the system daemon cannot be
    used from the session, and while capture is switched on. It switches by
    itself in both directions (it asks the system daemon again every ten
    seconds while it is not reading it), and rides out a restart of the
    system daemon. With no `kub0d` of its own to start it says the system
    daemon is not answering and keeps asking, where it used to say "kub0d is
    not built".
  - A block from the panel names only the processes of the account using
    it. The system daemon gives a binary the same app id under every account,
    so one row can hold another account's processes, and the helper refuses
    a block that names one.
  - Reading the system daemon, the account card and the policy list are its
    live frames. The `status` and `policies` read the panel makes when it
    opens is no longer laid over them (it went stale while the panel stayed
    open); it only supplies who the account is.
  - Reading the system daemon, a watch rule is a `watch-set`/`watch-delete`
    request and a name is one `tag` request; the panel no longer writes the
    `watch`, `tag` and `note` lines that daemon takes from root only.
  - Not yet moved: the "share destinations" switch (it has no effect next to
    a logged-in system daemon, as before; a setting on the system daemon is
    next), and the CLI's routes for `watches`, `watch` and `tag`.

- A daemon answers the client that asked (#61, one daemon). On a system
  install the socket admits the whole `kub0` group, and three things were
  still shared between every client:
  - The `history`, `investigate` and `timeline` frames, and a `ping`'s
    `status`, went to every client. They go to the one that sent the line.
  - `panel-open` and `panel-close` set one flag for the whole daemon, so one
    panel closing put it into the battery-saving cadence under another that
    was still open. Open panels are counted per client, and a client that
    disconnects without closing no longer counts.
  - The `digest` of what arrived while no panel was open went to every
    client. It goes to the first panel that opens.

## 0.4.8 (2026-11-19)

- The exec gate no longer starts empty (#86). The org deny list lived only in
  memory, so a daemon that started while the kub0 API could not be reached
  held no org keys until the API answered: for the first minutes of every
  boot, before the network is up, and for the whole of an outage after a
  restart or an upgrade. Nothing said so; `kub0 doctor` still ended with
  "nothing missing".
  - Every list the API returns is written to
    `/var/lib/kub0/execgate/org-list.json` (mode 0600), and the next start
    loads it for the same account. The gate is armed when the daemon starts,
    with the list as of its last sync. Digests trusted on this machine are
    subtracted from it as from any list.
  - Only a list the API returned replaces the gate's keys. A failed fetch
    used to hand the gate whatever the process held, which after a restart
    is nothing.
  - `kub0 status` and `kub0 doctor` say when the keys are from the saved
    list and how old it is (`55 keys from the org list saved 3h 12m ago (no
    sync since the daemon started)`), and the panel's Settings heading says
    the same. `kub0 doctor` warns when a logged-in host's gate has no org
    list at all.
  - The list belongs to the account it arrived under. `kub0 logout` removes
    the saved list with the keys, a list saved under another account is
    removed, not loaded, and a login as another account (or on another
    server) takes the previous account's keys out at once: they no longer
    stay until the new account's first list, which may never arrive.
  - A list that fails to save removes the older copy, so a restart never
    loads a list the org has since changed.
  - A 200 from the deny-list poll with no `entries` field is an error, not an
    empty list. Read as empty it cleared the gate.
  - A deny-list stream that has been told to stop (a logout, a new account, a
    rotated token) applies no further frame.
  - The gate frame gains `listReceivedAt` and `listRestored`.

## 0.4.7 (2026-11-16)

- The 0.4.x names that 0.4.5 and 0.4.6 kept alive for compatibility are gone
  from an installed host. The upgrade itself stays: a host on any 0.4.x still
  upgrades in one `kub0 install` (state moved, group renamed in place).
  - `kub0 install` removes what it used to keep: the links at
    `/usr/lib/vallum/{vallumd,vallum-block,kub0}`, a 0.4.x collector left
    there, the directory itself (unless it holds something kub0 did not put
    there, which is named and left), the `vallumd.service` alias and both
    0.4.x polkit policies. It does this only once kub0d runs, so a rollback
    still finds the 0.4.x binaries.
  - It also removes `/run/vallum` and the socket link in it. The unit no
    longer lists that directory, so systemd would have left it until the
    next boot.
  - `kub0d.service` has one name and one runtime directory: no
    `Alias=vallumd.service`, no `/run/vallum`. kub0d makes no link at the
    0.4.x socket paths.
  - The `ai.kub0.agent.compat.*` polkit actions (the helper at its old path)
    and `ai.kub0.agent.capture.compat` are removed.
  - A `VALLUM_*` environment variable is not read. One that is still set,
    with its `KUB0_*` name unset, logs one line saying so, so a switch such
    as the exec gate's does not stop working in silence.
  - The status group is `kub0`. A host that still has only `vallum-status`
    gets no status or command socket for its users, and the journal says to
    run `sudo kub0 install`, which renames it in place.
  - The exec gate no longer treats `/usr/lib/vallum` as a directory of
    critical binaries, nor `vallumd` and `vallum-block` as critical names.
  - The panel talks to one socket and runs one helper path; the status check
    runs `/usr/lib/kub0/kub0d` or nothing. `kub0` no longer falls back to a
    0.4.x daemon's socket, and a user daemon no longer leaves its heartbeat
    to a 0.4.x system daemon.
  - `scripts/install-capture.sh` removes the 0.4.x collector and its policy
    instead of linking the old path.
  - `kub0 doctor` lists every one of these still found on a host under
    "0.4.x leftovers".
  - CI reads only the `KUB0_LINUX_RUNNER` repository variable.
  - The rename guard's allowlist went from 27 sites to 16: the migration,
    the guards that refuse an old name, and the panel's own carry-over. A
    file that held only an alias is no longer listed, so an old name there
    fails the build.

- The panel's last two old names are gone: the plugin id is `ai.kub0.agent`
  (it was `ai.kub0.vallum`) and its settings are in `~/.config/kub0/ui.json`
  (they were in `~/.config/vallum`). `VallumAdapter.qml` is `Kub0Adapter.qml`.
  - Settings carry themselves over. The first start finds no file in the new
    folder, reads the old one and writes the new one at once. The old file is
    never written or deleted. Once the new file exists it always wins.
  - The plugin folder and the bar entry are named by the id, so an installed
    panel needs its folder renamed and `"id"` changed under `bar.layout` in
    `~/.config/omarchy/shell.json`; the README's upgrade section has the
    steps.
  - A hotkey written under the old id opens nothing now. The panel no longer
    reads it as another app's key or as a working one: the offer comes back in
    Settings, the write puts the new command on the same keys, and
    `compat/install-binds.py` removes the old marked block from
    `~/.config/hypr/bindings.lua` when it writes the new one.
  - The rename guard now fails on the old plugin id and the old settings
    folder anywhere outside the three places that read them.
- `kub0 sync` no longer says "the org has no block rules" when the org has
  one in a monitor-mode policy. With nothing to enforce it now says
  `nothing to apply: no org policy blocks on this device (none, or monitor
  mode only); no fleet rules are in the kernel`.

## 0.4.6 (2026-11-16)

- Scrolling in the panel is faster, keeps moving, and is yours to set.
  Settings has a new **Scrolling** section: four speeds (Slow, Normal, Fast,
  Fastest) that apply at once to every list, and a switch for momentum. The
  choices are `scrollSpeed` and `scrollMomentum` in `ui.json`.
  - Eight of the panel's eleven lists (History, Endpoints, the evidence
    drawer and all of Intel) had no wheel handling of their own, so they got
    Qt's: the touchpad's travel as the desktop scales it (Omarchy ships
    `scroll_factor = 0.4`) and nothing more. Every list now uses one handler,
    `WheelStep.qml`, and a test fails when a new list has none.
  - A list keeps moving when a touchpad swipe ends and slows to a stop; a
    faster swipe travels further. Qt gives no momentum on Wayland, which is
    why a long list was all finger work.
  - A mouse-wheel notch moves three rows, and a fast run of notches
    accelerates. Qt on Wayland fills a pixel delta for a wheel as well as a
    touchpad, so the old handler read every notch as a 15-pixel swipe and
    moved under one row. The handler now tells the two apart by the scroll
    phase, which only a finger has.
- Text size, spacing and panel size are yours to set. Settings has two new
  sections:
  - **Text and spacing**: text size (Small, Normal, Large, Larger: 0.9 to
    1.3 times the shell's own) and spacing (Compact, Normal, Roomy: the gaps
    between rows and sections at 0.6 to 1.4 times). They apply at once to
    every view. At Normal the panel is pixel-for-pixel what it was.
  - **Panel size**: width (Normal, Wide, Widest) and height (Normal, Tall,
    Full screen). The shell still fits the panel to the screen.
  The choices are `textSize`, `density`, `panelWidth` and `panelHeight` in
  `ui.json`. Two of the shell's own controls take no text size from a plugin
  and stay as the shell draws them: the header (name and state) and the
  dropdowns.
- Times and units are yours to set. Settings has a **Time and units**
  section:
  - **Times**: Mixed (the panel's own, and the default: how long ago for
    what is live, the locale's full date for what is logged), How long ago
    ("2m ago", "in 25m") or Clock time ("09:38:23" today, "Nov 14 21:05"
    this year, "2025-03-04 07:08" before). The last two say every timestamp
    the same way: History, Endpoints, connection evidence, the Intel drawer,
    watch-rule hits, activity lines, exec-gate matches, a rule's snooze and a
    timed destination rule's expiry. The age of the live feed ("65s ago" on
    a stale panel) is a duration, not a timestamp, and stays as it is.
  - **Sizes and speeds**: KiB and MiB (1024s, the default) or kB and MB
    (1000s).
  The choices are `timeStyle` and `byteUnits` in `ui.json`.
- `kub0 sync` works (#63). It failed every time: the daemon ran the helper's
  `fleet-sync` itself with no rule list, and the helper stops there. The
  request now goes to the daemon's own applier, the one caller that holds the
  org's list, which applies it again and answers with what the kernel holds:
  `applied the org's block rules: 3 rule(s), 41 entries; enforcing`, the same
  `enforcement` object `kub0 policies --json` reports, and a non-zero exit
  with the reason when the rules could not be applied.
  - Asked for, the rules are applied again even when the plan has not
    changed. The heartbeat's own pass over an unchanged plan only checks that
    the chain's rules are there, not the address sets behind them, so this is
    the repair when those were emptied by hand.
  - With no block rules from the org it clears the fleet rules from the
    kernel, whether or not this daemon put them there. An org list that has
    not been received yet clears nothing.
  - A daemon that is not logged in says so, and one that is mid-heartbeat
    for 45 seconds says that and applies when the heartbeat ends.
- `tests/qml/run-runtime.sh` can render the panel to PNGs for looking at a
  layout change: `VALLUM_SHOTS="apps:larger:compact:normal:normal" ...`.
- `tests/qml/run-runtime.sh` starts on a host that was upgraded from 0.4.x,
  where the old helper path is a symlink that bwrap cannot mount over.
- A full artifact store no longer fails a build or empties a release. On
  2026-11-16 the account's Actions artifact storage filled up and every
  upload was refused ("Artifact storage quota has been hit").
  - `release.yml` uploaded its spare copy before it attached the binaries to
    the GitHub Release, so a tag would have published a release with no
    files. The attach steps now run first, and on a tag a refused upload is a
    warning. A run without a tag has no Release, so there it still fails.
  - `build.yml`: a refused upload is a warning on the run, not a failed musl
    build. Nothing downloads that artifact.
  - Both keep artifacts three days instead of the default 90, which had this
    repository alone at 1.3 GiB.

## 0.4.5 (2026-11-14)

- The rename (#61 step 3): `kub0` on every name the agent puts on a host,
  with one release of compatibility so an upgraded 0.4.x host loses nothing.
  `vallumd` is `kub0d`, `vallum-block` is `kub0-block`, `vallum-capture` is
  `kub0-capture` (the crates keep their names); `/usr/lib/vallum`,
  `/var/lib/vallum`, `/usr/share/vallum` and `/run/vallum` are the same paths
  under `kub0`, and the sockets are `kub0.sock` and `kub0-status.sock`;
  `vallumd.service` and `vallum-expiry.*` are `kub0d.service` and
  `kub0-expiry.*`; the group `vallum-status` is `kub0`; polkit
  `ai.kub0.vallum.*` is `ai.kub0.agent.*` in `ai.kub0.agent.policy`;
  `VALLUM_*` variables are `KUB0_*`; the panel's title and messages say
  kub0. The plugin id stays `ai.kub0.vallum` and its settings stay in
  `~/.config/vallum`; moving either would lose them.
- What stays for one release: the old binary paths are links to the new
  binaries (`vallumd` a hard link, because a 0.4.x panel's status check
  refuses a symlinked one; the retired client verbs still answer through it);
  `kub0d.service` has `Alias=vallumd.service`, so `systemctl status vallumd`
  answers; `/run/vallum/vallum.sock` is a symlink to the command socket while
  kub0d runs (`RuntimeDirectory=kub0 vallum`, never a second listener); the
  daemon still resolves `vallum-status` when no `kub0` group exists, and uses
  neither when both do; a `VALLUM_*` variable is read when its `KUB0_*` name
  is unset, with one deprecation line; the per-user daemon's `vallum.sock` is
  a symlink to `kub0.sock`; a panel updated before `kub0 install` runs again
  falls back to the old socket, helper and status binary. The deprecated
  helper actions, the panel's helper fallback and the client-verb shims all
  stay, renamed.
- Polkit and the old helper path: from polkit 127, pkexec resolves the program
  with `realpath(3)` before it looks for an action, so `pkexec
  /usr/lib/vallum/vallum-block` (a 0.4.x panel's fallback) finds the renamed
  `ai.kub0.agent.<verb>` action; polkit 126 and earlier match the path as
  given, and the new `ai.kub0.agent.compat.<verb>` actions, same defaults,
  cover it there. A test replays pkexec's lookup both ways over the shipped
  policy, so neither version can fall to the generic exec action.
- The move: system state moves in exactly two places, `kub0 install` and
  `kub0d migrate-state`, the unit's `ExecStartPre=+` (outside its sandbox):
  one `rename(2)` of `/var/lib/vallum` to `/var/lib/kub0`, never a copy, with
  the account, exec-gate trusts, scoped and block records and the expiry
  timer's records. A plain `kub0d --system` or `--replay` start never moves
  anything, so a run by hand beside a stopped 0.4.x install cannot strand it.
  An empty skeleton at the new path is cleared first, so an interrupted move
  simply runs again; real state at both leaves the old directory untouched and
  says so. A move the kernel refuses (another filesystem, an empty mount point
  at the new path, which returns EBUSY) moves nothing, and kub0d, the helper,
  the CLI and the expiry timer all stay on the old directory: a new path that
  holds only empty directories never counts as the one in use. The unit no
  longer has `StateDirectory=` (systemd would create `/var/lib/kub0` before
  the move). The per-user daemon moves `$XDG_STATE_HOME/vallum` only when
  started with `--migrate-state`, which the panel passes; a bare start never
  does. Nothing moves while a 0.4.x daemon is running on that directory, found
  by its process (argv[0] `vallumd`, and its own `--state-dir` or environment
  for a per-user one) rather than by a socket path it might not have used. The
  helper never recreates `/var/lib/vallum` once it is gone.
- `kub0 install` does the rename on a 0.4.x host in an order that never
  leaves the host without an enabled daemon: it refuses first, changing
  nothing, when a `kub0` group exists beside `vallum-status`, or when the group
  it would keep or rename is not a system group or is some account's primary
  group (the rule kub0d applies to its socket group too, so a `kub0` user's
  private group is never handed the command socket or the installing user).
  It then stages everything at the new paths (binaries, polkit policy, geo
  databases, the exec gate's directory, `kub0d.service` and `kub0-expiry.*`,
  `daemon-reload`), renames the group with `groupmod -n` (same GID and
  members), and only then stops, disables and removes `vallumd.service` and
  `vallum-expiry.*`, moves the state and starts `kub0d.service`. If the move
  or the start fails, it puts the 0.4.x units back, moves the state back and
  starts vallumd again. The old binary paths become links, and the 0.4.x policy
  and geo data go, only once kub0d runs. `--no-start` on a host where
  vallumd.service is installed stages and stops there: it never retires the
  running daemon, renames its group or moves its state, and says how to switch.
  Without systemd, install refuses while a 0.4.x daemon runs (stop it from
  your init first), since kub0d beside it would be a second exec gate. It now
  also restarts the daemon when the geo databases change.
  `scripts/install-privileged.sh` runs `kub0 install` instead of repeating it
  in shell (still adding nobody to the group).
- `kub0 doctor` reports the old group, units, policy, directories and binaries
  a 0.4.x install left; fails while the state is still only at
  `/var/lib/vallum`, or at both directories, which is the gate for the release
  that drops the old names; and, run as root, warns about local polkit rules
  (`/etc/polkit-1/rules.d`, `/usr/share/polkit-1/rules.d`) that name an
  `ai.kub0.vallum.*` action, which silently stop matching after the rename.
- `kub0 install` from a directory of release binaries no longer mistakes
  `kub0-block-<target>` for the CLI: the part after a name must be a target
  triple. Release artifacts are `kub0d-<target>`, `kub0-block-<target>` and
  `kub0-<target>`; the workflows read `KUB0_LINUX_RUNNER`, and
  `VALLUM_LINUX_RUNNER` until the repository variable is renamed.
- Not renamed, because they are kernel and server state rather than names:
  the nftables table `inet vallum`, the `vallum.slice` cgroups and the rule
  comments in them (renaming would strand live blocks), and the heartbeat's
  `agent: "vallum"`, which the kub0 API keys endpoints on.
- A 0.4.x panel's own user daemon still looks for `vallumd` and
  `/var/lib/vallum/account.json` before it leaves the heartbeat to the system
  daemon, so until the panel is updated both send it (#52's double row).
- Geo databases across the rename: kub0d reads them only from
  `/usr/share/kub0/geoip`, and a release download ships none, so a host
  upgraded from a 0.4.x release would have lost its country and ASN lookups
  (and with them every country rule) while the old set sat unread in
  `/usr/share/vallum/geoip`. `kub0 install` now carries that set over when
  none is beside the binaries and none is installed yet, then removes the old
  copy. With a set already installed it says it is keeping it; the "applies
  no country rules" warning is left for a host that has none anywhere.

## 0.4.4 (2026-11-11)

- `sudo kub0 install` run as the installed copy (`/usr/bin/kub0`) said
  "no vallumd in /usr/bin; pass --from DIR", and `--from` there would only
  have reinstalled the same version. It now says this is the installed kub0
  and how to upgrade: unpack a newer release and run its `kub0 install`.
- `kub0` reads what the panel shows (#61 step 2): `kub0 apps [--sort
  bandwidth|connections|recent|name] [--blocked|--live] [--mine]`, `kub0 conns
  [--app APP] [--unattributed] [--follow]`, `kub0 activity [--since 1h]`,
  `kub0 history [--hours N] [--query TEXT] [--csv|--ndjson]`, `kub0 intel
  [--timeline]`, `kub0 why <app|ip|kind:value>`, `kub0 policies`,
  `kub0 watches` and `kub0 brief`, all with `--json`. Each is a `Read` verb
  the daemon answers from its own state, the data the panel's views and the
  old `vallumd` client verbs read. On the system daemon a row names its
  owner; `--mine` keeps the caller's own and is opt-in, since the rows a
  reader most needs there (system services, other accounts) are the ones a
  default would hide.
- `vallumd connect|status|disconnect|history|brief|investigate|timeline|watch`
  are retired: each prints the `kub0` command that replaced it and exits 2,
  for one release. The panel's own Connect and Disconnect without a system
  daemon now run the `kub0` next to vallumd on the user daemon's socket.
  `status`, `history` and `disconnect` were the offline readers of a state
  directory; state is now read back only through a running daemon, and one
  left under temporary storage is reached by starting `vallumd` with
  `XDG_STATE_HOME` at its parent (`tests/test_state_dir.py` proves the path).
- Policy snoozes go to the system daemon, the only one that enforces. The
  panel's snooze has never reached enforcement: it was a line to the user
  daemon, which keeps its own snoozes and enforces nothing, so a block rule
  read "snoozed" while the system daemon kept dropping the traffic. A snooze
  now runs `pkexec /usr/bin/kub0 --json policy snooze` (one prompt each time)
  and a resume is a `policy-resume` request; the panel's policy list and its
  snooze state come from the system daemon's new `policies` read. When the
  system socket cannot be reached but `/usr/bin/kub0` is installed (you are
  not in `vallum-status` yet, or have not logged in again since), a snooze or
  resume still runs `pkexec /usr/bin/kub0`, and the panel says it cannot show
  the result until you log in again. Only a per-user install (no
  `/usr/bin/kub0`) keeps the user daemon's snooze, which only quiets alerts.
- The panel's account card shows the system daemon's account (its `status`)
  when it is reachable, read on panel open and after a login, logout, snooze
  or resume, so a system-daemon login no longer reverts to "not connected"
  when the user daemon next reports.
- Tags go to both daemons, from the panel and from `kub0 tag`: the user
  daemon, whose rows show the name, and the system daemon, whose heartbeat
  carries it to the org (the 0.4.2 known gap). If the system daemon refuses
  or cannot be reached the user daemon's copy still applies, and the panel or
  the command says so.
- Watch rules stay with the user daemon, the panel's alerts, and `kub0 watch`
  and `kub0 watches` now go there too while a user daemon runs, falling back
  to the system daemon only on a system-only install. `kub0 watch --help`
  and the README state this exception to "system first".

- The panel sends its changes to the system daemon. It still reads from its
  own per-user daemon (rows, history, capture, watch rules, tags, policy
  snoozes, activity, and it still starts that daemon), but a block, unblock,
  destination rule, pause/resume or exec-gate trust now goes to the system
  daemon: a raise as a control request on a short-lived request-only
  connection to `/run/vallum/vallum.sock` (no prompt for a `vallum-status`
  member), anything the daemon keeps to root (unblock, cancelling a
  destination rule, pause, trust, allow once, the address-block fallback) as
  `pkexec /usr/bin/kub0 --json …`. The helper through pkexec stays as the
  fallback for one release, when the system socket cannot be reached. The
  exec-gate notification's buttons run `pkexec /usr/bin/kub0 trust|allow-once`.
  (Watch rules, tags and policy snoozes: see the routing entries above.)
  The panel keeps noting each block outcome in the per-user daemon's
  activity log, once per outcome; the system daemon records the blocks it
  ran in its own.
- The panel's Connect logs in the system daemon's account
  (`pkexec /usr/bin/kub0 --json login`, its codes read line by line and its
  final reply at exit) when the system socket is reachable, and Disconnect
  runs `kub0 logout`; otherwise the user daemon's account, through kub0.

- `kub0` asks polkit for what needs root. A non-root caller on a desktop
  (`WAYLAND_DISPLAY` or `DISPLAY` set) whose request the system daemon would
  refuse (a lowering verb, `login`, an address block) re-runs as
  `pkexec /usr/bin/kub0 <same arguments>` and exits with that command's
  status. New polkit actions `ai.kub0.vallum.kub0` and `…kub0-lib` name the
  two installed CLI paths and ask every time; `KUB0_NO_PKEXEC=1`, a headless
  shell or a missing pkexec keep the `sudo kub0 …` hint. The helper actions
  are marked deprecated; the panel still uses them, and they go after it
  moves to the daemon's socket.
- `as_uid`: a control request may name the user it acts for. The daemon
  honours it only from uid 0 and refuses the request from anyone else, never
  silently dropping it; helper-backed verbs then hand that uid to the helper
  as `PKEXEC_UID`, so ownership checks act on the user. The daemon's hello
  says it honours the field (`as_uid: true`). `kub0` running as root sends
  it, from `PKEXEC_UID`, else a non-root `SUDO_UID` (so `sudo kub0 block
  <app> --pid …` acts on the sudo caller's processes, where it used to check
  them against root), and only to a daemon whose hello says so: a change to
  an older daemon is refused ("this daemon is older than the CLI and cannot
  act for another user; update vallumd") rather than run as root.
- The daemon records block outcomes itself. A `block`, `block-dest`,
  `unblock` or `unblock-dest` it runs adds the activity record the panel's
  `note` line adds for the blocks it runs itself (`block`, `block_failed`
  with the helper's error, `unblock`). A helper refusal now reaches the
  caller with its fields (`error`, `code`, `rollback`) instead of flattened
  into a string.
- A parity test (`daemon/tests/parity.rs`) holds the daemon's verb table,
  the `kub0` command table and the panel's socket lines together: every verb
  that changes anything has a `kub0` command, `kub0` sends no verb the daemon
  does not answer, and every line the panel writes is one the daemon
  classifies.

- The group raises, root lowers. The system daemon's command socket
  (`/run/vallum/vallum.sock`) is now root:vallum-status 0660, so members of
  the `vallum-status` group reach the system daemon without sudo. What they
  may do is decided per request from the caller's uid: read, and raise
  protection (`block` of an app's process tree, `untrust`, `resume`, `sync`,
  and the new `block-dest`, `policy-resume`, `watch-set`, `watch-delete`,
  `tag`). Every verb that removes or weakens enforcement (`unblock`, `trust`,
  `allow-once`, `pause`, `teardown`, `logout`, and the new `unblock-dest` and
  `policy-snooze`) still needs uid 0, and says so: `lowers protection; needs
  root: sudo kub0 …`. `login` is root's too, since which org a host enforces
  (and so which deny lists and network policies it takes) is an admin's
  decision; a user daemon's owner still logs their own daemon in. A `block`
  with addresses (`kub0 block <app> --ip …`, the helper's `block-ips`) is
  refused to a member as well: it applies to the whole host, and the helper
  spares only nameservers and gateways, so a member could cut the daemon off
  from the kub0 server. On the system daemon a member changes only the watch
  rules they set. Without the group, or with one that fails validation, the
  socket stays root:root 0660 as before, logged once; a wrong owner, group or
  mode after setup still stops the daemon.
- New control verbs for what the panel did by other routes: `block-dest` and
  `unblock-dest` (the timed app-to-IP rule, through the helper's
  `block-scoped`/`unblock-scoped`, 5 minutes, 15 minutes or 1 hour),
  `policy-snooze` and `policy-resume` (the org's `user_can_snooze` refusal
  reaches the caller), `watch-set`, `watch-delete` and `tag`. The polkit pin
  test places each of them. The panel's `note` (its record of a block
  outcome) stays a legacy line and is not a verb: the daemon will record the
  blocks it performs itself, and as a verb it would only let members forge
  activity rows.
- On the system daemon the mutating legacy lines (`netpolicy-snooze`,
  `netpolicy-resume`, `watch`, `tag`, `note` sent without a `req` id) are
  taken from root only: they carry no access class, and the socket now admits
  a group. Any other client gets a `status` frame saying to update the panel.
  Read-only legacy lines, and every line on the user daemon, are unchanged.
- `kub0`: a non-root caller with no `--socket/--system/--user` talks to the
  system daemon when its socket lets them in, else to their own. New commands:
  `kub0 block <app> --to <ip> --for 5m|15m|1h --pid …`,
  `kub0 unblock <app> --to <ip>`, `kub0 policy snooze <rule> [--for 1h]`,
  `kub0 policy resume <rule>`, `kub0 watch add <kind> <value> [note…]`,
  `kub0 watch rm <id>`, `kub0 tag <network> <label…>`, all with `--json`.
  The `sudo` hint appears only for a request that needs root (a lowering
  verb, `login`, an address block); for the rest it names the group.
- `sudo kub0 install` adds the user who ran it (`SUDO_USER`) to
  `vallum-status` (`gpasswd -a`, else `usermod -aG`) and says a new login is
  needed. `kub0 doctor`'s `status membership` row says what membership gives
  (read and raise on the system daemon) and keeps `sudo kub0` for lowering.

## 0.4.3 (2026-11-06)

- The system daemon now names a logged-in user's apps, and says whose they
  are. `vallumd --system` runs as root, and the resolver filed every process
  of another uid under `system`: on the development desktop, all 143 of the system daemon's
  `exe-hidden-home` notices in 7 days read `system`, none said brave or
  kubectl, and per-app rules, blocks and the heartbeat's per-app networks lost
  the app the same way. In system mode a process of a human uid (`UID_MIN`
  from `/etc/login.defs`, 1000 when unset; never `nobody`) now resolves the
  way the user's own daemon resolves it, with that user's `.desktop` files
  consulted, and the row carries `app.owner` (`{uid, name}` from the passwd
  database). Its indicators name it `Brave (alice)`, and the behaviour rungs
  apply to it: it is a person's app, not a daemon on a schedule. Root's own
  processes and service accounts are unchanged (root's resolve by executable
  with no owner, a service account's stays `system`), and a user daemon never
  sends `owner`.
- `kub0 install` and `scripts/install-privileged.sh` create the
  `vallum-status` group when it is absent (`groupadd --system`, idempotent)
  and restart a running daemon so it can resolve it. The system daemon reads
  the group from `/etc/group` at start and serves no read-only status socket
  without it, and nothing created it, so every fresh install logged
  `pre-existing vallum-status group missing` and had no status socket. The
  group is created empty: the installers add nobody to it, and who may read
  the socket stays the administrator's call. `kub0 doctor` now has a `status
  group` row that reports the group missing from `/etc/group`; the
  membership row for a non-root caller is `status membership`.
- A `go test` or `go run` binary is no longer an `exe-temp-dir` warning. The
  go tool builds under `/tmp/go-build<digits>/` and runs the result itself;
  when both hold (the path, and `go` as the parent or an ancestor within
  three hops) the daemon raises `exe-build-dir` (notice) instead. Either
  half alone still warns: a binary dropped in `/tmp` by anything else, and a
  `/tmp/go-build123/` directory nothing built. On the development desktop that was every one
  of the panel daemon's 24 remaining warnings in 7 days.

## 0.4.2 (2026-11-05)

- A package upgrade under a running process is no longer an `exe-deleted`
  warning. When `/proc/<pid>/exe` says `(deleted)` and the path holds a file
  in a system directory again, the daemon asks the package manager who owns
  that file: owned means the package manager replaced the binary (an
  upgrade), which is `exe-changed` (notice); unowned, or a manager that
  cannot answer, keeps `exe-deleted` (warning), logged once the answer lands.
  Nothing claims either while the question is out, so an upgrade never warns
  first. On the development desktop that was 41 of the panel's 65 warnings in 7 days (Brave,
  kubectl), and 33 more on the system daemon (tailscaled), every one an
  upgrade. A binary that unlinked itself (no file at the path) still warns
  at once.

- A process whose binary was replaced while it ran (a package upgrade, or a
  binary that unlinked itself) keeps its app. `/proc/<pid>/exe` reads
  `/usr/bin/x (deleted)` then, and the daemon used to mint a second app from
  it (`x-deleted`, "X Deleted"), while the root helper strips the marker and
  calls it `x`. Per-app rules, blocks and org policy key on that id, so they
  missed the upgraded process, and its first connection read as a new app.
  On the development desktop in 7 days: tailscaled, NetworkManager, nomad and nebula, 40-odd
  rows. The `exe-deleted` indicator, which keeps the full path, still fires.
  Rules a user made on an `x-deleted` row stop matching (they now belong to
  `x`).

- A user daemon (the panel's) no longer heartbeats when a logged-in system
  daemon is running on the same host; the system daemon reports the host
  alone. kub0 keys a heartbeat row on org and node name, and both daemons
  send the host name, so on a desktop with the panel and `kub0 install`
  they overwrote one row every minute: the fleet view showed whichever wrote
  last (on the development desktop the panel's 0.3.0, never the enforcing 0.4.1), and while
  either kept sending the row stayed fresh after the other died. The user
  daemon checks each tick for `/var/lib/vallum/account.json` and a root-owned
  `vallumd --system` process (a user shell cannot fake either), still
  refreshes the fleet, and shows kub0's state for the host as its heartbeat.
  `kub0 status` and `kub0 whoami` say `sent by the system daemon`.
  Known gap: labels made in the panel ride the user daemon's heartbeat, so
  they do not reach the org while the system daemon reports the host.

## 0.4.1 (2026-11-05)

- The system daemon now sends its first outcomes report on the first live
  tick after it starts (a zero row when the gate is idle), not 24 hours
  later. An idle endpoint that spoke once a day looked the same to kub0 as
  one whose outcomes never arrived; now an install or restart proves the
  token, route and schema within a tick, and `journalctl -u vallumd` shows
  `outcomes: kub0 accepted` right away. One extra zero row per start.
- `vallumd.service` now starts after `network-online.target` (`After=` plus
  `Wants=`). Started before the network, the system daemon's first deny-list
  stream, heartbeat and fleet fetch failed DNS at every boot and logged it
  before the retry recovered. Where the distro enables a wait-online service
  the daemon now waits for it; where both are masked (omarchy) the target is
  reached at once, so nothing changes there. `kub0 install` and
  `scripts/install-privileged.sh` both install this file.

## 0.4.0 (2026-11-05)

- The outcomes channel (`daemon/src/outcomes.rs`): the system daemon now
  tells kub0 what the exec gate did, as counters only. Every heartbeat tick
  folds the gate's `blocked`, `allowed_once`, `allowed_local_trust` and
  `allowed_failopen` counters into a window; a window at least
  `KUB0_OUTCOMES_INTERVAL` seconds old (default 300) with a non-zero delta is
  posted to `POST /ingest/outcomes`, and an idle gate posts one zero row a
  day. The wire is `agent`, `agent_version`, `platform`, `window_start`,
  `window_end` and `outcomes[{kind, result, count}]`, nothing else: a test
  pins the key set and another proves a deny record's path, digest, reason,
  promoter and pid never appear. Windows the server did not accept are
  spooled in `<state dir>/outcomes-spool.json` (0600, newest 288) and sent
  oldest first when it answers again, restart or not. The user daemon's gate
  frame is a mirror and is never reported. `VALLUM_OUTCOMES=0` opts out.
  Until now a block was a desktop notification only; kub0 learned nothing.

- The system daemon kept no history after any restart that found active
  rows in the store: the restart fold failed with "disk I/O error". The unit
  runs under `ProtectSystem=strict` without a private /tmp, so SQLite had no
  writable directory to spill a statement journal into
  (`SQLITE_IOERR_GETTEMPPATH`). Both history connections now keep temp space
  in memory (`PRAGMA temp_store=MEMORY`), bounded by the 64 MiB store cap.

- `kub0`, the CLI (`cli/`, a third workspace member; `kub0-<target>` in the
  release artifacts and `SHA256SUMS`). One unprivileged binary over the
  daemon's socket for account (`login`, `logout`, `whoami`, `status`), org
  (`rules`, `endpoints`, `sync`), exec gate (`trusts`, `trust`, `untrust`,
  `allow-once`), blocks (`blocks`, `block`, `unblock`, `pause`, `resume`,
  `teardown --yes`) and host (`doctor`, `install`, `version`), with `--json`
  on every command. The daemon gained the request/reply half of the protocol
  (`daemon/src/control.rs`): a line with a `req` id is answered once, to the
  client that sent it, as a `type: "reply"` frame; who may do what is decided
  from the peer's `SO_PEERCRED` uid by a table its tests pin (reads for
  anyone who can connect, raises for root or the user daemon's owner, lowers
  for root only). The system daemon's command socket stays root:root 0660,
  the contract `docs/system-status.md` sets, so a command for it is
  `sudo kub0 …`. A login runs inside the daemon (the device flow moved to
  `daemon/src/device.rs`); the CLI shows each code as a partial reply and the
  daemon writes the account file and starts its heartbeat within a second,
  so the token never leaves the daemon. The nftables verbs run the installed
  `vallum-block` as root from the daemon with the caller's uid as
  `PKEXEC_UID`, exactly as the panel's pkexec path does; the exec-gate verbs
  append to the same `requests.ndjson` the helper writes and wait up to three
  seconds for the gate to show the effect. `kub0 install` is the root half of
  `scripts/install-privileged.sh` without the plugin (binaries, units, the
  polkit policy where polkit exists, geo databases when present), idempotent,
  for any systemd distribution; `kub0 doctor` reports what is installed,
  reachable and missing and names the package per distribution family. The
  daemon's client verbs (`connect`, `status`, `disconnect`, `history`, …)
  still work for the panel and print a hint at a terminal.
  `tests/test_kub0_cli_live.py` drives the CLI against a real user daemon,
  including a full device login against a fixture auth server.
  (#43)
- `kub0 doctor`: the system daemon line no longer reads "absent" for a
  user who cannot read `/run/vallum` (root:root 0750). ENOENT is still
  `missing`; EACCES on the root-only socket is `unknown` with a `sudo kub0
  doctor` pointer, and it no longer counts toward the exit status.


- rustls 0.23.46 in the lockfile (Dependabot: Session `Debug` formatting exposed
  TLS master secrets; an unauthenticated ServerHello could poison the per-name
  key-exchange cache; ECH rejection and brotli certificate decompression issues).
  Lockfile only, no API change.

## 0.3.0 (2026-11-01)

- `vallumd connect` replaces a device code that expires unused instead of
  exiting on it: up to four codes (an hour at kub0.ai's 15 minutes each),
  then `device login expired` as before. In `--json` mode each replacement
  is another `code` event, which the panel already shows as the current
  code. The first system-account login of a desktop took three days and a
  shell loop around the command because every lapse ended it.
- The exec gate names an over-cap file on stderr once, not on every exec.
  The `over_cap` counter still moves per exec. Four toolchain binaries
  (claude, mise, kubectl, rclone) had written twenty `over cap` lines in
  thirty seconds to a desktop journal the moment the gate armed.
- The exec gate is a product, not a counter. A match now produces an
  `ExecGateDeny` event (pid, parent pid, basename, path, sha256, the matching
  row's `reason`, `promoted_by` and `created_at`, and the decision: `blocked`,
  `allowed_local_trust`, `allowed_once`, `allowed_failopen`) that goes to the
  activity feed as `exec_gate_deny`, to the fleet frame as
  `execGate: { enabled, armed, keys, source, counters, denies, trusted,
  oncePending }`, and, for a block or a deny that failed open, to a desktop
  notification with **Allow once** and **Trust on this machine** buttons
  (one per sha256 per ten minutes). The stderr line names the path. The panel
  dropped the whole `execGate` object in `Kub0.applyFleet` before; it keeps it
  now, and `tests/test_execgate_contract.js` generates the fixture from the
  Rust struct so a new field cannot be dropped silently again. The counters
  moved under `counters` and `hit_block` is `blocked` (no panel ever read the
  old names).
- Local trust store (`daemon/src/trust.rs`). The gate consults the owner's
  trusted digests and one-shot allows before denying and subtracts trusted
  digests from the key set on every refresh. The system daemon owns
  `/var/lib/vallum/execgate/{trusted.json,allow-once.json}`; the helper's new
  `execgate-trust`, `execgate-allow-once` and `execgate-untrust` verbs (each
  with its own polkit action) append a request the daemon applies within a
  second. A one-shot allow expires after five minutes whether or not it was
  used. Settings lists the trusted digests with **Remove**.
- Defaults and lifecycle. In `--system` mode the gate runs unless
  `VALLUM_EXEC_GATE=0`, and the unit sets `Environment=VALLUM_EXEC_GATE=1`
  with a comment. The gate no longer marks filesystems or hashes execs until
  the first non-empty key set arrives (`exec gate loaded, idle until the first
  deny-list sync`); an empty key set, including a local `disconnect --system`,
  flushes the marks and idles it. Every fail-open branch is unchanged. The
  user daemon mirrors the system daemon's `state.json` into its own fleet
  frame and activity feed, so the panel can show a gate it cannot talk to.
- Live deny list. While connected, the daemon subscribes to
  `/detonate/api/events/stream` with the account's Bearer token and applies
  `denylist_snapshot` and `denylist_update` to the gate's key set and the
  deny-list model (`daemon/src/sse.rs`, parser tested on captured frames in
  `tests/fixtures/sse-denylist.txt`); it reconnects with exponential backoff
  from 1 s to 60 s, and the 60 s poll stays as the fallback and as the source
  of row metadata the stream does not carry. The fleet frame says which is
  delivering (`denylistLive`).
- Truth fixes. A deny-list row is labelled by its real action (`block`,
  `monitor`, or "Unset" when empty) instead of every empty action reading as
  "Block"; the fixtures no longer use `deny`, which the kub0 API never emits.
  The Settings sentence "Displayed, not enforced locally. Local enforcement
  arrives with the eBPF engine." is replaced by the exec-gate section above it
  and one honest line. The README gains an "Exec gate" section and no longer
  contradicts itself about blocking verification, QML coverage, and what
  leaves the machine. `DenylistEntry` carries `promoted_by` and `created_at`.
- `scripts/install-privileged.sh` now installs the daemon, the system unit,
  the helper, the polkit policy with every action, the geo databases when
  present and the exec gate's state directory, idempotently, and prints what
  it did.

## 0.2.0 (2026-10-14)

- Tie each captured DNS answer to the query that asked for it. A security
  review of the DNS-answer program found that any UDP datagram from port 53
  reaching one of the user's sockets was believed, so a same-uid process or
  an off-path sender who knew the port could have named an address whatever
  it liked. The collector now attaches a `cgroup_skb/egress` program that
  records (socket cookie, transaction id) → (question-name hash, server) for
  every UDP query to port 53 from the owner's sockets, and the ingress program
  reports a response only when that key is present, the question name hashes
  the same and the response comes from the server the query went to;
  anything else is counted (`dnsUnmatched`) and ignored. Both programs
  attach or neither does. Each answer now carries the `server` that gave it,
  and the daemon accepts only servers named in `/etc/resolv.conf` (re-read
  when it changes; loopback only when unreadable), counting the rest as
  `dnsForeign` on the capture status. The verifier accepted all six programs
  (`dns_egress` 192 instructions, `dns_ingress` 1,907); not exercised live
  here. `tests/verify-root-enhancements.sh` gains the acceptance: a fixture
  resolver in the private namespace sends two forgeries before each real
  answer, and the report's `dnsCapture` key says whether only the matched
  answer was reported and a foreign UID's query was ignored.
- Fix three Intel view defects found by loading the QML for the first time:
  the timed-block offer under an indicator row never rendered its duration
  buttons (its children referenced a property declared on their parent
  `Flow`, which QML does not put in scope, logging a `ReferenceError` per
  row) and logged a `Flow` anchoring warning; and the Timeline section's
  heatmap would have been empty because the investigate drawer's bar chart
  was named `timeline`, shadowing the root property its bindings read. Add
  `tests/qml/kit-harness.qml` with a stub `qs.Commons`/`qs.Ui`/`Quickshell`
  import path (`tests/qml/kitstub/`) so `IntelView`, `HistoryView`,
  `ConnectionEvidence` and `DestinationRules` instantiate under the plain
  Qt6 `qml` runtime without Omarchy or quickshell; 40 checks render fixture
  rows and click through the block offer, pivot, watch form and tabs.
  `tests/run.sh` runs it when a Qt6 `qml` is found.
- Add local intelligence (`docs/INTEL.md`). Every connection may carry
  `indicators`: claims with their basis, computed on this machine from this
  machine's evidence, highest severity first, each with an optional MITRE
  ATT&CK reference as vocabulary rather than verdict. Rungs: executable
  deleted while running, in a temp directory, world-writable, under a hidden
  home directory, or changed since the process started; first ASN, country or
  uncommon port for an app once it is established (20 connections over 24 h,
  learned into `baseline.json`); regular reconnection cadence to one
  destination; upload-heavy counters (re-evaluated as they move); fan-out to
  many networks in a minute; hosting-provider peer; public peer with no PTR
  after a lookup. Every public row now carries `asn` and `org` from the
  bundled DB-IP ASN database, on the procfs path and on database sources.
  `evidence.hash` is filled with the executable's SHA-256, computed off the
  sample loop and patched into rows when it lands, filling the field reserved
  in the v0 schema. New additive frames: `listeners` (every TCP LISTEN socket
  and bound non-ephemeral UDP socket with owner and scope, on hello and on
  change), `watchlist` (the user's rules, on hello and after a change), and
  `investigate` (a pivot over retained history plus live rows). New commands:
  `{"cmd":"watch"}` and `{"cmd":"investigate"}`. New closed activity kinds
  `watch_hit` and `indicator` (notice and above, once per indicator, app and
  peer per run). New CLI: `vallumd brief`, `vallumd investigate`, `vallumd
  watch`, all read-only against the state directory except `watch add|rm`.
  The panel gains an **Intel** view (indicators with severity filter and
  search, exposure, watchlist editor, and an investigate drawer with timeline
  and a "Watch this" button), an "Intel" startup option, ASN and indicator
  rows in the evidence drawer, and labels for the new activity kinds. Nothing
  new is fetched or sent; the heartbeat is unchanged. Verified live against a
  container's `/proc` over the socket and the CLI; the QML was not loaded in
  that environment and awaits a shell run.

- Second-review fixes. With sharing on, a private, LAN, link-local or
  tailnet network key could reach the kub0 heartbeat because the share path
  keyed off "new network" rather than "public peer"; only public peers are
  queued now, through the one predicate the behaviour rungs use. The AppImage
  temp-dir exemption required only a `/tmp/.mount_` prefix; it now requires a
  FUSE or squashfs mount at that directory per `/proc/self/mounts`. Fan-out
  was raised on every connection after the threshold; it is raised on the
  connections that widen the spread, and its window keeps counts rather than
  rebuilding a set per call. Timeline buckets are aligned to the hour so a
  label reading 13:00 means the hour from 13:00; labels print minutes. A
  late DNS name no longer retires `no-ptr` (the address still has none), and
  a late name adds `hosting` only under the first-sight gates (public peer,
  not a system row). A DNS answer now replaces a PTR name as documented. A
  failed heartbeat restored its keys at the wrong end and dropped the newest;
  fixed. A boot-time read that failed once was cached as a permanent failure;
  it is retried. A watch rule whose save failed survived no outside edit; it
  rides through the reload now. DNS queue loss was counted as attempt loss;
  it has its own counter. The DNS cache evicts by an expiry index instead of
  a scan. The DNS program rejects later IPv4 fragments, the two ring record
  sizes are asserted distinct at compile time, and `docs/CAPTURE.md` says
  which resolver paths the hook can and cannot see.

- Capture DNS answers in the optional collector. A `cgroup_skb/ingress`
  program on the user slice recognises UDP DNS responses to this uid's own
  sockets and reports each A and AAAA record with the question name; the
  daemon validates, caches address → name with the TTL clamped to a minute
  and a day, and names rows from it at first sight and when answers land,
  ahead of PTR. `hostnameSource` (`dns` | `ptr` | `source`) says which kind
  of name a row carries, and the evidence drawer explains it. Host-suffix
  watch rules and the PTR rungs now reach attributed rows without `--rdns`.
  A kernel that refuses the ingress program keeps address capture; the status
  line's `dns` field says so. Built, accepted by the Linux 6.18 verifier on
  load (five programs, nothing attached) and unit-tested here; attachment to
  a user slice and a live response await `tests/verify-root-enhancements.sh`
  on a real host.

- Offer a timed destination block from an indicator row. A notice or
  warning on a live connection can block its destination for 5 min, 15 min or
  1 hour through the existing `block-scoped` rule and the same gates the Apps
  view applies (helper ready, enforcement on, app blockable, not already
  blocked, a pid to scope to, one rule per app, never a host-critical
  address); a closed gate is named on the row. Info rows never offer it. No
  new polkit action.

- Add a timeline: `{"cmd":"timeline"}` and `vallumd timeline` answer, for
  every app, how many connections were observed in each hour (six-hour
  buckets past 48 h) of the last day or week, busiest first, at most nine
  rows with the rest folded. Presence, not arrivals: a connection counts in
  every bucket between its first and last sampling time. The Intel view draws
  it as a one-hue heatmap, sqrt-scaled to the busiest cell, with a hover line
  per cell and a click-through to investigate the app; the CLI renders the
  same data as a terminal heatmap.

- Add an opt-in kub0 prevalence client and an Intel row on the Overview. With
  the `shareDestinations` preference on (default off), `vallumd
  --share-destinations` sends `dest_networks` on the heartbeat: the /24 or /48
  keys of public destinations first reached since the last heartbeat, capped
  at 256, never an address or an app. The server may answer `prevalence`
  (`network_key`, `nodes`, `first_seen`); the daemon merges answers and
  publishes them on the `fleet` frame with `prevalenceSupported`, and the
  Intel view says "Seen on N other endpoints in your org", "First in your
  org", or that this server does not answer, under indicator rows and in the
  investigate drawer. The kub0 API does not answer it yet; the client
  degrades honestly until it does. The Overview gains a focusable Intel row
  (warnings and notices on current connections, sockets reachable from the
  network) that opens the Intel view. The README's heartbeat description now
  lists every key actually sent.

- Review fixes to the intel layer, from a bug-hunting pass over the three
  commits above. A `vallumd watch add` made while the daemon held fresh hit
  counts was overwritten on the next refresh; the file's rules now win on
  membership and memory's counts are carried by id. Hit counts were never
  republished; they are now. A PTR name landing after a row existed never
  re-ran host watch rules or the PTR rungs; it does now, without double
  counting the other kinds. An executable deleted while running was hashed
  from its replacement and asked about as `"x (deleted)"`, which called every
  upgraded-while-running binary unpackaged; deleted rows are flagged and never
  hashed or asked about. On merged-`/usr` Debian the dpkg miss on `/usr/bin/x`
  called core binaries unpackaged; the `/bin` alias is tried. A full hash
  queue poisoned the cache so a binary never got its hash; it retries.
  Loopback and LAN peers fed port novelty and cadence; behaviour rungs are
  public-peer only and never for `system` rows. Fan-out counted never-seen
  networks rather than distinct networks per minute; fixed. AppImage mounts
  under `/tmp/.mount_*` are not temp-dir binaries. Hidden-home paths are
  judged against the socket owner's home from passwd, not the daemon's. A
  truncated `/proc/<pid>/stat` could panic the sample loop; it cannot. Watch
  hits logged and notified once per connection; now once per (rule, app,
  peer). A `watch` command under `--replay` or a database source answers with
  an error instead of silence. Intel notifications carry a shield glyph, not
  the keybinding one, and the Intel view's liveness is pinned to
  ConnectionModel's.

- Add process lineage and package ownership to connection evidence, a
  desktop notification for watch hits and warnings, and indicators in History.
  `evidence.lineage` carries the owning process's ancestors (parent first, up
  to eight), command line and working directory, read from `/proc` once per
  process; `evidence.package` is the distribution package that owns the
  executable per pacman, dpkg or rpm (local database only, system directories
  only), or `"none"`, in which case an `exe-unpackaged` notice is added to the
  row when the answer lands. The evidence drawer shows all of it. The
  `notifyIntel` preference (default on) sends `omarchy notification send` for
  a watch-rule hit or a warning-level indicator arriving live; the hello
  replay never notifies. History rows show their retained indicators.

- Cut vallumd's steady disk writes. History checkpoints write only rows that
  are new, changed or no longer observed (one checkpoint record carries the
  sample time for every unchanged active row) through a SQLite write-ahead log
  with `synchronous=NORMAL`, transfer counters of live rows go to a narrow
  table instead of rewriting each record, and rows past the 10,000 cap are
  trimmed in batches of 256 rather than one per checkpoint; `hosts.json` is compact and
  rewritten for a new network, not for every `last_seen` bump (those are held
  up to 15 minutes). Before: 174 KB/s (15 GB a day), measured over an hour on
  a laptop holding 41 to 100 connections.

- Show resolved hostnames on the Live tab. `normalizeConn` never kept
  `hostname`, so every peer the daemon had named rendered as a bare address.
  A fixture generated from the daemon's serde structs
  (`tests/fixtures/connection-contract.json`) now goes through the panel's real
  ingest path in `tests/test_wire_contract.js`, which fails on any field the
  daemon sends and the panel drops without a stated reason.

- Reverse DNS no longer runs on the sample loop. Lookups are in-process
  (`getnameinfo`) on worker threads instead of a `getent` fork per address, so
  an unresponsive resolver cannot stall polling; a row created before its name
  is known is updated in place when the lookup lands. `VALLUM_NO_PTR=1`
  disables lookups (the isolated tests use it).

## 0.1.0 (2026-10-08)

- Correct Darwin CI to the native library suite and source-default binary
  test after the failed full-package enforcement-fixture attempt. Use independent
  proc_pidpath identity, bounded/private fixtures, null-safe endpoint self-tests,
  real duplicate FDs and retained observation-history checks. Corrected native
  acceptance and arm64 execution remain pending.

- Default Darwin to read-only libproc observation with honest additive
  observation provenance. Correct proc_listallpids entry-count sizing/retention.
  Add independent SDK ABI/PID coverage and private IPv4/IPv6 TCP/connected-UDP
  IPC gates on explicit Intel/arm64 Darwin CI. Native execution is pending.

- Bound tenant inventory future-clock tolerance to 60 seconds and expire online
  status at exactly ten minutes. Show the full last-success date and age on
  failed refreshes, preserve last-good inventory, and label owner-app counts
  precisely. Add model/parser boundaries and a private native inventory fixture;
  native execution is pending (docs/ENDPOINT-INVENTORY.md).

- Show daemon role and policy evidence while disconnected, including cleanup
  errors; keep tenant inventory gated. Retire current policy evidence on source
  replacement, demo transitions and daemon exit, before accepting a hello role.
  Native fixtures check ancestor visibility and policy retirement during demo.
  Private native checks passed for lifecycle, visible errors, and
  timestamp boundaries.

- Keep policy errors visible with an empty list. Distinguish failed refresh of a
  known applied plan from unverified retained kernel rules, clear prior policy
  evidence on reconnect/account change, and show daemon reasons as plain text.
  Separate explicit hello role from account/helper readiness; legacy role stays
  unknown. Label rule counts as connection matches and preserve apply-time meaning.

- Bind the dynamic recovery Socket's callback receiver with `id: socket`.
  Retire live callbacks and pending history requests on demo entry; daemon exit
  during demo no longer changes its status or schedules live restarts. The
  runtime runner masks the fixed production helper only inside a private child
  namespace. Native recovery acceptance is pending.

- Recover the live panel feed by replacing a refused or lost Unix socket with a
  bounded exponential retry, while ignoring callbacks from retired sockets and
  reporting interrupted local history requests. Explicit demo mode and stored
  preferences remain intact during reconnects.

- Make system-mode enforcement fail safe: only the server saying there are no block
  rules, or a local disconnect, takes them out of the kernel. The system vallumd
  reads its geo databases from `/usr/share/vallum`, not a path relative to systemd's
  `/`. With no shared-infrastructure ranges to keep (the ASN database missing, or
  one with no such records) it applies no new block rules, leaves the ones already
  in the kernel, and reports an error naming the database. A country block rule with
  no country database to give it ranges (missing, or a file with no countries in it)
  does the same, rather than syncing a plan without that country. Both databases are
  read once, so installing one takes a vallumd restart, and the error says so. A
  country rule that gets no ranges is reported as not enforced rather than covered.
  A netpolicy fetch that fails, 404 and 401/403 included, keeps the last policy
  received and sets `netpolicyRefreshOk: false`; the panel says the list it shows is
  stale, or that there is none to show. A policy set this vallum cannot read in full
  (a mode or action it does not know, a policy or rule with no id, a block rule whose
  match it cannot read) is a failed fetch too, never fewer rules; a set it reads in
  full with no block rule in it, an org switching to monitor, still clears. A 304
  counts only against a set received with an ETag. Until an account's policy has
  arrived (after a restart, or an account change including a token rotation), rules
  already in the kernel stay and the state says so; before, an account change
  followed by a failed fetch cleared every block. An account file that cannot be
  read or parsed changes nothing, at the start of a heartbeat or at its end; only a
  missing one is a disconnect. A failed sync no longer hides earlier rules from a
  later clear, and a clear that fails is an error, not `none`, and is retried, on
  disconnect too. Each heartbeat reads the kernel back with a read-only, bounded
  `nft -a list chain`, re-applies rules removed underneath it, and takes the pause
  state from the same listing, so `enforcing` only describes rules the kernel was
  seen to hold; a read that fails reports the rules as unconfirmed. Only nft's own
  "no such table or chain" answer reads as an empty kernel, not a loader that cannot
  find libnftables, and one family's drop rule left behind counts as rules held, so
  it is cleared once the server says none. The last policy lives in memory only, so
  a host rebooted during a kub0 outage enforces nothing until the server answers
  (documented, not changed).

- Enforce org network-policy block rules on Linux when vallumd runs as the system
  service: `vallum-block fleet-sync` installs one nftables transaction (interval
  sets plus a single drop rule per family, below the pause rule). A keep set the
  helper computes itself (private and tailnet ranges, the host's resolvers and
  gateways) always wins, and the daemon adds the kub0 server and shared
  infrastructure (CDN and cloud ASNs, via DB-IP ASN Lite). A user-mode vallumd and
  macOS report block matches as would-block and say why. App-scoped block rules are
  not enforced yet. Rules a policy allows can be snoozed for an hour from the panel.

- Watch org network policies (country, kub0 threat intel, IP) attached to this
  endpoint's host group. Matches are counted, shown on the connection and under
  Network policies, and reported on the heartbeat; nothing is blocked. A
  never-block floor (private and tailnet ranges, the kub0 server, local
  resolvers) is counted as suppressed and never reported as a destination. Needs
  the kub0 API's `/api/enforce/netpolicy`; an older server or an unreachable route
  keeps the last policy received and reports the refresh as failed.

- Add a searchable tenant Vallum endpoint inventory with online/offline filters,
  last seen, version, reported blocking rules, and a this-device marker. Clicking
  a selected filter or device clears it; selected devices show kernel and
  architecture details. Retain the last successful inventory on refresh failure,
  and clear it when disconnecting or changing accounts.

- Keep timed-rule cancellation available for dormant apps and normalized desktop
  IDs; remove scoped drops before their sets, clear records after teardown, and
  preserve incomplete-verification warnings on retries.

- Add opt-in Linux connect/unconnected-UDP capture with separate attempt history,
  UID-scoped hooks, bounded queues, loss counters and procfs fallback. Capture
  remains off by default; kernel attachment and overhead require root verification.

- Preserve source, verdict and decision provenance through the legacy model,
  and expose a connection evidence drawer for live and retained observations.

- Add timed app-to-IP rules with kernel-enforced expiry, cancellation, and
  scheduled cgroup cleanup; existing whole-app blocks keep their own status.

- Display measured Linux TCP upload/download rates and sampled session totals
  per app, with bandwidth sorting and unknown values for unsupported traffic.
- Add searchable local connection history with time filters, seven-day/10,000-row
  retention, CSV copy, and read-only CSV/NDJSON export through `vallumd history`.
- Preserve live connection counts and default battery-aware sampling behavior;
  opting into capture drains its bounded queue at the active cadence.
