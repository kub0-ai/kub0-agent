# kub0 agent

Per-app outbound network visibility and control for Linux: which app talks to
which country and network, a one-key per-app firewall block, and, with a kub0
account, your org's deny list and network policy enforced on the machine. It
is a `kub0` command with a system daemon behind it, and an
[Omarchy](https://omarchy.org) shell panel on top: country flags, animated
arcs, live rows.

The design premise is that "where does this machine talk to" should not depend
on which engine answered the question. Several sources normalise into one flow
schema and one UI: read what another firewall already decided, sample live
sockets, or opt into kernel connect/UDP attempt capture.

**Status: v0.5.1, early.** It works with no account, and then nothing leaves
the machine that was not already leaving. kub0 accounts are not open to the
public yet; what a connected account sends is listed under
[Connecting to kub0](#connecting-to-kub0).

The project was called *vallum* until 0.4.5. Everything you type or see is
`kub0`. A few names that are not typed still say vallum, and you will meet
them in `nft list ruleset` and `systemd-cgls`: the nftables table
(`inet vallum`) and its rule comments, the cgroup slice (`vallum.slice`), the
Rust crates, and the agent name the heartbeat reports.

> ### Provenance
>
> This repository starts from
> [ccdwyer/omarchy-snitch](https://github.com/ccdwyer/omarchy-snitch) (MIT,
> Christopher Dwyer). The QML panel, world map, flag set, `/proc` connection
> monitor, privileged nftables helper, and CI workflows are his work. His 13
> commits are in this history unchanged, so `git diff 147efa6 HEAD` answers
> "which parts are new" without anyone having to take a claim on trust.
>
> kub0 also reads [OpenSnitch](https://github.com/evilsocket/opensnitch)'s
> event database (GPL-3.0, Simone Margaritelli and contributors). That is an
> interop relationship: no OpenSnitch code is used here, and
> [`THIRD-PARTY.md`](THIRD-PARTY.md) carries the binding clean-room rule that
> keeps it that way. [`docs/SCHEMA.md`](docs/SCHEMA.md) is the wire contract.

## Sources

A source answers exactly one question, "what has happened since last time", and
returns it as a `Flow`. Enrichment (GeoIP, network keys, first-seen tracking)
happens once above the source, so every driver inherits it and each one stays
auditable as "does this faithfully read its input".

| `--source` | State it reports | Verdict | Status |
|---|---|---|---|
| `procfs` | live sockets | none, observation only | default, upstream's |
| `opensnitch` | past decisions | `external`, OpenSnitch's own | built |
| procfs with `--capture` | live sockets plus retained connect/UDP attempts | none for attempts | optional, defaults off |

```sh
kub0d --source opensnitch --os-backfill today --emit-flows
```

The OpenSnitch driver is **strictly read-only** against a database another
program is actively writing: a `mode=ro` URI *and* `SQLITE_OPEN_READ_ONLY`, with
a test asserting a `DELETE` fails. It probes the schema and degrades one field
per missing column rather than refusing to start, because it is reading a
foreign table it does not version. Their `time` column carries no timezone, so
`--os-time-utc` flips the interpretation; ordering is unaffected either way.

Sources disagree about what a row *is*: `procfs` reports sockets open right now,
OpenSnitch reports decisions already made. Averaging those produces a number that
means nothing, so the panel splits them into **Live** and **History** tabs keyed
on `state`, and the bar pill counts Live only. Classification deny-lists the
finished states rather than allow-listing the live ones — `procfs` emits raw
kernel state names, so an allow-list would silently drop anything it failed to
enumerate. Local history now retains sampled socket observations after they
disappear and across daemon restarts, for seven days / 10,000 records. Optional
capture also retains point-in-time attempts whose outcome is unknown. These
records do not increase the live count. See [`docs/TRAFFIC-HISTORY.md`](docs/TRAFFIC-HISTORY.md).

Coverage from `procfs` is **TCP plus connected UDP**. `/proc/net/udp` only has a
remote endpoint for `connect()`ed sockets, so most QUIC/HTTP-3 is invisible or
listed as `UDP (unresolved)` and never drawn as an arc. Optional capture observes
unconnected UDP destinations in the caller's user slice; applications moved
into kub0's block scopes (`vallum.slice`) are outside that subtree until restored. Reverse DNS is off
by default. Without a kub0 account nothing leaves the machine except the traffic
that was already leaving. With one, the heartbeat carries exactly what the
*Connecting to kub0* section lists, which includes up to 32 matched destination
addresses per org policy rule; connection rows, history, local rules, exec-gate
events and paths never do.

When a live socket has no owning process, `reason` says why: `orphan` (inode 0),
`no-owner` (a complete `/proc/<pid>/fd` scan found none), or `unreadable` (the
scan could not open every fd directory, including a pass that opened none).
First-seen unknown sockets are appended to `$XDG_STATE_HOME/kub0/unknown.ndjson`
(default `~/.local/state/kub0/unknown.ndjson`).

## Install

There are two halves, installed separately: the panel, which is an Omarchy
plugin, and the daemon it reads. On a server there is only the second; see
[Servers and other distributions](#servers-and-other-distributions).

### On Omarchy

```sh
omarchy plugin add https://github.com/kub0-ai/kub0-agent --enable
```

That puts the panel in the bar and nothing else: Omarchy never runs an
installer for a plugin. Open the panel and it says kub0 is not installed yet,
and offers two ways to fix that:

- **Install kub0** opens a terminal that downloads the release matching the
  panel for your architecture, checks its checksum, and runs its
  `sudo ./kub0 install`. The script is
  [`scripts/install-release.sh`](scripts/install-release.sh); it is short, and
  it does nothing the server instructions below do not do by hand.
- **Build from source** compiles the daemon in the plugin folder instead
  (`./build.sh`; it installs Rust if it is missing). The panel then runs that
  daemon as you: other accounts' and system services' connections show as
  `system`, with no app name.

After **Install kub0**, log out and back in once. The install adds your
account to the `kub0` group, which is what lets the panel read the daemon, and
a session joins a group only when it starts. The panel says so until you do.
If it still says so afterwards, reboot: where the user service manager
outlives a logout (lingering is on, or another session is open), logging out
does not start a new one.

`omarchy plugin update` updates the panel. The daemon is updated by installing
a newer release: `./scripts/install-release.sh` in the plugin folder installs
the one that matches the panel. When the two are different versions the panel
says which is behind and the command that fixes it.

### From a clone

To work on it, clone into the plugin directory and build:

```sh
git clone https://github.com/kub0-ai/kub0-agent.git \
  ~/.config/omarchy/plugins/ai.kub0.agent
cd ~/.config/omarchy/plugins/ai.kub0.agent
./build.sh
omarchy-shell shell rescanPlugins
omarchy plugin enable ai.kub0.agent
```

The last two lines are not optional, and leaving them out is the failure that
looks like a broken plugin rather than an unfinished install. Cloning gets the
manifest discovered; a discovered plugin is still `enabled: false`, which means
no bar icon, no panel, and no service—the shell only mounts a plugin's
`service` entry point once the plugin is enabled. Confirm with
`omarchy-shell shell listPlugins`: the `ai.kub0.agent` row has to read
`"enabled": true`. (`"active": false` there is not a problem. `active` answers
"is this the current bar option", and only a `kind: "bar"` plugin can be one.)

Enabling puts the widget in the bar's right section, per
`barWidget.defaultSection` in the manifest. `omarchy bar move` relocates it.

To develop against a working tree instead, symlink it—the shell's scan globs
`~/.config/omarchy/plugins/*/` and follows a symlinked directory, so the repo
becomes the plugin with no second copy to drift:

```sh
ln -sfn ~/Projects/kub0-agent ~/.config/omarchy/plugins/ai.kub0.agent
```

One cost, and it is worth knowing before you spend twenty minutes on it: a
symlinked plugin does not hot-reload. The shell watches the plugin tree with
`inotifywait -m -r`, which does not descend through a symlink, so edits inside
the repo raise no event. `rescanPlugins` does not cover for it either—that
re-reads manifests and leaves the already-compiled components in place, so the
shell keeps serving the old QML and reports errors against the old line
numbers. Use `omarchy-restart-shell` after a change. A normal clone install is
a real directory and hot-reloads as expected.

`./build.sh` compiles `kub0d` and `kub0-block` from source, typically
seconds with a warm Cargo cache. **No Linux binaries are committed.** A
release publishes them for `x86_64` and `aarch64` (see
[Servers and other distributions](#servers-and-other-distributions)).

Monitoring needs no privilege at all once `kub0d` is on `PATH` or at
`./bin/kub0d`. It does not need nftables, conntrack, or cgroup v2. Those are
required only for blocking:

| Need | Check | Arch | Debian/Ubuntu |
|------|-------|------|---------------|
| nftables | `nft` | `nftables` | `nftables` |
| conntrack | `conntrack` | `conntrack-tools` | `conntrack-tools` |
| cgroup v2 | `/sys/fs/cgroup/cgroup.controllers` | systemd default | same |

`kub0-block status` reports `nft`, `conntrack`, `cgroupv2`, and
`blockingReady`. When any are missing the UI greys out block controls and names
the missing package. The map keeps running.

Blocking also needs the helper installed at the path the polkit policy
authorizes. Open the panel and click **Install helper**, or run it directly:

```sh
cd ~/.config/omarchy/plugins/ai.kub0.agent
./scripts/install-privileged.sh
```

The script runs the freshly built `kub0 install` under `sudo` (never
`sudo bash`), leaving group membership to you as it always has, then runs
`pkexec /usr/lib/kub0/kub0-block status` to prove the policy resolves. On a
0.4.x host that install is also the rename; see
[Upgrading from 0.4.4](#upgrading-from-044-the-rename).

The policy has one action per helper verb, each scoped to that path **and**
that verb. Blocking and resuming use `auth_admin_keep`, so a run of blocks asks
once. Unblocking, pausing and teardown use `auth_admin` and ask **every time**.
polkit keeps an authorization for the process that ran `pkexec`, which is the
shell, and any code running as you can reach the shell: over its IPC, or by
editing this plugin's QML, which the shell reloads live. A kept authorization
for lowering protection would let that code lift every block with no prompt.
So a password prompt for an unblock or a pause you did not start is a reason to
cancel.

`sudo` rather than `pkexec` for the install itself is deliberate. Omarchy's
polkit agent runs inside the shell process, and the shell restarts when the
plugin directory changes—which is exactly what `./build.sh` does when Cargo
writes `bin/`. The agent takes its password dialog down with it, so a
pkexec-driven install can be dismissed halfway by its own side effects.

**Run it from a real terminal.** `sudo` needs a controlling tty to prompt, so
launching the script from anything detached—an editor task runner, a shell
spawned by another tool—fails with `sudo: a terminal is required to read the
password`. That is the environment, not the script.

Place the bar pill if it did not land:

```sh
omarchy bar move ai.kub0.agent --section right
```

### Upgrading to 0.5 (one daemon)

`sudo kub0 install` from the unpacked release, then put the new panel in
place. Nothing needs doing by hand; this is what changes:

- **The panel reads the system daemon** and starts no `kub0d` of its own, as
  long as you are in the `kub0` group (the install adds you; log in again
  once). It lists the whole host: system services and other accounts'
  connections too. With capture switched on it still runs its own daemon.
- **Your watch rules and network names come along.** The install carries them
  from the panel's own daemon (`~/.local/state/kub0`) to the system daemon,
  once, and says what it carried. Names go to your org with the heartbeat, as
  any `kub0 tag` name does.
- **Destination sharing** is `sudo kub0 share on` / `kub0 share off`, or the
  same switch in Settings, and holds across restarts. It starts off: the
  panel's old preference is not carried.
- **`kub0`** has one route. `kub0 watches`, `kub0 watch` and `kub0 tag` reach
  the system daemon like every other command; `kub0 doctor` no longer warns
  that you have no daemon of your own.

### Upgrading from 0.4.6 (the panel's id and settings folder)

<!-- rename-compat: the panel's names through 0.4.6, on purpose; the parity test skips this region -->
The panel's plugin id is `ai.kub0.agent` (it was `ai.kub0.vallum`), and its
settings are in `~/.config/kub0/ui.json` (they were in `~/.config/vallum`).

- **Settings: nothing to do.** The first start finds no `~/.config/kub0/ui.json`,
  reads `~/.config/vallum/ui.json` and writes the new file at once. The old
  file is never written or deleted; remove it when you like.
- **The plugin folder is named by the id.** Rename it, or re-point your link:

  ```bash
  mv ~/.config/omarchy/plugins/ai.kub0.vallum ~/.config/omarchy/plugins/ai.kub0.agent
  ```

- **The bar lists the widget by id.** In `~/.config/omarchy/shell.json`, under
  `bar.layout`, change `"id": "ai.kub0.vallum"` to `"id": "ai.kub0.agent"`, then
  `omarchy-restart-shell`. The widget keeps its place.
- **The hotkey.** One written before this release runs
  `omarchy-shell shell toggle ai.kub0.vallum`, which opens nothing now. The
  panel sees that and offers the hotkey again (Settings, **Set hotkey**); the
  write puts the new command on the same keys and removes the old block from
  `~/.config/hypr/bindings.lua`.
- Scripts that call `omarchy-shell ai.kub0.vallum status ''` or
  `omarchy-shell shell toggle ai.kub0.vallum '{}'` need the new id.
<!-- /rename-compat -->

### Upgrading from 0.4.4 (the rename)

<!-- rename-compat: the 0.4.x names, on purpose; the parity test skips this region -->
This release renames everything the endpoint agent puts on a host to `kub0`. The
plugin id (`ai.kub0.vallum`) and `~/.config/vallum`, where the panel keeps its
settings, were left as they were in 0.4.5 and 0.4.6; 0.4.7 renames those too
(the next section).

| 0.4.4 | now | what 0.4.5 and 0.4.6 also kept |
|---|---|---|
| `vallumd`, `vallum-block`, `vallum-capture` | `kub0d`, `kub0-block`, `kub0-capture` | the old paths are links to the new binaries |
| `/usr/lib/vallum`, `/usr/share/vallum` | `/usr/lib/kub0`, `/usr/share/kub0` | `/usr/lib/vallum` keeps the links |
| `/var/lib/vallum` | `/var/lib/kub0` | moved, not copied, by `kub0 install` or the unit's first start |
| `/run/vallum/vallum.sock`, `vallum-status.sock` | `/run/kub0/kub0.sock`, `kub0-status.sock` | `/run/vallum/vallum.sock` is a symlink while kub0d runs |
| `vallumd.service`, `vallum-expiry.*` | `kub0d.service`, `kub0-expiry.*` | `Alias=vallumd.service`: `systemctl status vallumd` answers |
| group `vallum-status` | group `kub0` | renamed in place, same GID and members |
| polkit `ai.kub0.vallum.*` | `ai.kub0.agent.*` | `ai.kub0.agent.compat.*` cover the old helper path |
| `VALLUM_*` | `KUB0_*` | the old name is read, with one log line |
| `$XDG_RUNTIME_DIR/vallum.sock`, `~/.local/state/vallum` | `kub0.sock`, `~/.local/state/kub0` | moved when the panel starts its daemon; the old socket name is a symlink |

**The third column is gone from 0.4.7.** It was one release of compatibility
that ran for two. `kub0 install` now removes what it used to keep: the links
in `/usr/lib/vallum` (and the directory, unless it holds something kub0 did
not put there), a 0.4.x collector left there, the `vallumd.service` alias and
both 0.4.x polkit policies. kub0d makes no `/run/vallum` link; the
`ai.kub0.agent.compat.*` actions are gone; a `VALLUM_*` variable is not read
(one that is still set logs a line saying so); and a host whose group is
still `vallum-status` has no status or command socket for its users until
`kub0 install` renames it. `kub0 doctor` lists any of these still on a host.
What stays is the upgrade itself: a host on any 0.4.x still upgrades in one
`kub0 install`, as described here.

`sudo kub0 install` (or `./scripts/install-privileged.sh`) does the system
half in an order that never leaves the host without an enabled daemon. It
refuses, changing nothing, when a `kub0` group already exists beside
`vallum-status` (two groups are never merged), or when the group it would keep
or rename is not a system group or is some account's primary group. It stages
everything at the new paths first (binaries, polkit policy, geo databases, the
exec gate's directory, the new units), renames the group with `groupmod -n`
(same GID and members), and only then stops, disables and removes
`vallumd.service` and `vallum-expiry.*`, moves `/var/lib/vallum` to
`/var/lib/kub0` with one `rename(2)` and starts `kub0d.service`. If the move
or the start fails, it puts the old units back, moves the state back and
starts vallumd again. Once kub0d runs, the old binary paths and the old
policy go.
The account, the exec gate's trusts and the scoped and block records come
across with the directory, and the new expiry timer reads it. `--no-start` on
a host where vallumd.service is installed stages everything and switches
nothing. Without systemd it refuses while a 0.4.x daemon runs: stop it from
your init first.

Only two things ever move the system directory: `kub0 install`, and the unit
itself on start (`ExecStartPre=+kub0d migrate-state`, outside its sandbox),
for a host whose binaries changed without `kub0 install`. A `kub0d` run by
hand never does. If `/var/lib/kub0` already holds state, `/var/lib/vallum` is
left untouched and the journal says so. If the kernel refuses the move
(another filesystem, an empty mount point at the new path), nothing moves and
kub0d, the helper and the expiry timer keep using `/var/lib/vallum` until it
can; `kub0 doctor` fails until then, and also fails while both hold state,
because the next release drops the old path. Nothing moves while a 0.4.x
daemon runs on the directory. The panel's own daemon moves
`~/.local/state/vallum` (it starts kub0d with `--migrate-state`); a bare
`kub0d` start does not. Local polkit rules that name `ai.kub0.vallum.*`
stop matching: `sudo kub0 doctor` lists them.

Update the panel and the system half together. Through 0.4.6 a 0.4.x panel
kept working against the renamed system half (it found `/run/vallum/vallum.sock`,
ran `pkexec /usr/lib/vallum/vallum-block` and read `/usr/lib/vallum/vallumd`),
and a newer panel fell back to a 0.4.x system half. From 0.4.7 neither does:
the panel talks to `/run/kub0/kub0.sock` and runs `/usr/lib/kub0/kub0-block`,
and a 0.4.x system daemon is not one it leaves the heartbeat to.
<!-- /rename-compat -->

### Migrating from omarchy-snitch

**Remove upstream's plugin first.** Both projects install a privileged helper,
and until v0.1.0 they installed it to the *same* root-owned path. A polkit
action is scoped to an exec path, so two projects sharing one path means each
authorizes the other's binary. This project moved to its own path for exactly
this reason (now `/usr/lib/kub0/`), but an existing upstream install still has to be torn down
deliberately, because nothing removes it for you:

```sh
pkexec /usr/lib/snitch/snitch-block teardown
pkexec rm -f /usr/lib/snitch/snitch-block \
             /usr/share/polkit-1/actions/io.github.chris.snitch.policy
omarchy plugin remove io.github.chris.snitch
# only if you opted in to upstream's keybind
sed -i '/-- BEGIN io.github.chris.snitch/,/-- END io.github.chris.snitch/d' \
  ~/.config/hypr/bindings.lua
```

`teardown` must run **before** the helper is deleted: it is what drops
`table inet snitch` and upstream's cgroups. Deleting the binary first strands
both, and they will keep filtering traffic with nothing left to manage them.

Per-app rules do not carry over. kub0 reads OpenSnitch's history, not
omarchy-snitch's, because omarchy-snitch keeps no persistent rule store.

## Usage

*Shell rendering is only partly covered by this repo's automated tests; see
[Dev](#dev).*

Click the bar pill to open the panel. If no hotkey is set, the Protection
section offers **Set hotkey**. That bind is written to
`~/.config/hypr/bindings.lua` only when you click it, never on first load.

The chord is not fixed and this document deliberately does not name one: the
shell assigns whichever combination is actually free and reports it back, which
is what the button's label shows. On the machine this was written on it chose
`SUPER + SHIFT + ALT + S`, because the shorter chord was already taken.

- **Pill**: one glyph. The wall means monitoring is current and enforcement is
  not paused; a filled shield means Idle or Wait; a hollow shield means Paused
  (every block held, none enforced); shield-off means Off; an
  alert shield means stale, unavailable, or demo. The tooltip leads with the
  state word (On, Idle, Wait, Paused, Stale, Off, Demo) and carries the
  connection totals. A pause rule never shows the wall.
- **Dimmed pill**: monitoring is not current — connecting, waiting for a
  snapshot, stale, unavailable, or explicit demo. Missing `kub0d` does not
  load fixture replay automatically.
- Away digest on open: `N new networks while you were away` (destinations, not
  threats)

Hover an arc: `firefox -> 142.250.x.x, US, port 443`.

| Key | Action |
|-----|--------|
| `left` `right` | Switch Overview / Apps / Intel / History / Endpoints |
| `up` `down` / `k` `j` | Move the app list (Apps) |
| `b` | Block or unblock the selected app when that control is shown |
| `i` | Install kub0, the helper, or nftables; or build the daemon (when shown) |
| `/` | Search apps, IPs, countries; indicators on Intel |
| Esc | Clear the endpoint dialog (and pending target), then search, then the panel |
| Tab / Shift-Tab | Host panel switch (`switchPanelFrom`) |

The supported way to open the panel is clicking the bar pill. The manifest also
declares a `panel` kind, so the shell IPC verbs are valid:

```sh
omarchy-shell shell summon ai.kub0.agent '{}'
omarchy-shell shell toggle ai.kub0.agent '{}'
omarchy-shell ai.kub0.agent status ''
```

Summoned placement is best-effort (`KeyboardPanel` `centerOnBar` when the host
provides `shell.bar`). That host field is not in the documented Quattro IPC
table; if it is missing, use the pill. See [`ASSUMPTIONS.md`](ASSUMPTIONS.md)
for every other place the shell contract was inferred rather than documented.

## The `kub0` CLI

`kub0` is the command line for everything the panel does and for the hosts
that have no panel: a server, a VM, a desktop that is not Omarchy. It is one
unprivileged binary that talks to the running `kub0d` over its socket. It
never carries a capability and never runs the helper; the daemon decides what
the caller may do and runs the privileged half itself, as root, through the
same `kub0-block` the panel uses.

```sh
kub0 status                 # daemon, account, org rules and exec gate on one screen
kub0 whoami
sudo kub0 login             # device-code login (root on the system daemon); the daemon keeps the token
kub0 rules                  # the org deny list and network policies this endpoint holds
kub0 endpoints              # the org's endpoints, as the last heartbeat saw them
kub0 block firefox --pid 4242                                 # nftables: block an app's process tree
kub0 block firefox --to 203.0.113.9 --for 15m --pid 4242      # block one destination for a while (5m, 15m, 1h)
kub0 untrust <sha256>       # exec gate: remove a local trust (resume, blocks, trusts: also no sudo)
sudo kub0 trust <sha256>    # lowering protection needs root (allow-once, unblock, pause, teardown, logout)
sudo kub0 block firefox --ip 203.0.113.9                      # an address block is host-wide: root (acts for the sudo caller)
sudo kub0 unblock firefox --to 203.0.113.9
kub0 policy resume <rule>   # an org network-policy rule applies again; `sudo kub0 policy snooze <rule> --for 1h`
kub0 share                  # whether the networks this host reaches are sent to your org; `sudo kub0 share on`, `kub0 share off`
kub0 watch add country KP   # alert on matching connections; `kub0 watch rm <id>`, `kub0 watches`
kub0 tag 203.0.113.0/24 Office VPN    # names the network on every row, and for the org; `--clear` removes it
kub0 apps --sort bandwidth  # what the panel shows: apps (--blocked, --live, --mine), conns, activity
kub0 conns --app firefox --follow
kub0 history --hours 24 --query firefox --csv
kub0 intel --timeline       # indicators, exposure, watch rules; the hour-by-hour timeline
kub0 why 203.0.113.9        # the evidence for one app, address, ASN, network or port
kub0 policies               # the org network policies, with this host's snoozes
kub0 brief --hours 24       # a Markdown digest
kub0 doctor                 # what is installed, reachable and missing on this host
sudo kub0 install           # the daemon, helper, units and this CLI; adds you to the kub0 group
kub0 --json status          # every command: the daemon's reply as JSON
```

Which daemon a command reaches: root talks to the system daemon
(`/run/kub0/kub0.sock`); anyone else talks to the system daemon when its
socket lets them in, and to their own (`$XDG_RUNTIME_DIR/kub0.sock`) when it
does not. `--system`, `--user` and `--socket PATH` override that. **The group
raises, root lowers.** The system daemon's command socket is
root:kub0 0660 (`docs/system-status.md`), so members of the
`kub0` group can connect, and the daemon decides from the caller's
uid (`SO_PEERCRED`) what they may do: read, and raise protection (`block`
of an app's process tree, `block --to`, `untrust`, `resume`, `sync`,
`policy resume`, `watch`, `tag`). A verb that lowers protection (`unblock`,
`unblock --to`, `trust`, `allow-once`, `pause`, `teardown`, `logout`,
`policy snooze`) is refused to anyone but root: `sudo kub0 …`, the same bar
as `nft` or `systemctl`. So is `login`, because which org a host enforces is
an admin's decision (a login brings that org's deny list and network
policies), and so is `block --ip`: an address block applies to every process
on the host, and the helper's floor spares only its nameservers and gateways,
so a member could cut the daemon off from the kub0 server. `sudo kub0 install`
adds the user who runs it to the group (a new login applies the
membership). The table is `daemon/src/control.rs`,
pinned by its tests against the polkit policy. On the system daemon a member
removes or renames only the watch rules they set. Org rules are never lifted
locally: `unblock` acts on the app's own cgroup block and on addresses blocked
for it, not on rows that arrived through fleet sync.

On a desktop the password prompt for those comes from polkit rather than a
`sudo` line. When the system daemon would refuse a request to this non-root
caller, `WAYLAND_DISPLAY` or `DISPLAY` is set, `/usr/bin/pkexec` and the
installed `/usr/bin/kub0` exist, and `KUB0_NO_PKEXEC` is not set, `kub0`
re-runs itself as `pkexec /usr/bin/kub0 <same arguments>` (polkit action
`ai.kub0.agent.kub0`, asked every time) and exits with that command's
status and output. Anywhere else it prints the `sudo kub0 …` line as before.
Root under pkexec or sudo acts for the user who asked: `kub0` sends `as_uid`
(`PKEXEC_UID`, else a non-root `SUDO_UID`), so the helper's ownership checks
act on that user's processes, not on root's, and `sudo kub0 block <app> --pid
…` blocks your own app. A plain root shell acts as root. The daemon honours
`as_uid` only from root, refuses a request that carries it from anyone else,
and says in its hello that it does (`as_uid: true`); `kub0` refuses a change
to a daemon that does not ("this daemon is older than the CLI and cannot act
for another user; update kub0d") rather than let it act as root, and sends
a read without the field.

`block` and `block --to` need the app's process ids (`--pid`): the helper
moves that verified process tree, and finds nothing on its own. The panel
passes the pids it shows. Every block and unblock the daemon runs for a
request is recorded in its activity log (`block`, `block_failed` with the
helper's error, `unblock`): the same record the panel adds with a `note` line
after running the helper itself.

A login goes through the daemon: `kub0 login` asks it to mint the device code,
prints `Open <url> and enter code <code>` as each code arrives (a code that
expires unused is replaced, up to four), and the daemon writes the account
file itself (`/var/lib/kub0/account.json` 0600 for the system daemon). The
token never reaches the CLI. The running daemon starts its heartbeat within a
second of the write; no restart.

On the wire a request is any NDJSON line with a `req` id next to its `cmd`;
the reply is a `type: "reply"` frame carrying the same `req`, sent to that
client only (`partial: true` for a login's intermediate codes). Every other
line is the panel's fire-and-forget path. The user daemon takes all of them as
before. The system daemon still answers the read-only ones (`investigate`,
`timeline`, `history`, `panel-open`/`panel-close`, `ping`) from anyone who can
connect, but takes the mutating ones (`netpolicy-snooze`, `netpolicy-resume`,
`watch`, `tag`, and the panel's `note` record of a block outcome) from root
only, because they carry no access class:
any other client gets a `status` frame saying to update the panel.

A daemon serves several clients at once: on a system install its socket admits
the whole `kub0` group. What one client asks is answered to that client. The
`investigate`, `timeline` and `history` frames, and a `ping`'s `status`, go to
the client that sent the line, not to every client. An open panel is counted
per client: the daemon samples at the active cadence while any client is
between its `panel-open` and `panel-close` (or its disconnect), and the
`digest` of what arrived while no panel was open goes to the first panel that
opens.

Exit codes: 0 ok, 1 the daemon refused (its reason on stderr), 2 usage, 3 no
daemon reachable (with what to do about it).

Every read (`apps`, `conns`, `activity`, `history`, `intel`, `why`,
`policies`, `watches`, `brief`) is a `Read` verb any caller who can connect
may use, answered from the daemon's own state: the data the panel's views
read. On the system daemon a row carries its owner (`app.owner`), and
`kub0 apps --mine` keeps the caller's own; it is not the default, because the
system daemon is the one that sees every process on the host, and the rows a
reader most needs (system services, other accounts' traffic) are exactly the
ones a "mine" default would hide. `kub0 apps --blocked` asks the system
daemon's `blocks` as well, since what is blocked is the helper's to say.

**Which daemon a command reaches.** One: system first, as above, for every
command. Until 0.5 watch rules went to the user daemon first and a tag to
both, because the panel read the user daemon; the panel now reads the system
daemon, so `kub0 watches`, `kub0 watch add|rm` and `kub0 tag` see and change
the same list the panel shows. On the system daemon everyone in the `kub0`
group sees every watch rule and changes the ones they set; root changes any,
and a rule added with `sudo kub0 watch add` belongs to whoever ran sudo.

The one exception is a panel with capture switched on: it runs a daemon of its
own, shows that daemon's rows and keeps its watch rules and names there;
`kub0 --user watches` and `kub0 --user tag` reach that one. `--system`,
`--user` and `--socket PATH` still send any command to that one daemon.
`kub0 tag <network> --clear` takes a name away. A name given to your own
daemon while a system daemon is installed stays on this machine, and `kub0`
says so: the org gets names from the system daemon. With nobody listening on
the user daemon's socket beside a system daemon that answers, `kub0 doctor`
reports that as it should be, not as something missing.

The daemon's old client verbs (`connect|status|disconnect|history|brief|investigate|timeline|watch`)
are retired: for one release each prints the `kub0` command that replaced it
(`kub0 login`, `kub0 whoami`, `kub0 logout`, `kub0 history`, `kub0 brief`,
`kub0 why`, `kub0 intel --timeline`, `kub0 watch`) and exits 2, under the name
it was run as (`kub0d`, or the 0.4.x path that is a link to it).

### Servers and other distributions

Monitoring and the exec gate need nothing beyond the static binaries, which
each [release](https://github.com/kub0-ai/kub0-agent/releases) publishes for
`x86_64` and `aarch64` (musl, no runtime dependency). Blocking needs
`nftables`, `conntrack` and cgroup v2, as on Omarchy; `kub0 doctor` names the
missing package for the distribution it is on (`apt install nftables
conntrack`, `dnf install nftables conntrack-tools`, …).

```sh
# from the release page: the tarball for your architecture and its SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS-x86_64-unknown-linux-musl
tar xzf kub0-agent-*-x86_64-unknown-linux-musl.tar.gz
cd kub0-agent-*-x86_64-unknown-linux-musl
sudo ./kub0 install          # /usr/lib/kub0/{kub0d,kub0-block,kub0}, /usr/bin/kub0, the units, the kub0 group, the geo databases
kub0 doctor
sudo kub0 login              # optional, for an org that has a kub0 account
kub0 status                  # after a new login, as a member of the kub0 group
```

The tarball holds the three binaries, the two geo databases, and the license
notices (`THIRD-PARTY-LICENSES.md` is the license of every crate in the build
graph, of Rust's standard library and of musl libc). The same binaries are
also attached loose, under target-suffixed names
(`kub0-x86_64-unknown-linux-musl`, …): `chmod +x` them and `install` accepts
them, but they come without the geo databases, so org country rules need the
tarball. The tarball, the binaries and the checksum file each carry a signed
build provenance, which says which workflow built it from which commit:

```sh
gh attestation verify kub0-agent-*-x86_64-unknown-linux-musl.tar.gz \
  --repo kub0-ai/kub0-agent \
  --signer-workflow kub0-ai/kub0-agent/.github/workflows/release.yml
```

`install` is idempotent (every file is compared before it is written; the
unit restarts only when something it runs changed), installs the polkit policy
only where `/usr/share/polkit-1/actions` exists (a server does not need it),
copies the geo databases when they sit beside the binaries, creates the
`kub0` group when it is absent, adds the user who ran `sudo` to it
(`gpasswd -a`, else `usermod -aG`; nobody else: who else reads and raises on
the system daemon is yours to decide, `docs/system-status.md`), and on a host
without systemd installs the binaries and prints the `kub0d --system` line
to run from your init rather than guessing. OpenRC and runit units are not
shipped.

A bare Linux server with no Kubernetes is an endpoint, on the same footing as
a desktop: it enrols with `kub0 login`, receives the org deny list and network
policies, and reports on the same heartbeat. It is not the cluster product.

## Bandwidth and local history

Settings offers optional Linux connect/unconnected-UDP capture. It is off by
default, requires the separately installed privileged collector, and stores
attempts in History without adding to live counts. Loss counters and procfs
fallback are explicit. See [capture](docs/CAPTURE.md) for installation and
privileged verification; no kernel attachment or overhead result is assumed.

Select an app and open **Connection evidence** to inspect a source record,
including executable, owner, destination, verdict and decision maker when
reported. Retained observations have the same drawer. User annotations and
inferred owner clues keep their own labels.

The selected app also offers timed destination blocking. Choose an IP and
5 minutes, 15 minutes or 1 hour. See [destination rules](docs/DESTINATION-RULES.md)
for scope, socket limitations and kernel expiry.

Apps shows measured TCP upload/download rates and sampled session totals.
Choose **Bandwidth** to sort by the latest measured rate. Rates warm up after
connection discovery and become unknown when measurements are unavailable.

**History** keeps local Linux procfs observations for seven days, up to 10,000
connections. Search by app, executable, IP, hostname, country, or port; choose
one hour, 24 hours, or seven days. **Copy shown as CSV** copies the latest 200
matching observations. Export all retained matches from the terminal:

```sh
kub0 history --hours 168 --csv > kub0-history.csv
kub0 history --query firefox --hours 24 --ndjson
```

One reply carries up to 2,000 rows (`more` says when there were more); narrow
`--query` or `--hours` for the rest.

The private database is `$XDG_STATE_HOME/kub0/history.sqlite`, falling back to
`~/.local/state/kub0/history.sqlite`. No history is uploaded. **First observed**
and **Last observed** describe sampling, not exact connection open/close times.
See [docs/TRAFFIC-HISTORY.md](docs/TRAFFIC-HISTORY.md) for the measurement contract.

## Intel

*The daemon side was exercised live against a container's
`/proc` (see `docs/INTEL.md`, "What was verified"). The views were loaded
under the plain Qt6 `qml` runtime against a stub kit
(`tests/qml/kit-harness.qml`, run by `tests/run.sh`), not in the shell, so the
first shell run should still read `journalctl --user` for warnings.*

The **Intel** view is what this machine can say about its own traffic beyond
"it exists", computed locally from evidence the daemon already holds. Nothing
in it is fetched, and nothing in it is sent.

- **Indicators.** Each connection may carry claims with their basis: the
  executable has been deleted while running, runs from `/tmp`, or is
  world-writable; the app reaches an autonomous system, country or port it
  never has before (only once it is *established*: 20 connections over a
  day, so day one is not an anomaly); it reconnects to one destination on a
  regular cadence; a connection has sent far more than it received; an app
  fanned out to many networks in a minute; the peer is a hosting provider or
  a bare IP with no name. Severity says how much the evidence narrows things,
  never how dangerous it is, and every basis names what else produces the
  same shape. Where a MITRE ATT&CK technique describes the shape it is cited
  as vocabulary, not as a finding.
- **ASN and organisation** on every public peer, from the bundled DB-IP ASN
  database: who announces the range, which is not who rents the machine.
- **Exposure.** Every socket this machine listens on, with its owning app and
  whether it is bound to loopback, one address, or every interface.
- **Watch rules.** Your own: an ASN, country, address or range, hostname
  suffix, port, or app. A match is a warning on the row and a line in Recent
  activity. `kub0 watch add|rm` and `kub0 watches` edit the same rules.
- **Investigate.** Pivot on an address, ASN, app, network, country, port or
  hostname over the seven-day local history: apps, destinations, networks,
  countries, timeline, cadence, and indicator counts.
- **Timeline.** A heatmap of which app talked in which hour over the last day
  or week, from the same history. A connection counts in every hour it was
  observed; click an app to investigate it.
- **Executable hashes.** `sha256` of each app's binary, computed off the
  sample loop and shown in the evidence drawer; this fills the `app.hash`
  field the wire schema reserved from v0.

From a terminal, read from the running daemon:

```sh
kub0 brief --hours 24                  # Markdown digest: totals, indicators, cadences, exposure
kub0 intel --timeline --hours 24       # indicators and exposure, then which app talked in which hour
kub0 why AS13335 --hours 24            # or 1.2.3.4, DE, 1.2.3.0/24, 443, example.com, firefox
kub0 watch add cidr 203.0.113.0/24 "known bad range"
```

The contract, every rung's exact condition, and what each cannot see are in
[`docs/INTEL.md`](docs/INTEL.md).

## Connecting to kub0

The **Endpoints** view lists every device in your tenant inventory that reports
the kub0 endpoint agent, including offline devices. Search by hostname, version,
architecture, or kernel; click a status filter again to clear it. Each row shows
last seen, reported blocking rules, version, and a **this device** marker. Click
a row for architecture and kernel details, and click again to collapse it.

Inventory updates with the existing heartbeat. A failed refresh retains the
last successful inventory and labels it accordingly. Devices become offline
after ten minutes without a heartbeat. Disconnecting or changing accounts
clears the inventory. Remote connection history and traffic remain on each
device; this view reports inventory and heartbeat status.

An account is optional, and accounts are not open to the public yet: this
section is for orgs that already have one. Without an account, monitoring and
your own blocks stay local and nothing is sent. With one, the machine enrols
in your org: it receives the org's deny list and network policies, and sends
the heartbeat described below.

```sh
sudo kub0 login                              # device login through the system daemon (auth default https://kub0.ai)
kub0 login --server-url URL --auth-url URL   # the per-user daemon, custom endpoints
kub0 whoami                                  # github username + node name; never the token
sudo kub0 logout                             # deletes the account file
```

The panel's **Connect** logs in the account that heartbeats: the system
daemon's, through `pkexec /usr/bin/kub0 --json login`, when its socket is
reachable (it shows the code as kub0 prints it), and **Disconnect** runs
`pkexec /usr/bin/kub0 --json logout`. Without a reachable system daemon they
log the per-user daemon in and out through the `kub0` next to it (the
plugin's `bin/kub0`, on the user daemon's socket). With a reachable system
daemon the account card and the network-policy list are the system daemon's,
read over the panel's request connection (`status`, `policies`, `rules`) when
the panel opens and after a login, logout, snooze or resume; otherwise they
are the per-user daemon's, as before.

A code is good for 15 minutes. One that expires unused is replaced on the
spot, four codes in all, before the login fails with `device login expired`.

`--system` writes `/var/lib/kub0/account.json` (0600). Otherwise
`$XDG_STATE_HOME/kub0/account.json` (fallback `~/.local/state/kub0`).

The org deny list is fetched with every heartbeat (`GET
/detonate/api/enforce/denylist`) and, while connected, also arrives live over
`GET /detonate/api/events/stream` (server-sent events, same Bearer token:
`denylist_snapshot` on connect, `denylist_update` per change). The stream
reconnects with exponential backoff from 1 s to 60 s and the poll stays as the
fallback; the Settings fleet section says which is delivering. A row's `action`
is shown as the API sent it (`block`, `monitor`, or "Unset" when empty).

## Exec gate

The system kub0d (`--system`, the unit in `packaging/systemd/`) refuses to
execute a file whose sha256 is on the org deny list: a fanotify
`FAN_OPEN_EXEC_PERM` content gate, the desktop shape of the one kub0's cluster
node agent runs. It is
on by default in system mode (`KUB0_EXEC_GATE=0` turns it off) and never runs
in the per-user daemon, which lacks the privilege for permission events.

It is fail-open on purpose. It loads at start but marks no filesystem and hashes
nothing until it holds a non-empty key set (the org list, live or polled, or a
local `KUB0_EXEC_GATE_DENY_FILE`); a key set that empties again, including a
local `kub0 logout` on the system daemon, flushes the marks and idles the
gate. It does not wait for the network to hold the org list: the daemon keeps
the last list the kub0 API returned in `/var/lib/kub0/execgate/org-list.json`
and arms from it when it starts, so a boot or a restart while the API cannot be
reached is covered by the list as of the last sync. `kub0 status` and
`kub0 doctor` say how old that list is until a sync replaces it. An answer that is late (3 s), a full worker queue, a read error, a file
over the size cap, an org list over 500 rows, or a kernel without fanotify all
allow the exec. The critical-process allowlist (shells, coreutils, systemd,
package managers, the helper itself) never contributes a key and is never
hashed while its inodes match the signature recorded at start.

A match is a product event, not a counter. Each one carries the pid, parent
pid, the file's basename and path, its sha256, the matching row's `reason`,
`promoted_by` and `created_at`, and the decision: `blocked`,
`allowed_local_trust`, `allowed_once`, or `allowed_failopen` (the gate wanted to
deny and could not). It goes to the activity feed (`exec_gate_deny`, under the
*blocks* filter), to the fleet frame's `execGate` object (state, key count,
counters, the last 50 matches, the trusted list), and a block raises a desktop
notification: "kub0 blocked `<name>`: this file matches a sample kub0
detonated on `<date>` (`<reason>`)", with two buttons. **Allow once** lets the
next exec of that sha256 through within five minutes; **Trust on this machine**
records it in `/var/lib/kub0/execgate/trusted.json`, after which it is
subtracted from the key set on every refresh. Both run
`pkexec /usr/bin/kub0 allow-once|trust <sha256>` through the system daemon
and ask for your password every time. Notifications are limited to one per
sha256 per ten minutes. Settings lists the trusted digests with **Remove**
(an untrust raises protection: a group member's request goes to the system
daemon with no prompt; without a reachable system daemon, the helper's
`execgate-untrust`).

Reading the system daemon, the panel shows the gate's live state. On its own
per-user daemon (capture on, or no usable system daemon) what it shows is a
mirror: the system daemon writes `/var/lib/kub0/execgate/state.json`, the user
daemon re-reads it when it changes and says in the heading whether the state
is live, stale (the system daemon stopped writing), or not reported at all.

What the gate **did** reaches kub0 as counters, never as events (the outcomes
channel, `daemon/src/outcomes.rs`). On the heartbeat tick the system daemon
folds the gate's four decision counters (`blocked`, `allowed_once`,
`allowed_local_trust`, `allowed_failopen`) into a window; once the window is
at least `KUB0_OUTCOMES_INTERVAL` seconds old (default 300, min 60) and holds a
non-zero delta it is posted to `POST /ingest/outcomes` as
`{agent, agent_version, platform, window_start, window_end, outcomes:
[{kind: "exec_gate", result, count}]}`. An idle gate posts one zero row a day
so the org's census still lists the endpoint. No path, hostname, digest, pid,
reason or user is on that wire: the key set is pinned by a test, a second test
feeds a deny record through and proves none of its strings appear, and the
server rejects any extra field with a 400. Windows kub0 did not accept wait in
`<state dir>/outcomes-spool.json` (0600, newest 288 kept) and go out oldest
first, eight per tick, when it answers again, across a daemon restart. The
user daemon never reports: its frame is a mirror. `KUB0_OUTCOMES=0` keeps
every outcome on the host. The kub0 console raises one alert per org per day
when a report carries `blocked > 0`.

`sudo bash tests/execgate-selftest.sh` proves the gate end to end on a root
Linux host with no kub0 server; `scripts/install-privileged.sh` installs the
daemon, the unit, the helper and the polkit actions idempotently and prints what
it did.

Env: `KUB0_SERVER_URL` (default `https://api.kub0.io`), `KUB0_NODE_NAME`
(default hostname), `KUB0_HEARTBEAT_INTERVAL` (seconds, default 60, min 15),
`KUB0_OUTCOMES_INTERVAL` (seconds, default 300, min 60), `KUB0_OUTCOMES`
(`0` disables the outcomes channel).

Heartbeat POST `/ingest/heartbeat` JSON only: `node_name`, `probe_ver`,
`agent`, `agent_ver`, `kernel_version`, `arch`, `lsm_active` (false),
`lsm_capable`, `event_count`, `blocks_active`, `tags` (your own network
labels), `policy_matches` (org policy match counts with up to 32 matched
destination addresses per rule), and `dest_networks` (empty unless you turn
on *Share destination networks* in Settings → Intel, then the /24 or /48 keys
of new public destinations, never addresses or apps). No connection rows, no
history, no rules. The exact key set is pinned by a test in
`daemon/src/kub0.rs`.

## Blocking

*Inherited from upstream. Paths updated for the rename; semantics unchanged. The
block and unblock path was re-verified end to end in this repo on 2026-09-15 (see
[`docs/VERIFICATION.md`](docs/VERIFICATION.md)); the rest of this section is
upstream's description.*

Blocking uses nftables through the installed helper. Monitoring does not.
Production blocks always run `/usr/lib/kub0/kub0-block`; checkout copies are
never authorized.

**Which daemon the panel reads.** One, where it can. When the system daemon
is installed and this session can reach its socket (you are in group `kub0`),
the panel reads its rows, history, watch rules, activity and exec gate from
the system daemon and starts no `kub0d` of its own. It then shows what
`kub0 apps` shows: the whole host, system services and other accounts'
connections included, one watch list and one set of network names. The panel
starts its own per-user daemon, as every release before 0.5 did, in two cases:
the system daemon cannot be used from this session (not installed, or not in
the group yet), and while **capture** is switched on, which only the panel's
own daemon can run (and only where the plugin has a `kub0d` to start). It
moves between the two by itself: on its own daemon, or on none, with kub0
installed it asks the system daemon again every ten seconds and on every panel
open, and switches when it answers; one that loses the system daemon's stream
retries it for a few seconds (a restart is over in one) before starting its
own. With nothing of its own to start it says the system daemon is not
answering, and keeps asking.

On the system daemon one row can hold several accounts' processes, because a
binary has the same app id under every account that runs it. A block from the
panel names only the processes of the account using it; an app that only
another account runs is shown, and blocking it is its owner's or root's. The
account card and policy list are that daemon's live frames; a `status` read
only supplies who the account is after a login or logout.

**Where the panel sends a change.** It sends every block, unblock,
destination rule, pause/resume, exec-gate trust and policy snooze/resume to
the system daemon, which runs the helper as root for it and is the only
daemon that enforces:

- A change a member of the `kub0` group may make (an app block, a
  timed destination block, resume, untrust, a policy resume) is a control
  request on a short-lived, request-only connection to
  `/run/kub0/kub0.sock`. No password prompt.
- A change the system daemon keeps to root (unblock, cancelling a destination
  rule, pause, trust, allow once, a policy snooze, and the "endpoints only"
  address block) runs `pkexec /usr/bin/kub0 --json …`: the password prompt
  comes from polkit's kub0 action (`ai.kub0.agent.kub0`, asked every time),
  and kub0 tells the daemon whom it acts for, so the helper's ownership checks
  act on you.
- If the system socket cannot be reached (no system daemon, or you are not in
  the group yet), a block or unblock runs `pkexec /usr/lib/kub0/kub0-block`
  as it did before; that fallback stays for one release. A policy snooze or
  resume still goes to the system daemon through `pkexec /usr/bin/kub0` when
  it is installed, and the panel says it cannot show the result until you log
  in again. Only a per-user install (no `/usr/bin/kub0`) sends it to the
  per-user daemon, where nothing is enforced, so it only quiets alerts.

`sudo kub0 install` brings the installing person's watch rules and network
names over from the panel's own daemon (`~/.local/state/kub0`), once: each is
sent to the system daemon as a request, a watch rule acting for them so it
stays theirs to change. What the system daemon already has is left as it is
and listed, and the person is only noted as done when every file was read and
every request answered. Names go to the org with the heartbeat, as any
`kub0 tag` name does. Names the org sent, history and the activity log are not
carried; the system daemon has its own.

A **name** (tag) and a **watch rule** go to the daemon the panel reads.
Reading the system daemon, both are requests to it (`tag`, `watch-set`,
`watch-delete`: a member changes the watch rules they set), and a refusal is
shown where the change was made. On its own daemon the panel keeps the 0.4
arrangement: watch rules stay with the per-user daemon, and a name goes to
both, with a notice when only the panel has it. The system daemon keeps its
own record of the blocks it runs; the panel writes its own note of a block
outcome only to its own daemon.

Every PID passed to `block-app` is checked against the **invoking user**
(`PKEXEC_UID`, then `SUDO_UID`, never the helper's root euid). The process must
exist, its UID must match that user, and starttime must still identify the same
PID. PIDs owned by other users, PID 1, kernel threads, and missing PIDs are
refused.

`block-app` creates `/sys/fs/cgroup/vallum.slice/vallum-<app>/`, migrates the
app's process tree into it, installs

```
socket cgroupv2 level N "vallum.slice/vallum-<app>" drop
```

on `table inet vallum`, migrates every live PID in the validated forest, and
flushes conntrack for TCP and connected UDP remotes. The flush is host-wide, so
it skips every address an endpoint block refuses (loopback, link-local,
multicast, the tailnet, and this machine's nameservers and default gateways).
The forest is the seed PIDs plus ancestors and descendants running the same
executable, and every same-user process in the app's own `app-*.scope`. `verified: true` is
returned **only** when every live PID is in the cgroup, the nft rule lists, and
conntrack deletion succeeded. Partial migration rolls back. Processes already in
the root cgroup are refused, and endpoint fallback is offered instead.

If cgroup migration or the match fails, the UI offers **endpoints only, affects
all apps** rather than silently substituting `block-ips`. Endpoint fallback
records per-app ownership, so **Unblock** removes that app's addresses while
shared addresses owned by another blocked app stay. `system` and `unknown` rows
cannot be blocked.

That ownership is one file, `/var/lib/kub0/endpoint-owners.json`. If it is
there and cannot be read as that record (damaged, empty, in another shape), an
endpoint block or unblock is refused and changes nothing: the addresses in the
set stay blocked, and the file is left as it was. `kub0-block status` then
reports `ownersKnown: false` with the reason. The way out is to lift every
block and start again, `sudo kub0 teardown --yes`, which also removes the
file; or to put a good copy of the file back.

`kub0-block teardown` deletes `table inet vallum` and the plugin's cgroups,
and reports failure if either remains. Other firewall tables are never touched.

## Troubleshooting

Every entry here is a failure that actually happened during install and cost
real time. They share a shape worth naming up front: the plugin looks broken
when it is only unfinished, or looks unchanged when it is only stale.

**Nothing appears in the bar.** The plugin is discovered but not enabled.
Discovery and enablement are separate steps, and a discovered-but-disabled
plugin has no icon, no panel, and—most confusingly—no running service, because
the shell only mounts a `service` entry point for an enabled plugin. Check:

```sh
omarchy-shell shell listPlugins | grep -A3 ai.kub0.agent
```

`"enabled": true` is what you need. `"active": false` alongside it is *not* a
fault: `active` answers "is this the current bar option", and only a
`kind: "bar"` plugin can ever be one.

**Edits do nothing, and errors cite line numbers that no longer exist.** You
installed by symlink and the shell is serving a stale compiled component. The
watcher is `inotifywait -m -r`, which does not descend through a symlink, so
your edit raised no event; `rescanPlugins` does not rescue it either, because
it re-reads manifests and leaves compiled components alone. Run
`omarchy-restart-shell`. If the reported line number disagrees with the file on
disk, that mismatch *is* the symptom.

**`sudo: a terminal is required to read the password`.** The install script is
fine; the shell you ran it from has no controlling tty. Run it from a real
terminal window.

**The pill is dimmed.** The count is not coming from this machine. Ask which:

```sh
omarchy-shell ai.kub0.agent status ''
```

`"daemon": "missing"` means `kub0d` was never built—run `./build.sh`.
`"fallback": true` means the service is playing the replay fixture because it
could not reach the daemon.

**`Target not found` from `omarchy-shell`.** The IPC target is the full plugin
id, not a short name, and `status` takes one string argument even though it
ignores it. All three of these are wrong—`omarchy-shell vallum status`,
`omarchy-shell shell call ai.kub0.agent status`, and any form omitting the
argument. This is the correct one:

```sh
omarchy-shell ai.kub0.agent status ''
```

**Block controls are greyed out.** Either the helper is not installed
(`"needsHelper": true`) or a kernel feature is missing. `kub0-block status`
names which, and the packages are in the table above. Monitoring is unaffected
either way—it needs no privilege at all.

## Honest limitations

- Sub-second flows can slip between 500ms `procfs` samples. The seen-set is
  advisory.
- TIME_WAIT and LISTEN sockets are parsed then dropped. They are not
  conversations.
- Linux TCP counters use sock_diag. UDP, unsupported sources, and unavailable
  kernel measurements remain unknown. Totals count sampled deltas, not all traffic
  since an app launched; connections entirely between polls remain invisible.
- Other-uid processes appear as `system` (no desktop identity without privilege)
  and cannot be blocked.
- An app block cuts the IP traffic of sockets the app's own processes open. It
  does not contain an app that asks something else to connect for it: D-Bus to
  `systemd --user` for a transient unit, a URL handed to an unblocked browser,
  any other process of yours. Unix sockets are not IP traffic and are not
  matched. It stops an honest app's traffic, not a hostile one. Endpoint blocks
  are host-wide and are not escaped this way.
- App identity is the process's exe basename or `comm`, both chosen by the
  process, or a `.desktop` file in `~/.local/share/applications`. Anything
  running as you can present itself under another app's row. The block
  confirmation lists every program in the row, so a joined row shows a second
  one before you confirm. No process of yours can take the `system` or
  `unknown` row, which cannot be blocked.
- City-level geo is out of scope. Centroids are country-level.
- Linux binaries are not committed to the repository. They come from a
  release, or from `./build.sh`.

## Dev

```sh
./tests/run.sh          # cargo test + node model suites + kub0d --self-test
cargo test --workspace
```

What has been proven on a real machine, and what has not, is in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md). Contributing:
[`CONTRIBUTING.md`](CONTRIBUTING.md). Reporting a vulnerability:
[`SECURITY.md`](SECURITY.md).

`--system` selects root mode (`/run/kub0/kub0.sock` at 0660, state in
`/var/lib/kub0/daemon`); `--socket` and `--state-dir` still override.
`kub0d` refuses an explicit `--state-dir` under temporary
storage (`/tmp`, `/var/tmp`, `$TMPDIR`, and their symlink aliases), including paths
whose final directory does not exist yet. Cleanup there could delete the account
file and stop heartbeats. Use a durable path or omit the override. Environment-based
defaults are unchanged. With the daemon's own `status|history|disconnect` retired, state
is read back only through a running daemon (`kub0 status`, `kub0 history`,
`kub0 logout`). A state directory already under temporary storage is reached by
starting `kub0d` with `XDG_STATE_HOME` set to its parent, since an
environment-based default is never refused.
Install `packaging/systemd/kub0d.service`, copy the binary to
`/usr/lib/kub0/kub0d` and the geo databases to `/usr/share/kub0`, the
`--system` data dir:

```sh
sudo install -D -m0644 -t /usr/share/kub0/geoip data/geoip/dbip-country-lite.mmdb \
  data/geoip/dbip-asn-lite.mmdb data/geoip/ATTRIBUTION.txt
```

then `systemctl enable --now kub0d` (the steps are in `packaging/systemd/README.md`).

The Omarchy plugin's per-user daemon is unaffected without `--system`.

QML hot-reloads only from a **real directory** at
`~/.config/omarchy/plugins/ai.kub0.agent/`. If you took the symlink option
above, it does not—see the note in Install—and every QML change needs
`omarchy-restart-shell` before the shell is running what you wrote.

`tests/run.sh` runs the Qt6 QML tests (`tests/test_*.qml` and the kit harness
under `tests/qml/`) whenever a Qt6 `qml` runtime is found, and prints
`skipped` when none is. They
prove the files load and bind and that fixture rows render; they do not load
`Panel.qml` or `Service.qml` whole, and they do not prove the result looks
right. For a change the suite does not reach, a running shell is the check, and
the shell's own log is the only thing that reports QML errors:

```sh
journalctl --user --since "1 min ago" | grep -i kub0
```

A clean grep after a restart proves the file loaded and bound without error.
It does not prove the result looks right, and both UI defects fixed before the
harness existed were invisible to it.

Replay without a live daemon:

```sh
./bin/kub0d --replay tests/fixtures/replay.ndjson \
              --socket "$XDG_RUNTIME_DIR/kub0.sock"
```

If `kub0d` is missing entirely, the service plays `data/replay.ndjson` inside
QML so the map still opens.

## Attribution

- Fork of [omarchy-snitch](https://github.com/ccdwyer/omarchy-snitch) by
  Christopher Dwyer, MIT. Full terms retained in [`LICENSE`](LICENSE).
- File-hygiene patterns adapted from
  [omasnatch](https://github.com/weedwhitesandwine/omasnatch) by
  weedwhitesandwine, MIT.
- Interoperates with [OpenSnitch](https://github.com/evilsocket/opensnitch),
  GPL-3.0. No code taken, no endorsement implied.
- IP geolocation by [DB-IP](https://db-ip.com) Country Lite and ASN Lite,
  [CC-BY-4.0](https://creativecommons.org/licenses/by/4.0/).
- Landmass from [Natural Earth](https://www.naturalearthdata.com/) 110m, public
  domain.
- Indicator vocabulary cites [MITRE ATT&CK®](https://attack.mitre.org)
  technique ids and names, used with attribution under MITRE's terms of use;
  no ATT&CK data is bundled.
- Flags are bundled geometric SVGs with ISO code fallback, no emoji font
  dependence.

[`THIRD-PARTY.md`](THIRD-PARTY.md) is the authoritative record and is maintained
as code is taken, not reconstructed before publication.

## Remove

```sh
# only if the system kub0d is installed: it re-applies its org's block rules
sudo systemctl disable --now kub0d kub0-expiry.timer
pkexec /usr/lib/kub0/kub0-block teardown
pkexec rm -f /usr/lib/kub0/kub0-block \
             /usr/share/polkit-1/actions/ai.kub0.agent.policy
# only if the system kub0d is installed: its binaries, units and geo databases
sudo rm -rf /usr/lib/kub0 /usr/share/kub0
sudo rm -f /usr/bin/kub0 /etc/systemd/system/kub0d.service /etc/systemd/system/kub0-expiry.*
omarchy plugin remove ai.kub0.agent
# only if you opted in to the keybind
sed -i '/-- BEGIN ai.kub0.agent/,/-- END ai.kub0.agent/d' \
  ~/.config/hypr/bindings.lua
```

Run `teardown` before deleting the helper. It is what removes
`table inet vallum` and the cgroups, and once the binary is gone there is
nothing left that knows how.
