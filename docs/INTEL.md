# Local intelligence

What kub0 can say about a connection beyond "it exists", computed on this
machine from this machine's evidence, and how far each claim reaches.

Nothing in this document describes a lookup against a remote service. The
indicator engine reads the row, a per-app baseline learned from earlier rows,
the cadence of earlier connections to the same place, the executable on disk,
and the bundled DB-IP databases. Nothing is fetched to produce an indicator
and nothing described here is sent anywhere, the heartbeat included.

## What was verified

On 2026-10-11 the daemon in this change was run unprivileged in a Linux
container against that container's own `/proc`, with a Python client on its
socket. The greeting carried `hello`, `fleet`, `activity`, `listeners`,
`watchlist`, `snapshot` in that order; the `listeners` frame named four
sockets (two bound to every interface, two to loopback) with their owning
apps; every public row carried `asn` and `org` from the bundled ASN database;
one row carried an `upload-heavy` indicator whose basis matched its counters
(1.0 MiB sent, 21 KiB received); a `watch` set command stored a rule and was
answered with the list, a malformed one was answered with the list unchanged
and an error; `investigate` over everything aggregated 16 rows into 2 apps and
3 destinations with a 168-bucket timeline, and a malformed subject answered
with the error and an empty pivot; the daemon's then client verbs `watch add`,
`investigate 443` and `brief` read the same state directory and rendered. The Rust
unit tests pin every rung of the indicator engine, the baseline's learning
gate, the cadence and fan-out detectors, watch-rule matching for every kind,
executable flags, hashing, pivot aggregation and the brief renderer; the Node
tests pin the panel's ordering, filtering, labels and the wire allow-list.

A second run with the release build on 2026-10-11 watched the asynchronous
half land: both live rows gained `evidence.hash` (SHA-256 of a 257 MB and a
31 MB binary), `evidence.package` read `none` because dpkg owns nothing under
`/opt` on that host, and each row gained the `exe-unpackaged` notice on
landing, with its lineage (the process, its parent, a shell and the
supervisor above it, with cwd and command line) present from first sight.

**QML, verified against a stub kit on 2026-10-12.** The first rounds had no
Qt6 runtime and checked `IntelView.qml` for bracket balance only. Once one was
installed, `tests/qml/kit-harness.qml` instantiated `IntelView`, `HistoryView`,
`ConnectionEvidence` and `DestinationRules` against the minimal `qs.Commons`,
`qs.Ui` and `Quickshell` stand-ins in `tests/qml/kitstub/` with a fixture
model (indicators at all three severities, DNS- and PTR-sourced names, ASN,
lineage, a package answer, three listeners, two watch rules, a 24-bucket
timeline, a pivot and a prevalence answer) and clicked through the block
offer, the pivot buttons, the watch form and the section tabs. It found three
defects no other test could see, all fixed in the same change: the block
offer's children referenced a property declared on their parent `Flow`, which
QML does not put in scope (every row logged a `ReferenceError` and the
duration buttons never rendered); the same `Flow` anchored a child, which a
`Flow` refuses; and the drawer's bar chart had `id: timeline`, which shadowed
the root's `timeline` property in the heatmap's bindings, so the Timeline
section would have rendered no rows. `tests/run.sh` runs the harness whenever
a Qt6 `qml` is present. What the harness cannot show is how the views sit in
the real shell kit, so the first live run should still read `journalctl
--user` for QML warnings, as the README's Dev section says. Also not verified
here: the executable hash landing on a row (the probe was queued and the row
re-sent on completion in unit tests, not watched end to end on the socket),
and the baseline rungs, which by design cannot fire inside a one-day-old state
directory.

## Indicators

An indicator is a claim with its basis, attached to a connection. Each has a
stable id, a severity, an optional MITRE ATT&CK reference, and a sentence of
evidence written for the person reading it. The row carries them under
`indicators`, highest severity first; the evidence drawer lists them; the
Intel view sorts and filters them across every current row.

Severity is about how much the evidence narrows things, not about danger:

| severity | means |
|---|---|
| `warning` | a fact about this machine that is rarely benign, or a watch rule you wrote |
| `notice` | a departure from this app's own learned behaviour, or a shape worth naming |
| `info` | context that helps read the row and asks for nothing |

| id | severity | fires when | ATT&CK |
|---|---|---|---|
| `watchlist` | warning | the connection matches one of your watch rules | |
| `exe-deleted` | warning | `/proc/<pid>/exe` ends in ` (deleted)`: the file is gone while the process runs. A package upgrade mid-run does this too | T1070.004 |
| `exe-temp-dir` | warning | the executable is under `/tmp`, `/var/tmp` or `/dev/shm`; an AppImage's `/tmp/.mount_*` runtime is excluded, and a Go build directory under the go tool raises `exe-build-dir` instead | T1036.005 |
| `exe-world-writable` | warning | the executable file is writable by every user | T1574 |
| `exe-hidden-home` | notice | the executable is under a hidden directory in your home, `~/.local/bin` excepted | T1036.005 |
| `exe-build-dir` | notice | the executable is under `/tmp/go-build<digits>/` and the `go` tool is its parent or an ancestor within three hops, which is what `go test` and `go run` do. Either half alone (the path without the go tool, the go tool without the path) is still `exe-temp-dir` | |
| `exe-changed` | notice | the executable's mtime is later than the process start | |
| `exe-unpackaged` | notice | the executable is in a system directory (`/usr`, `/opt`, `/bin`, ...) and the host's package manager (pacman, dpkg or rpm, local database only, the merged-`/usr` alias tried too) says no package owns it. Added when the lookup lands, so the row is re-sent; later rows of the same binary carry it from birth. A binary deleted while running is never asked about | T1036.005 |
| `new-asn` | notice | first time this app reaches this autonomous system, once the app is established | |
| `new-country` | notice | first time this app reaches this country, once established | |
| `uncommon-port` | notice | first time this app uses this port, the port is not in the common set, once established | T1571 |
| `beacon-cadence` | notice | at least 6 connections from this app to this destination with inter-arrival jitter ≤ 25% and a median interval ≥ 5 s | T1071 |
| `upload-heavy` | notice | this connection has sent ≥ 1 MiB and at least 5× what it received. Re-evaluated as counters move; the row is re-sent when the answer changes | T1048 |
| `fan-out` | notice | this app reached ≥ 25 distinct /24 or /48 networks inside one minute; raised on the connections that widened the spread, not on every connection that followed | T1046 |
| `hosting` | info | the PTR name or ASN organisation is a hosting provider | |
| `no-ptr` | info | a public address with no reverse-DNS name, after a lookup finished | |

The ATT&CK column names the shape of what was observed in the vocabulary
analysts already share. It is never a statement that the technique is in use,
and every basis sentence says what else produces the same shape: update
checkers beacon, backup clients upload, dev builds run from `/tmp`.

### Which rows the behaviour rungs apply to

Baseline, cadence, upload and fan-out describe an app the user chose to run,
reaching the internet. They are computed only for public peers (a dev server
on localhost and a NAS on the LAN are not places an app "goes", and a helper
polled on loopback is not a beacon), and never for `system` rows, which are
another uid's daemons on a schedule by design. Executable flags and watch
rules apply to every row. On the system daemon only service accounts are
`system` rows: a logged-in user's app is named the way the user's own daemon
names it, carries its owner, and gets the behaviour rungs like any other app;
its indicators name it with the account, `Brave (alice)`.

### From a claim to an action

A notice- or warning-level indicator row on a live connection offers to block
its destination for 5 minutes, 15 minutes or an hour. This is the timed
destination rule the Apps view already has (`docs/DESTINATION-RULES.md`,
helper verb `block-scoped`), scoped to that app and that address, through the
same gates: the helper must be installed and ready, enforcement not paused,
the app blockable (never `system` or `unknown`), not already blocked as a
whole, with a running process to scope to, one timed rule per app, and never
an address the host cannot afford to lose. When a gate is closed the row says
which, in the words the Apps view uses. Info rows never offer it: a hosting
provider is context, not a reason to block. No new privilege surface is
added; the polkit action is the existing `block-scoped` one.

### What "established" means

The baseline rungs fire only once an app has made at least 20 connections
over at least 24 hours on this machine. Before that, every destination is
new, and a feature that calls day one an anomaly trains you to ignore it by
day two. The baseline is `baseline.json` in the state directory: per app, the
first time each ASN, country and port was reached. Private destinations teach
nothing about where an app goes on the internet and are not recorded against
it, though they count toward the app being established. `system` and
`unknown` rows have no identity to learn and get no baseline.

### What the rungs cannot see

- A connection between two samples is never observed, so never counted,
  baselined or beaconed. Capture (`docs/CAPTURE.md`) narrows this for
  attempts but does not feed the baseline.
- `hostname` is the name this user's software asked DNS for when the optional
  collector saw the answer to that software's own query from a configured
  resolver (`hostnameSource: dns`), else a PTR name looked up
  only with `--rdns` or for unattributed rows (`ptr`). With neither, a blank
  name proves nothing and `no-ptr` does not fire.
- `upload-heavy` reads TCP counters; UDP transfer is unknown and never heavy.
- Executable flags describe the file at `/proc/<pid>/exe`. A process that
  execs something else, or is a script under an interpreter, is judged by the
  interpreter's binary.
- Nothing here reads the system firewall, so an indicator on a connection
  says nothing about whether another engine allowed it.

### Executable hash

`evidence.hash` is `sha256:<hex>` of the executable, computed once per
(path, size, mtime) on a worker thread and patched into every row of that
executable when it lands, the way reverse-DNS names are. Files over 512 MiB
are not hashed. This fills the field `docs/SCHEMA.md` 2.2 reserved from v0.
It is a hash of the file now, not of the bytes in memory; `exe-changed` is
the flag for the case where those differ.

### Lineage and package

`evidence.lineage` carries the owning process's ancestors (parent first, up to
eight, stopping at pid 1), its command line (cut at 512 characters) and its
working directory, read from `/proc` once per process at first sight (Linux
only: macOS rows carry no lineage).
`truncated` says the chain stopped early because an ancestor had gone. It is
context for reading an identity, never a source of one: the app is still its
exe path. `evidence.package` is what the package manager said owns the
executable, or `"none"`; it is asked only for system directories, since a
binary under `$HOME` is unowned by construction and that is not news. Both
show in the evidence drawer.

### Notifications

A desktop notification (`omarchy notification send`) is sent for a watch hit
or a warning-level indicator on a new connection, when the `notifyIntel`
preference is on (default on). Notices and info never interrupt. The hello
replay is history and never notifies; only one-entry activity frames do.

## ASN and organisation

Every public peer carries `asn` and `org` from the bundled DB-IP ASN Lite
database. The organisation is the registrant of the announced range,
"Hetzner Online GmbH", and says who announces the range and nothing about who
rents a machine in it. The panel shows it in the evidence drawer as "Network
(ASN)" and uses it in the Intel view; it never replaces a name in the Apps
list, for the reason `suggest.rs` gives about hosting PTRs: saying where is
not saying who. The database was already bundled for the never-block floor;
this change reads its organisation field too. Attribution is unchanged.

## Exposure

`{"type":"listeners"}` carries every TCP socket in LISTEN and every UDP
socket bound below the kernel's ephemeral range
(`net.ipv4.ip_local_port_range`, default 32768) with no remote, each with its
owning app, exe, uid and a `scope`: `all` (bound to `0.0.0.0` or `::`),
`loopback`, or `address` (one specific address). Sent in the greeting and
whenever the set changes. Owners resolve the same way connections do, so
another user's socket is `system`.

"All interfaces" means reachable from any network this host is on, firewall
permitting. kub0 does not read the firewall and does not say which networks
can actually reach it.

## Watch rules

A watch rule is the one indicator you write yourself. It raises a `warning`
on every new connection that matches, and records a `watch_hit` activity
entry with the rule, the match and the peer. Rules are evaluated when a
connection is first seen; a rule added while a connection is open does not
fire on it until it reconnects.

Kinds and values:

| kind | value | matches |
|---|---|---|
| `asn` | `13335` or `AS13335` | the peer's ASN |
| `country` | `KP` | the peer's country |
| `cidr` | `203.0.113.7` or `203.0.113.0/24` | the peer address, v4-mapped v6 included |
| `host` | `example.com` | the PTR name or any name under it |
| `port` | `4444` | the remote port |
| `app` | `curl` or `/usr/bin/curl` | the app id or executable path |

Rules live in `watchlist.json` in the state directory, at most 256. The panel
edits them over the socket (`{"cmd":"watch","action":"set"|"delete",...}`,
answered with the full list and an error string when refused), `kub0 watch
add|rm` sends the same requests, an editor may change the file directly, and the daemon re-reads the file
within five seconds of either. When both changed, the file's rules win on
membership and the daemon's hit counts are carried over by id, then the
merged list is written once. Hit counts are persisted on the rule and
republished to the panel as they move.

`host` rules need a name: a DNS answer the optional collector matched to the
app's own query (`docs/CAPTURE.md`, "DNS answers"), a PTR lookup with `--rdns`, or an
unattributed row's own lookup. A name that arrives after the row does is matched then, the
way it would have been had the resolver been quicker; the other kinds were
already evaluated and are not counted twice. A watch hit is written to the
activity log, and notified, once per (rule, app, peer address) per daemon run.

Watch hits are shown and logged locally. They are not reported on the
heartbeat.

## Investigate

`{"cmd":"investigate","request":"...","subject":"...","since":ms}` answers
with `{"type":"investigate","request","pivot","error"}`: everything matching
the subject across retained history (`docs/TRAFFIC-HISTORY.md`, seven days,
10,000 rows) plus live rows the store has not written yet. A subject is
`kind:value` with kind one of `ip`, `app`, `asn`, `network`, `country`,
`port`, `host`; a bare value is classified (an address, `AS13335`, a
two-letter code, a CIDR, a port number, a dotted name, else an app id). An
empty subject pivots on everything.

The pivot carries totals (connections, live, sampled bytes, first and last
sampling time), apps, destinations, countries, ASNs, ports, indicator counts
with one example basis each, an hourly timeline over the window, and the
reconnection cadence to the subject when the arrivals show one. Lists are
capped at 50; `truncated` says the history read hit its cap, so totals are a
floor. Counts are sampled connections, never packets or flows.

`kub0 why SUBJECT [--hours N]` asks the running daemon for the same pivot
(the `investigate` read; `--json` for the structure). It replaced
the daemon's own `investigate` verb, which is retired.

## Timeline

`{"cmd":"timeline","request":"...","hours":24|168}` answers with
`{"type":"timeline","request","timeline","error"}`: for every app, how many
connections were observed in each bucket of the window (hourly up to 48 h,
six-hourly beyond), busiest apps first, at most nine rows with the rest
folded into `other`. This is presence, not arrivals: a connection counts in
every bucket between its first and last sampling time, and a live row runs to
the end of the window. An hour in which a connection stayed open is an hour
the app was talking, which is the question a timeline answers.

The Intel view draws it as a heatmap: one hue, light to dark for magnitude,
sqrt-scaled to the busiest cell so a quiet hour beside a busy one stays
visible; labels in the panel's own ink; a hover line naming the cell and its
count; a click on an app row opens the investigate drawer on that app.
`kub0 intel --timeline [--hours N]` renders the same data as a terminal
heatmap, which is also the table view the chart stands beside (it replaced
the daemon's own `timeline` verb).

## Brief

`kub0 brief [--hours 24]` (Markdown; `--json` for the structure) renders a
digest of the
window: totals, new apps and networks (from the activity log), blocks, watch
hits, indicators by severity with an example, regular cadences per
(app, destination), top destinations with ASN, apps with sampled transfer,
countries, and the sockets this machine is listening on right now. The
Markdown is meant for a terminal, a note or a ticket. Everything in it is a
reading of local state; nothing is fetched.

## Activity

Two closed kinds were added: `watch_hit` and `indicator`. `indicator` is
written for notice- and warning-level indicators on a new connection, and for
the `exe-unpackaged` notice when it lands later, once per (indicator, app,
peer address) per daemon run, so a periodic app is logged once, not once per
period. Info indicators stay on the row.

## History

Retained observations keep their indicators, and the History view shows them
on each row as `Severity · Label`, red when any is a warning.

## Where kub0 fits

Everything above runs without an account. What an account adds, and only by
opt-in, is the dimension one machine cannot have: how many other endpoints in
the org reached the same destination.

**Sharing is off by default**, and it is a setting of the daemon that reports
the host. Where the system daemon is installed that is the system daemon:
`sudo kub0 share on` turns it on (root, since it decides what leaves the
machine), `kub0 share off` turns it off (anyone in group `kub0`), bare
`kub0 share` and `kub0 status` show it, and it is kept in
`/var/lib/kub0/daemon/settings.json` across restarts. The panel's switch
(Settings → Intel) drives the same setting when the panel reads the system
daemon, asking for an administrator to turn it on. Until 0.5 the switch only
restarted the panel's own daemon with `--share-destinations`, and next to a
logged-in system daemon that daemon reports nothing, so the switch had no
effect there. On a per-user install it is still the panel's `shareDestinations`
preference and that flag. Off takes effect at once: the keys queued for the
next heartbeat are dropped, a batch a failed heartbeat had in flight is not
put back, and none is collected while no account is connected. With sharing
on, the
heartbeat's `dest_networks` carries the /24 or /48 network keys of public
destinations first reached since the last successful heartbeat, at most 256,
deduplicated, only while an account is connected. Never an address, never an
app, never a port, never a time. Off, the key is sent empty and nothing from
the Intel layer leaves the machine.

The server may answer with `prevalence: [{network_key, nodes, first_seen}]`,
`nodes` excluding this endpoint. The daemon merges answers across heartbeats
(newest wins per key) and publishes them on the `fleet` frame with
`prevalenceSupported`: `null` until a heartbeat succeeds, `false` when the
server's 200 carried no `prevalence` key. The panel shows one line under an
indicator row and in the investigate drawer: "Seen on N other endpoints in
your org", "First in your org", "no answer yet for this network", or "not
answered by this server". It never shows a count the server did not give.

**Server status.** As of this writing the kub0 API does not answer
`prevalence`; a current server ignores `dest_networks` (it decodes without
rejecting unknown fields) and the panel reports "not answered by this
server". The client side is built so the feature lights up when the server
does, and so that what is sent is written down here before it is sent
anywhere.
