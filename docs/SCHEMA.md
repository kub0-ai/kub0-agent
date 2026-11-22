# kub0 agent wire schema v0

The contract between every data source, the UI, and (later) the fleet layer.

Two independent agents encode against this: the desktop plugin and the
cluster-side sensor. They ship on different cadences with no coupling, which
means **a mistake here cannot be fixed with a coordinated release**, and the
free-local tier means upgrades can never be forced. Both sides therefore:

- carry an explicit `schema` integer on every record
- **ignore unknown fields** rather than erroring
- treat every addition within a major version as additive and optional
- **never reuse a field name** with different meaning

Transport is newline-delimited JSON over a unix socket
(`$XDG_RUNTIME_DIR/kub0.sock` in user mode, `/run/kub0/kub0.sock` with
`--system`), inherited from the upstream daemon (`snitchd` there, `kub0d` here).

The first frame on a new client is `hello`. `mode` is additive (`user` is the
historical default; `system` is the root daemon). `account` is additive and
never includes the token (`last_heartbeat_ok` is `null` until a heartbeat is
attempted):

```json
{"type":"hello","version":"0.1.0","pid":1,"coverage":"tcp+connected-udp","rdns":false,"mode":"user","account":{"connected":false,"node_name":"host","github_username":"","last_heartbeat_ok":null}}
```

`github_username` is additive and is not a secret. The account token never appears on this frame.

---

## 1. Modes

Listen and intercept are **not two architectures**. They are two attach
profiles feeding one event stream, so history stays continuous across a mode
switch and the UI never changes shape.

| | Listen | Intercept |
|---|---|---|
| Attach | `tracepoint` / `fentry` on `tcp_v4_connect`, `udp_sendmsg` | `cgroup/connect4`+`connect6`, `cgroup/sendmsg4`+`sendmsg6` |
| Emits a verdict | no | yes |
| Can break networking | **no** | yes |
| `verdict.action` | always `observed` | `allow` / `deny` / `reject` / `ask` |
| Tier | free, all sources | free local, fleet-managed when paid |

`cgroup/connect4` rather than BPF_LSM: BPF_LSM needs `lsm=...,bpf` on the
kernel cmdline, which is a reboot and a boot-parameter edit, and that is a
fatal install requirement for a desktop plugin. `cgroup_sock_addr` needs only
cgroup v2. `kub0-block` already builds `vallum.slice/vallum-<app>/` and
migrates process trees into it, so the existing cgroup machinery is the anchor
the verdict program attaches to, not a dead end.

`cgroup/sendmsg4` covers unconnected UDP, which is the QUIC hole that both
upstream plugins have.

---

## 2. Event

One observed flow. Emitted by every source.

```jsonc
{
  "schema": 0,
  "kind": "flow",
  "ts": 1757600000000,          // ms since epoch
  "id": "tcp:54321:142.250.1.1:443",
  "source": "opensnitch",       // opensnitch | procfs | libproc | ebpf
  "state": "live",              // live | closed | observed

  "app": {
    "key": "/usr/bin/firefox",  // CANONICAL IDENTITY, see 2.1
    "name": "Firefox",
    "desktop": "firefox.desktop",
    "icon": "firefox",
    "pid": 1234,
    "hash": null,               // "sha256:..." when known, see 2.2
    "container": null,          // "flatpak:org.mozilla.firefox", "docker:<id>"
    "system": false,            // true = other uid, identity unavailable
    "owner": null               // { "uid": 1000, "name": "alice" } from the system daemon, see 2.1
  },

  "proto": "tcp",               // tcp | udp
  "local":  { "ip": "10.0.0.5", "port": 51234 },
  "remote": { "ip": "142.250.1.1", "port": 443, "host": "google.com" },

  "verdict": {
    "action": "allow",          // allow | deny | reject | ask | observed
    "ruleId": null,
    "provenance": "default"     // see 3.2
  },

  "geo": { "country": "US", "lat": 37.7, "lon": -122.4, "asn": 15169, "org": "Google" },
  "bytes": null,                // { "tx": 0, "rx": 0 } when available, see 2.3

  "newNetwork": false,
  "networkKey": "142.250.1.0/24"
}
```

Non-obvious fields:

### 2.1 `app.key` is the exe path

Both OpenSnitch (`connections.process`) and `/proc/<pid>/exe` give the absolute
binary path, so it is the only identity every source can produce. Everything
else in `app` is presentation resolved on top of it, and may be absent.

`system: true` means the process belongs to another uid and no desktop identity
was recoverable without privilege. Those rows are never blockable.

`owner` is sent only by the system daemon (`kub0d --system`, root), for a
process of a logged-in user: a uid at or above `UID_MIN` from `/etc/login.defs`
(1000 when unset; never `nobody`). The system daemon names such a process the
way the user's own daemon would, with that user's `.desktop` files consulted,
and the row says whose it is: `{ "uid": 1000, "name": "alice" }`, the account
from the passwd database (the uid as text when it has no entry). Root's own
processes carry no `owner`; a service account's process is `system: true`. A
user daemon never sends it. Additive.

### 2.2 `app.hash` exists from v0 even though nothing writes it yet

A path-keyed rule is defeated by replacing the binary at that path. Little
Snitch re-prompts when a code signature changes; the Linux equivalent is a
content hash, and OpenSnitch already supports process checksums.

The field is reserved now because it is a **rule subject**, and adding a subject
type later means migrating every rule on every installed machine, on a tier that
cannot be forced to upgrade. Cheap now, expensive in eighteen months.

### 2.3 `bytes` distinguishes measured zero from unknown

Linux procfs `Connection` records now carry optional `bytes: {tx, rx}` from
netlink `sock_diag` / `INET_DIAG_INFO`. They are cumulative TCP acknowledged
upload and received-byte counters at the last observation. Socket ownership is
still attributed through procfs. UDP, other sources, older kernel layouts and
failed dumps remain null; queue depths are never used as transfer counters.

Legacy `Connection` records also carry `exe`, the observed executable path.
It defaults to an empty string when unavailable; `app.id` remains the desktop
identity or process name and must not be interpreted as an executable path.

An additive `bandwidth` frame contains `ts` and `apps` with `id`, `txBytes`,
`rxBytes`, nullable `txRate`/`rxRate`, `measured`, and `tcp`. Rates are bytes per
second over monotonic elapsed time. Session totals count only measured deltas;
the first observation establishes a baseline. Missing samples, changed socket
cookies and counter resets start a new baseline rather than fabricating bytes.
An app rate is null until all its observed TCP sockets have comparable samples.

Legacy `Flow.bytes` remains null for sources without measurements. Connection
history uses a separate `history` response, and never changes live counts. See
[TRAFFIC-HISTORY.md](TRAFFIC-HISTORY.md) for IPC and retention.

Legacy records can also carry `evidence: {source, recordedAt, verdict,
ownerMethod, hash, container}`. Flow projection preserves the source's action,
rule ID and provenance; procfs leaves verdict null because a sampled socket
does not report an enforcement decision. Missing evidence on older records
means unknown. The evidence drawer distinguishes reported fields, inferred
owner clues, IP geolocation and user/fleet annotations.

Optional capture stores `connect-attempt` and `sendmsg-attempt` records only in
retained history, with `evidence.source: ebpf`, calling PID/UID/comm and event
time. They have unknown outcome/lifetime/executable/bytes/verdict and never
enter live counts. The additive `capture-status` frame includes `ts`, `state`,
`detail`, `received`, `emitted`, `kernelDropped`, `collectorDropped`,
`userspaceDropped` and `invalid`. It does not refresh monitoring health.
See [CAPTURE.md](CAPTURE.md) for scope, authorization and fallback.

### 2.4 `state` keeps Live and History from being averaged

OpenSnitch stores one row per unique flow (app + destination + port).
`kub0d` stores sockets currently open. Summing them produces a number that
means nothing, so the UI renders two tabs and this field decides which.

`observed` is for listen mode, where a flow was seen but no verdict applied.

The panel classifies by **deny-listing the finished states** rather than
allow-listing the live ones, because the sources do not share a vocabulary.
`procfs` is the default and emits raw kernel state names, so an allow-list
would have to enumerate every live TCP state correctly and would drop any it
missed — including states a future source invents.

The deny-list has exactly one entry, `closed`, and only `opensnitch` produces
it. `procfs` contributes nothing to History: `sample()` drops `LISTEN`,
`TIME_WAIT` and TCP `CLOSE` before a `Connection` is built, and a TCP
conversation that ends arrives as a `disconnect`, which deletes the row rather
than filing it. Teardown states (`FIN_WAIT1/2`, `CLOSE_WAIT`, `LAST_ACK`,
`CLOSING`) are conversations ending, not ended, and stay live.

> **`CLOSE` was in that list for one commit and had to come out.** The string is
> in `procfs`'s state table, which made it look like a second finished marker.
> It is not: the filter that drops TCP `CLOSE` is TCP-only, and an *unconnected
> UDP socket* — an mDNS listener — has no remote endpoint and so parses as
> `CLOSE` while being perfectly alive. Denying it hid live sockets from the
> pill, the severe direction a deny-list was supposed to be structurally
> incapable of.
>
> The generalisable error: the vocabulary a producer *can* emit is not the
> vocabulary that *reaches* a consumer, and the gap between them is a filter
> several hundred lines away from the assignment you read. It also shows the
> deny-list argument has a precondition worth stating — it only holds while
> every entry is a state that can *only* mean finished.

The same rule governs the map: an arc claims this machine is talking to that
place, so `drawableArcs` excludes history unless a caller opts in. The amber
pulse is governed by it too — the away digest counts backfilled networks on
purpose, but the pulse says "new network" in the present tense and fires on live
rows only.

### 2.5 `local` is nullable

A live socket sampler always knows the local endpoint. A store of past decisions
often does not — it recorded what the connection was *to*, and the ephemeral
source port was never interesting enough to keep. Null says "not observed"; a
zero port would claim a measurement.

Same rule as `bytes`, for the same reason, and the OpenSnitch driver is the
first source to exercise it.

---

## 3. Rule

```jsonc
{
  "schema": 0,
  "id": "01J9X...",
  "subject": { "match": "exe", "value": "/usr/bin/firefox" },   // exe|hash|cgroup|container|any
  "object": {
    "host": "*.googleapis.com",   // any field null = "any"
    "ip": null,                   // accepts CIDR
    "port": 443,
    "proto": "tcp"
  },
  "verdict": "deny",              // allow | deny | reject
  "ttl": { "kind": "forever", "expiresAt": null },
  "provenance": "user",
  "locked": false,
  "createdAt": 1757600000000,
  "createdBy": "alice"
}
```

### 3.1 TTL kinds

| kind | Meaning | Needs |
|---|---|---|
| `once` | this attempt only, see 4.1 | decision cache |
| `untilProcessExit` | while this pid tree lives | exec/exit events |
| `duration` | until `expiresAt` | timer |
| `untilReboot` | cleared on boot | non-persistent store |
| `forever` | persisted | rule file |

`untilProcessExit` is why eBPF matters beyond enforcement: process lifetime
requires exec/exit events, which polling cannot deliver reliably.

### 3.2 `provenance` is the field that makes this sellable

`user` | `ruleList` | `fleetPolicy` | `default` | `external` | `observation`

Neither Little Snitch nor OpenSnitch distinguishes a locally-clicked rule from
a centrally-pushed one. The fleet tier requires exactly that: an admin must be
able to push policy that a local user can see, and that `locked: true` prevents
them from overriding.

Required from v0. The desktop tier only ever writes `user` and `default`, but
the field must already be in every persisted rule when the fleet layer arrives,
or every existing install needs a migration.

**`external` was added when the first source driver landed.** A flow read out of
OpenSnitch's database carries a real verdict that *another engine* reached.
None of the original four values can say that: `default` would claim kub0
decided, and the fleet console would then be auditing a rule it does not own and
cannot produce. A verdict is only as useful as the answer to "who decided", so
"not us" has to be expressible.

Consumers written against the original four must therefore treat an unrecognised
provenance as opaque rather than as an error — which is the ignore-unknown rule
from the preamble, arriving sooner than expected.

---

## 4. Known traps

### 4.1 "Approve once" is the hard one

An application retrying a blocked connection 50 times per second turns the
prompt into a denial of service against the user. `once` therefore requires:

- a decision cache keyed on the 5-tuple with a short TTL, so a retry inside the
  window reuses the answer instead of re-prompting
- prompt-storm coalescing, so N pending asks from one app collapse into one
  dialog

Get this wrong and the product is unusable on day one, regardless of how good
the rest is.

### 4.2 Daemon death: fail open, via an unpinned link (decided)

When the intercept daemon dies while a `cgroup/connect4` program is attached,
traffic flows. A crash degrades to listen mode.

**This was posed as a product decision and is mostly not one.** The kernel
decides it, and what it decides follows from one implementation choice:

| Attach | On loader death |
|---|---|
| `bpf_link`, unpinned | **detaches** — `bpf_link_release()` → `bpf_link_free()` → `ops->release()` |
| `bpf_link`, pinned into bpffs | survives; the pin holds a reference |
| legacy `BPF_PROG_ATTACH` | survives; the cgroup owns the program ref |
| any of the above, cgroup `rmdir` | detaches — `cgroup_bpf_offline()` |

So "fail open" is not a policy the daemon implements. It is what an unpinned
`bpf_link` already does, and it is also what the kernel does with no program
attached at all: `BPF_CGROUP_RUN_SA_PROG` starts at `__ret = 0` and only
consults a filter `if (cgroup_bpf_enabled(atype))`.

kub0 attaches with an **unpinned `bpf_link`** and does not pin the program
either — `bpf_program__pin` keeps a program *loaded*, not *attached*, which is
a distinction worth stating because it looks like it would help and does not.

**The consequence for anyone who later wants fail-closed**, which is the part
that was not obvious and is the reason this section is longer than "we picked
option one": a surviving program cannot consult a dead daemon. Enforcement that
outlives the daemon has to already be in kernel memory, which means the deny
policy has to live in a **pinned BPF map**, and section 3's rule model needs a
kernel-representable projection before any of it can be written. The "fail
closed only for `fleetPolicy` + `locked`" option needs more than a pinned link:
the map itself must carry that distinction, because there is no userspace left
to interpret `provenance`.

That makes the failure mode a *schema* question wearing a runtime question's
clothes. It is recorded here so the fleet tier re-opens section 3 rather than
reaching for a loader flag.

Reversibility is why this is safe to decide now: pinning is a property of how
the link is created, so moving to a surviving attach later is a change in the
loader, not a migration of anything persisted.

Version floors this depends on: `cgroup/connect4` needs 4.17, `cgroup/sendmsg4`
(the QUIC hole, section 1) needs 4.18, `BPF_LINK_CREATE` for cgroups needs 5.7,
and CO-RE against kernel BTF needs 5.2. Cgroup links support only
`BPF_F_ALLOW_MULTI` semantics.

---

## 5. Sources

A source answers one question — "what has happened since last time" — in
`Flow`. Everything above a source is written once.

| Source | Status | State it emits | Verdict |
|---|---|---|---|
| `procfs` | upstream's, unchanged | `live` | none |
| `opensnitch` | **built** | `closed` | `external` |
| `libproc` | **built**, macOS only | `live` | none |
| `ebpf` | next source, not next phase | `live` / `observed` | kub0's own |

`libproc` is the Darwin analogue of `procfs` and holds to the same contract: it
samples, so it contributes nothing to History. It drops `LISTEN` and every
teardown state rather than filing whichever connections happened to die on a
tick boundary, and it does not synthesise a `closed` flow when a socket vanishes
between polls — `closed` stays something only `opensnitch` produces, on every
platform.

Endpoint Security cannot replace it and is not a later upgrade path for it: ESF
has no network-connect event at all (verified against `MacOSX.sdk` on macOS
26.6.2 — of 156 `ES_EVENT_TYPE_*` symbols the only connect events are
`UIPC_{BIND,CONNECT}` and `XPC_CONNECT`). Enforcement on macOS is a
`NEFilterDataProvider` System Extension, which is a separate source and a
separate entitlement. Observation needs neither.

```sh
kub0d --source opensnitch --os-backfill today --emit-flows
```

The driver is strictly read-only against a database another program is actively
writing: a `mode=ro` URI *and* `SQLITE_OPEN_READ_ONLY`, with a test that asserts
a `DELETE` fails. It degrades one field per missing column rather than refusing
to start, since it is reading a foreign schema it does not version.

Enrichment — GeoIP, `networkKey`, `newNetwork` — is **not** the driver's job. It
happens once, above the source, so every future source inherits it and each
driver stays auditable as "does this faithfully read its source".

### 5.1 First-run backfill: `today` (decided)

`--os-backfill none | today | all`. The default is `today`: rows at or after
local midnight, so the History tab opens with context the user recognises and
startup cost is bounded by one day of traffic no matter how old the database is.

The reason this was open rather than obvious is that it looked like it might
also be a *safety* question. Once flows drive prompts (4.1), a backfilled flow
must never be mistaken for a live one, and a large backfill sounded like the way
that goes wrong.

It is not, and the distinction matters for every source that follows: backfilled
rows are separated **structurally**, not by volume. Every row the OpenSnitch
driver emits carries `state: closed` and `verdict.provenance: external`, so a
prompt path keyed on `state: live` cannot see them at all, whether three arrive
or thirty thousand. Having settled that, the choice reduces to startup cost
versus how populated the panel looks on first run, and `today` is the cheap
middle.

> **Correction, same day.** The paragraph above is true of the *producer* and
> was never checked against the one *consumer* that exists. `Flow::to_legacy`
> maps `Closed` to `"CLOSED"` honestly, but `ConnectionModel.js` does not read
> the field, and the daemon's OpenSnitch loop broadcasts `Event::Connect` per
> row and never `Event::Disconnect` — so the panel counts a day of finished
> history as live conversations, under a pill that says "live connections".
>
> The reasoning error is worth keeping because it will recur with every source
> added here: a field that separates two classes of record only separates them
> for code that reads it. "Structurally separated" is a claim about a consumer,
> not about a schema, and it has to be verified per consumer. Until the panel
> keys on `state` (2.4), the honest statement is that backfill is separated for
> the *prompt* path and not for the *display* path.
>
> **Closed.** `ConnectionModel.js` now keys on `state` (2.4). Fixing it turned
> up a *second* consumer nobody had counted: the `tick` heartbeat carried the
> daemon's own tally and assigned it straight to the live count, so a correct
> split was re-broken once a second by a message that changes no connection.
> "Verified per consumer" means enumerating them, not fixing the one that
> prompted the audit.

`none` was rejected because the history is the only thing OpenSnitch's database
has that kub0 does not, so an empty first run defeats the point of reading it.
`all` remains available and is the right flag for a forensic look at an
established install.

### 5.2 Their timestamps have no timezone

OpenSnitch's `time` column is text with no offset, and the clean-room rule
forbids reading their source to find out which one it means. The driver assumes
**local** and `--os-time-utc` flips it.

The assumption is contained: ordering and the incremental cursor compare the raw
text, which sorts correctly either way. A wrong guess misdates a displayed
timestamp and cannot corrupt the read. Whoever first points this at a real
database should confirm it and record the answer here.

---

## 6. Activity (additive)

Local append-only timeline. **Nothing in this stream is sent off the machine.**
The kub0 link is header state plus the `kub0_*` / `heartbeat_*` kinds below.

Wire event, additive on the unix socket. Sent once to each new client **right
after `hello`** with the newest 300 entries (file order: newest last, so the
client receives **ascending `ts`**), then live as a one-entry frame:

```json
{"type":"activity","entries":[{"ts":1757600000000,"kind":"app_first_seen","app":{"id":"firefox","name":"Firefox"},"detail":{}}]}
```

Each line of `$STATE_DIR/activity.ndjson` is one object:

```json
{"ts":1757600000000,"kind":"new_network","app":null,"detail":{"network":"142.250.1.0/24","country":"US"}}
```

`kind` is a **closed enum**. Unknown kinds are rejected. The set is:

`daemon_start` · `source_changed` · `app_first_seen` · `new_network` ·
`unknown_owner` · `block` · `unblock` · `block_failed` · `kub0_connected` ·
`kub0_disconnected` · `heartbeat_ok` · `heartbeat_failed` · `watch_hit` ·
`indicator`

`watch_hit` carries `detail.rule`, `detail.match`, `detail.remote`,
`detail.port`, `detail.hostname`. `indicator` carries `detail.indicator`,
`detail.severity`, `detail.basis`, `detail.attack` (an ATT&CK id or null),
and the same peer fields; it is written for notice and warning indicators on
a new connection, once per (indicator, app, peer address) per daemon run.
See `docs/INTEL.md`.

Heartbeat kinds are written **only on a change of outcome** (ok→failed,
failed→ok, or the first result). They are never written every tick.

Client-originated notes (the UI runs the helper; the daemon only records):

```json
{"cmd":"note","kind":"block","app":{"id":"firefox","name":"Firefox"},"detail":{"mechanism":"cgroup","error":""}}
```

`kind` here is only `block` | `unblock` | `block_failed`. `detail.error` is the
only free-text field and is capped at 200 characters. Anything else is ignored
with one log line.

---

## 6.1 Local intelligence on the legacy record (additive)

Three additive fields on the panel's `Connection` record, all absent when
there is nothing to say (`docs/INTEL.md` has the contract):

```json
{"asn":24940,"org":"Hetzner Online GmbH","indicators":[{"id":"beacon-cadence","severity":"notice","attack":{"id":"T1071","name":"Application Layer Protocol"},"basis":"Firefox reconnects here about every 60s (12 times, 4% jitter). Update checkers, telemetry and command channels all keep a schedule; the schedule alone does not say which."}]}
```

`severity` is `info` | `notice` | `warning`, and `indicators` is sorted
highest first. `attack` is a vocabulary reference, never a verdict. `org` is
the ASN registrant, not the tenant. `evidence.hash` (2.2) is now written:
`sha256:<hex>` of the executable, patched into the row when computed. Two
more additive evidence fields: `evidence.lineage` (`{ancestors:[{pid,comm,
exe}], cmdline, cwd, truncated}`, parent first, at most eight) and
`evidence.package` (the owning distribution package, or `"none"`), the latter
patched in with the hash. `hostnameSource` (additive, absent when there is no
name) says where `hostname` came from: `dns`, the name this user's software
asked for, from the optional collector's DNS-answer programs (the answer
matched to the socket's own query, from a resolver in `/etc/resolv.conf`);
`ptr`, a reverse lookup; `source`, reported by a database source.

Three additive frames, ignored by a panel that does not know them:

```json
{"type":"listeners","ts":1757600000000,"listeners":[{"proto":"tcp","ip":"0.0.0.0","port":22,"app":{"id":"system","name":"system","icon":"","desktop":"","pid":0,"system":true},"exe":"","uid":0,"scope":"all"}]}
{"type":"watchlist","ts":1757600000000,"rules":[{"id":"w-cc24217a","kind":"port","value":"4444","note":"","ts":1757600000000,"hits":0,"last_hit":0}],"error":""}
{"type":"investigate","request":"investigate-1-1","pivot":{"subject":{"kind":"ip","value":"203.0.113.7"},"connections":12,"...":"see intel::Pivot"},"error":""}
{"type":"timeline","request":"timeline-1-1","timeline":{"since":1757500000000,"until":1757586400000,"bucketMs":3600000,"buckets":24,"apps":[{"id":"firefox","name":"Firefox","counts":[0,3,"..."],"total":41}],"otherApps":0,"total":[0,3,"..."],"max":12,"truncated":false},"error":""}
```

`listeners` and `watchlist` are sent in the greeting after `activity` and
before `snapshot`, then on change. `scope` is `all` | `loopback` |
`address`. `watchlist.error` is set when the last change was refused; the
list is then the unchanged one.

Three client commands:

```json
{"cmd":"timeline","request":"timeline-1-1","hours":24}
{"cmd":"watch","action":"set","kind":"asn","value":"AS13335","note":"optional"}
{"cmd":"watch","action":"delete","id":"w-cc24217a"}
{"cmd":"investigate","request":"investigate-1-1","subject":"asn:13335","since":1757500000000}
```

`kind` is `asn` | `country` | `cidr` | `host` | `port` | `app`. `subject` is
`kind:value` with kind one of `ip`, `app`, `asn`, `network`, `country`,
`port`, `host`, or a bare value the daemon classifies; empty means
everything. `since` is clamped to the history retention window.

---

## 7. Fleet (additive)

Org-scoped kub0 snapshot for the Protection tab. **Additive.** Unknown fields
are ignored. The account token never appears on this frame.

Emitted:

- once to each newly connected client **right after `hello`** (last-known
  values; zeros / `unknown` / `null` until a heartbeat has run)
- again after **every** heartbeat attempt (success or failure). Fetch failures
  are logged once per change and are never fatal; last-good `orgEndpoints`,
  `nodeLimit`, `selfState`, and `denylist` are kept.

```json
{"type":"fleet","ts":1757600000000,"connected":true,"orgEndpoints":3,"nodeLimit":10,"selfState":"enforced","lastHeartbeatOk":true,"lastHeartbeatTs":1757599990000,"denylistVersion":7,"denylist":[{"name":"Block curl","comm":"curl","path":"/usr/bin/curl","action":"deny","reason":"org policy"}]}
```

| field | source |
|---|---|
| `connected` | account file present |
| `orgEndpoints` | `GET {server_url}/api/nodes` → `count` |
| `nodeLimit` | same → `node_limit` |
| `selfState` | that list's row whose `node_name` matches this host: `enforced` \| `monitored` \| `down`. Missing row → `unknown` |
| `lastHeartbeatOk` | last `POST /ingest/heartbeat` outcome; `null` until attempted |
| `lastHeartbeatTs` | unix ms of that attempt; `0` until attempted |
| `denylistVersion` | `GET {server_url}/api/enforce/denylist` → `version` |
| `denylist` | same → `entries`, capped at 500. Each row carries `name`, `comm`, `path`, `action`, `reason`. `name` is the API's `name`, `title` or `label`, else the daemon's own sentence for the rule ("Block curl"), so it is never empty for a rule with a matcher. Other API fields (`namespace_scope`, `promoted_by`, `created_at`) are ignored |

The rows above are what the panel shows. `comm` and path rules are not
enforced by kub0d. The exec gate below enforces only sha256 sample keys, and
only when it is switched on.

### Exec gate

The system daemon (`--system`) can refuse an execution whose bytes are on the
org deny list. It is off unless the process environment is `KUB0_EXEC_GATE=1`.
User mode ignores that variable and does not log it. A row contributes a key
only when its `path` basename is 64 hex characters (the sample sha256, either
case) and its `action` is `block`. A row whose `comm` is a critical system
binary contributes nothing. Those binaries are resolved from `/usr/bin`,
`/usr/sbin`, `/bin`, `/sbin`, `/usr/local/bin`, `/usr/local/sbin`,
`/usr/lib/systemd`, `/usr/lib/kub0`, and `/usr/libexec` (and the same paths
under pid 1's root). Each is recorded with the size, mtime, and ctime observed
at start. An allow-set hit skips the content check only while that signature
still matches; once the inode's bytes may have changed, the event is hashed
like any other file.

The allow-set compares size, mtime and ctime recorded at start, so a writer
that already holds a dirty shared mapping of a critical binary when the daemon
starts is not detected. The allow-set exists so that a bad deny row naming a
critical binary cannot stop the system, not as a tamper check.

A local file, `KUB0_EXEC_GATE_DENY_FILE`
(one digest per line, `#` comments allowed), is read at start, re-read every
60 seconds, and unioned in. A file that contains at least one digest arms the
gate on its own, which is how a root self-test blocks a sample without kub0.
The org list is the one source kept on disk. Each list the kub0 API returns
is written to `org-list.json` in the gate's directory (rows that carry a key
only, the account they arrived under, and the time; mode 0600), and a new
process loads it for the same account before its first sync, so it does not
start by allowing every exec until the network is up. A copy saved under
another account, in another schema, or over 500 rows is removed, not loaded,
and a logout removes it. A change of account takes the previous account's
keys out at once, without waiting for the new account's first list. A list
that fails to save removes the older copy. Only a list the API returned
replaces the keys: a failed fetch hands the gate nothing, and neither does a
200 whose body has no `entries` field (`"entries": null` is an empty list). The gate frame says which it is on:
`listReceivedAt` is when the API last returned the list behind the keys (ms
since the epoch, `0` while no org list is held), and `listRestored` is true
while the keys are still the saved copy's. The fleet frame's `denylist` stays
capped at 500 rows for the panel. The gate counts the org list before that cap. More than 500 rows
keeps the key set already installed and does not arm the gate or log a key
change.

Fail-open. A file larger than `KUB0_EXEC_GATE_CAP_KIB` (default 65536 KiB;
`0` disables the cap) is allowed without hashing. Any read error allows. An
event stays in the in-flight map until it is answered. The worker duplicates
the event fd and decides on that duplicate, hash included, so the original
stays answerable the whole time. The first answer wins. The watchdog allows
and closes any event still unanswered after 3 seconds, even while a worker is
still reading the duplicate, and the worker's later verdict is discarded. A
digest read from the duplicate may still fill the cache, because it is the
same open file. If the worker queue is full, the reader allows that event at
once and counts `overflow`. If `fanotify_init` fails, or no superblock can be
marked, the daemon logs `exec gate NOT loaded` and keeps running. If the event
read fails, the group fd is closed and the kernel allows every pending and
future exec. Shutdown sets a closing flag, joins the reader, the mount rescan,
and the watchdog (the watchdog allows what it still holds first), then closes
the group fd under its lock and closes the worker queue. The log line
`exec gate: stopped` is written once. A worker blocked in a read is not
joined; after shutdown its answer finds the group closed and writes nothing.
Stopping the process closes the group fd too, and the kernel then allows every
exec that was waiting. A path is never logged or sent next to a digest. A
response write is retried on `EINTR`. Any other failure or a short write
counts `error` once and logs one debug line, and the event fd is still closed.
After the group fd is closed a response writes nothing and counts nothing.

The fleet frame carries an additive object `execGate`. An older frame omits
it (`#[serde(default)]`). It is local telemetry and is not on the kub0
heartbeat.

```json
"execGate":{"on":false,"marks":0,"uncovered":0,"hashed":0,"cacheHit":0,"allowlisted":0,"overCap":0,"error":0,"deadline":0,"overflow":0,"hitBlock":0,"keys":0}
```

| field | meaning |
|---|---|
| `on` | a deny list has been installed at least once (a fleet publish of at most 500 rows, or a non-empty local deny file). A longer fleet list does not arm the gate |
| `marks` | superblocks marked |
| `uncovered` | markable superblocks whose mark failed |
| `hashed` | execs whose bytes were hashed from the event fd |
| `cacheHit` | a digest reused because size, mtime and ctime were unchanged |
| `allowlisted` | a critical binary whose size, mtime, and ctime still match the signature recorded at start, allowed without hashing |
| `overCap` | allowed without hashing because of the size cap |
| `error` | allowed because the file could not be read |
| `deadline` | allowed because the answer was older than 3 seconds |
| `overflow` | allowed by the reader because the worker queue was full |
| `hitBlock` | refused because the sha256 was in the key set |
| `keys` | digests currently refused |



Three more additive fields on `fleet`: `prevalence`
(`[{networkKey, nodes, firstSeen}]`, how many other org endpoints reached a
destination network, merged across heartbeats), `prevalenceSupported`
(`null` until a heartbeat succeeded, `false` when the server's response had
no `prevalence` key), and `sharingDestinations` (sharing is on for this daemon: started with
`--share-destinations`, or on the system daemon switched on with
`kub0 share on`; the frame is sent again when it changes). The heartbeat request gains `dest_networks`, the
network keys of public destinations first reached since the last successful
heartbeat, empty unless sharing is on. See `docs/INTEL.md`, "Where kub0
fits".

Darwin defaults to `libproc` unless `--source` is explicit. Its read-only
flows use action `observed` and provenance `observation`, preserved in legacy
evidence. This additive provenance makes no allow/deny decision. Linux keeps
its procfs default; other sources retain their existing provenance.
