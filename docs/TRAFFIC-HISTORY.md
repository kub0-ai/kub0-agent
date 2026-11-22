# TCP bandwidth and local connection history

The Linux procfs sampler measures TCP acknowledged upload and received bytes
through `sock_diag`/`INET_DIAG_INFO`. It checks the inode and both endpoints
against the sampled socket; a raced or unavailable measurement stays unknown.
The netlink decoder validates message lengths, sequence, dump completion and
the returned `tcp_info` length. Each family has a 100 ms timeout. Unsupported
sources and UDP have no transfer measurement. Traffic stays local.

Apps displays bytes per second and totals measured during this daemon session,
and offers a **Bandwidth** sort. Totals count differences between successful
samples, not pre-existing socket counters. A first sample, missing measurement,
new socket cookie or decreased counter establishes a new baseline. App rates
are unknown if any observed TCP socket lacks a comparable measurement. Rates
use a monotonic clock and are hidden when monitoring is stale. Upload measures
acknowledged TCP payload; these are not wire-byte or retransmission counters.

## Local history

The separate History view records Linux procfs observations, including UDP
with unknown transfer. It does not merge them into Live or reinterpret
OpenSnitch decision history. The database contains connection identity,
endpoints, names and evidence already emitted by the daemon, first/last
observed times, and measured transfer between samples. Connections entirely
between polls are still missed. Passive battery mode still uses the existing
cadence, so short-lived connections can be absent from history.

Rows are checkpointed every five seconds, and immediately before a history
query. Abrupt termination can lose observations since the last checkpoint.
Restart marks previous session rows as no longer observed without changing
their last observation timestamps. A socket disappearing means it was absent
from the next sample; the timestamps do not claim its exact open/close time.

A checkpoint writes a row's record only when the row is new, changes, or is
no longer observed. A row present in a sample was observed at that sample's
time, so an active row whose content did not change is not rewritten: one
checkpoint record holds the latest sample time, and an active row's last
observation (and its procfs evidence timestamp, which is the sample time) is
read from it. Transfer counters of active rows are checkpointed every five
seconds too, into a narrow table of the active rows only, so a busy connection
does not rewrite its record. Restart folds the last committed time and
counters into the previous session's rows before marking them no longer
observed, so the values a query returns are the same as when every row was
rewritten. The store uses SQLite's write-ahead log with `synchronous=NORMAL`:
power loss can drop the last commits, never corrupt the file.

Retention is seven days, capped at 10,000 newest observations. Rows past the
cap are trimmed in batches once 256 have accumulated, so the file can briefly
hold that many more; queries and exports return only the newest 10,000. SQLite page
allocation is limited to 64 MiB; the write-ahead log can add up to about 4 MiB
of disk usage while the daemon runs. The database, its `-wal` and `-shm`
companions and the writer lease are private 0600 files. Unsafe directories, symlinks,
public database files and concurrent daemon writers are refused. A storage
failure appears in History while monitoring continues. Read-only CLI exports
do not take the writer lease or alter observation state.

## IPC

`bandwidth` is an additive event:

```json
{"type":"bandwidth","ts":1757600000000,"apps":[{"id":"/usr/bin/probe","txBytes":1024,"rxBytes":2048,"txRate":512.0,"rxRate":1024.0,"measured":1,"tcp":1}]}
```

It updates transfer display and ordering, and does not establish snapshot
freshness or change live counts. Old clients may ignore it.

Clients query retained observations with a correlation token and a literal
substring search over app name, executable, remote IP/port, hostname, country,
protocol and PID. `since` is an inclusive epoch-millisecond lower bound,
clamped to retention. Query text is limited to 256 UTF-8 bytes.

```json
{"cmd":"history","request":"history-1","query":"probe","since":1757596400000}
```

The response has `type: "history"`, the same `request`, `entries`, `more`,
`error`, `retentionDays: 7` and `rowCap: 10000`. Each entry has `key`,
`firstObserved`, `lastObserved`, `active` (present in the latest checkpoint),
`connection` and nullable `bytes` (sampled differences). Results are newest
first, limited to 200 matching observations. `more` tells the UI to narrow its
search. Only matching correlation tokens are applied. The panel supports
one-hour, 24-hour and seven-day queries and copies the shown results as CSV.

`kub0 history --csv` exports retained matches from the running daemon, up to
2,000 per reply (`more` says when there were more); `--query`, `--hours`
(1–168) and `--ndjson` are supported. (The daemon's own `history` verb is retired.)
Unknown transfers export as blank fields. CSV escapes quotes and prefixes
formula-like cells so a process or hostname cannot become a spreadsheet formula.

## Verification

`tests/run.sh` exercises the decoder, rate aggregation and missing samples,
cookie/counter resets, retention, persistence, symlink refusal, CSV handling,
model compatibility, and real loopback TCP counters. Its isolated daemon probe
verifies IPC delivery, connection disappearance, restart preservation, and
read-only CSV export, with external PTR lookups disabled (`KUB0_NO_PTR=1`;
lookups are in-process, so a `getent` PATH shim no longer stops them).

`tests/qml/traffic-history-preview.qml` exercises the actual History component's
search field and CSV button. `tests/qml/verify-panel.py` renders the actual
Apps and History panels on a private headless Sway display using fixtures.
The live shell and firewall are not modified by these tests.
