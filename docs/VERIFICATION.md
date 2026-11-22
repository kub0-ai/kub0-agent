# What has been verified

What was proven on a real machine and when, and what was not. Dates are the
day of the run; a claim here is about the build that existed then.

`./tests/run.sh` runs the Rust, Node and Qt6 regression suites, `kub0d --self-test`,
local TCP/history/restart checks and optional-capture fallback. The OpenSnitch driver has additionally been exercised end
to end against a synthetic database, confirming backfill, geo enrichment, and
delivery of a row inserted while a client was attached.

The offscreen Service harness exercises refused and missing initial sockets,
listener rebind in the same daemon, daemon restart, bounded missing-listener
retries, and demo/destruction cleanup. It runs the real `Service.qml` in
a private child mount/network namespace with the canonical helper masked by
a refusing fixture, private HOME/XDG directories, and schema-valid preferences.
Extracted-function tests and component loading alone do not prove recovery,
and a host that refuses the namespace setup has not run this harness at all.
It passed natively on 2026-10-07: the refused and missing-listener cases, the
same-daemon rebind, the restart and the demo matrix, with current snapshots
throughout, subscriptions replayed and loaded preferences unchanged, and
again on 2026-11-20 against 0.5.0.

**Shell integration is verified, as of 2026-09-14 on Omarchy 4.0.0.alpha.** The
plugin installs, is discovered and validated by `PluginRegistry`, enables into
the bar, and the shell mounts its `service` entry point and spawns the daemon
itself. `omarchy-shell ai.kub0.agent status ''` answered `"daemon":
"connected"`, `"fallback": false`, 34 live connections—real `/proc` data, not
the replay fixture. The shell's log is clean of warnings for this plugin.

That run is also what caught the one defect this claim is worth having: a
`liveBar ? liveBar.foreground : …` binding assigned `undefined` to a `QColor`
on every panel load that did not arrive through the bar widget, because the
shell hands a third-party panel two different facades and only one of them has
colours. At the time nothing in the suite executed QML, so nothing in the suite
could have found it; the Qt6 QML tests under `tests/` came later and still prove
only that the files load and bind (see Dev in the README).

The privileged helper is installed and reports ready, as of the same date.
`scripts/install-privileged.sh` placed the helper and the polkit action
(under their pre-rename names), after which the helper's `status` returned `"blockingReady":
true` with `nft`, `conntrack`, and `cgroupv2` all true, and the plugin's own
`status` flipped to `"helper": true, "blocking": true, "needsHelper": false`.

**Panel rendering:** `tests/qml/verify-panel.py` loads the actual Apps, History,
evidence drawer and Settings components on a private headless Wayland display,
checks warnings, and captures screenshots for visual review. Fixtures do not
prove privileged operations on the live desktop. An authenticated isolated run
on 2026-10-04 verified timed-rule migration, cancellation, kernel expiry and
membership restoration, plus IPv4/IPv6 TCP and unconnected UDP capture, UID
filtering, backpressure reporting and detachment on kernel 7.2.5-4-omarchy.
That report applies to the helper and collector as built that day. See
[`CAPTURE.md`](CAPTURE.md) and `tests/verify-root-enhancements.sh`.

**Blocking is verified end to end, as of 2026-09-15.** A disposable probe
looping HTTPS requests was blocked by PID: the helper returned
`"verified": true` having moved a six-process forest into
`vallum.slice/vallum-<app>`, installed
`socket cgroupv2 level 2 "..." drop` on `table inet vallum`, and the probe's
requests went from succeeding to failing. Unblocking restored them, teardown
removed the table, and the seven unrelated nftables tables on the box were
untouched. This is the one claim in this section that took a real packet to
earn.

That run also found two defects on the *cleanup* path, both now fixed, and
both invisible to every test in this repo:

- `unblock-app` reported failure on a successful unblock. Blocking moves a
  process out of its cgroup, and where that cgroup is a systemd *transient*
  scope, emptying it is what makes systemd garbage collect it. The recorded
  restore target was therefore gone by unblock time, the write failed, and the
  processes were left inside `vallum.slice`—which in turn is why teardown could
  not remove it. Restore now falls back to the nearest surviving ancestor.
- `teardown` called `rmdir` on every entry in the cgroup directory, including
  roughly ninety control files that can only ever answer `ENOTDIR`. The one
  real error was buried in the noise.

**Still not verified:** blocking by a route other than PID (the endpoint
fallback, `block-ips`), and recovery when cgroup migration is refused outright.

## Policy status evidence

The Settings panel keeps policy errors visible even when no current policies are
listed. A failed refresh may retain a known same-account applied plan. After a
restart or account change, rules left in the kernel are unverified; an error or
`enforcing: false` does not establish that those rules are absent. Missing or
legacy status remains unknown. Reconnecting clears the panel's previous policy
evidence until the daemon reports current evidence.

The hello `mode` describes this daemon connection, separately from the tenant
account and the per-app privileged helper. It is `system` when the panel reads the
system daemon and `user` when it reads the daemon it started itself, whose fleet
frames provide no live root-system visibility. Legacy hello frames without a
mode do not establish a role.

Policy `hits` and `blocked` count observed new connection matches; `blocked`
means a match to the known applied block plan, not an nft packet-drop measurement.
`appliedTs` remains the successful fleet-sync acknowledgement time. The panel does
not infer receive, revalidation or kernel observation times from refresh/hello
frames; those observations remain unavailable. No durable policy cache is added.

The actual-Panel policy fixture is part of `tests/qml/run-runtime.sh`. It needs
the isolated native QML environment; a namespace or socket refusal is a run that
did not happen, not a passing result.

The endpoint view uses one one-shot clock timer, scheduled by
`Endpoints.nextTransitionDelay` at the earliest recognized row transition:
future skew reaching the 60-second tolerance, or age reaching exactly 600000 ms.
Ordinary age updates remain bounded to a ten-second cadence. Unsupported,
explicitly down, expired, and invalid reports do not create rapid retries.
Native QML Timer delivery follows animation frames (typically about 16 ms);
this is not a real-time millisecond guarantee.

The endpoint fixture keeps its deterministic inventory date and count checks
and adds an actual view seeded 1.5 seconds before expiry using real
`Date.now()`. It observes Online before the deadline and requires Offline within
one second afterward, without assigning the live view's clock. On 2026-10-07
the row went Offline 151 ms after its deadline; the same fixture failed
against the previous ten-second view clock, which expired late.
