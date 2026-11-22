# Optional read-only system protection visibility

This unit supplies source code, not deployment. It does not install or enable a
service, create groups, change group membership, or modify a live firewall.
User monitoring, per-app helper readiness, and root system policy diagnostics
remain independent. The settings surface provides no privileged system action.

`kub0 install` and `scripts/install-privileged.sh` create the local
`kub0` group when it is absent (`groupadd --system`) and restart a
running daemon so it can resolve it. `sudo kub0 install` also adds the user
who ran sudo (`SUDO_USER`, never root) to it, with `gpasswd -a`, else
`usermod -aG`; `scripts/install-privileged.sh` adds nobody. An administrator
opts any other member in using their site's account-management procedure. A
fresh login is needed for supplementary group membership. `kub0 doctor`
reports the group missing from `/etc/group`, and what membership gives.
<!-- rename-compat: the 0.4.x names, on purpose; the parity test skips this region -->
The group was `vallum-status` before the rename. `kub0 install` renames it in
place (`groupmod -n`, same GID and members) and refuses, changing nothing,
while a `kub0` group exists beside it. For one release the daemon still
resolves `vallum-status` when `kub0` is absent (it says so once); when both
exist it uses neither, so a `kub0` group that was there first is never handed
the command socket. Either name is used only when it is a system group (GID
within `/etc/login.defs`' `SYS_GID_MIN`..`SYS_GID_MAX`, 1-999 without one)
that no `/etc/passwd` account has as its primary group; `kub0 install`
refuses to keep or rename a group that is not. The sockets moved from
`/run/vallum` to `/run/kub0`.
<!-- /rename-compat -->
The daemon resolves only the pre-existing entry in a bounded, root-owned,
non-writable `/etc/group` (and reads `/etc/passwd` and, when present,
`/etc/login.defs` under the same checks, for the system-group rule above); it
never invokes NSS or network group lookup. Missing
or invalid groups disable diagnostics with a stderr diagnostic, and leave the
command socket root:root 0660 (logged once), while command monitoring and
policy enforcement continue. There is no unsafe permission fallback. The
status GID must be nonzero (GID0 is the command socket's root-only fallback)
and must not be shared by another local group name. Every nonempty,
non-comment local row must have exactly four colon-separated fields, a nonempty
name (no comma or leading `+`/`-`), no whitespace/control characters, and an
ASCII-decimal GID in the u32 range. Leading-zero GIDs are compared numerically.
Blank rows and comment indentation recognize only ASCII space, tab, LF, CR, form
feed and vertical tab. Unicode text after an ASCII `#` comment marker is ignored;
Unicode whitespace before that marker is validated and rejected. CRLF row
delimiters remain supported. Any malformed
row, even an unrelated alias, makes diagnostics nonfatally unavailable; this
strict local format deliberately does not emulate libc/NSS permissiveness.
A missing/denied/untrusted/stale/malformed response means unavailable.

The system service still runs with its existing root identity. No service
`Group=`, supplementary-group directive, setgid directory, setuid/setgid
executable, or world-writable socket is added. The runtime directory can become
root:kub0 0750; only root can change its entries. Its independent
`kub0-status.sock` is root:kub0 0660, verified using pathname metadata
following filesystem `lchown`/chmod operations. The command socket
`kub0.sock` is root:kub0 0660 too when the group resolves, and
root:root 0660 when it does not (or when the kernel refuses the group). It is
set before diagnostic setup and checked again after it, against the group
chosen: a wrong owner, group or mode stops the daemon rather than serve a
socket it did not mean to. A member reaches the command socket only through
the runtime directory, which diagnostic setup gives the group.

What a member may do there is decided per request from the peer's uid
(`SO_PEERCRED`), not from the socket mode: `daemon/src/control.rs` lets a
non-root peer read and raise protection, and keeps every verb that removes or
weakens enforcement (`unblock`, `unblock-dest`, `trust`, `allow-once`, `pause`,
`teardown`, `logout`, `policy-snooze`) to uid 0, with `login` (which org the
host enforces is an admin's decision). A `block` request that carries
addresses (`block-ips`) is root's too, checked on its arguments: an address
block applies to every process on the host, and the helper's floor spares only
nameservers and gateways, so a member could cut the daemon off from the kub0
server. An app block without addresses stays the group's. Mutating legacy
lines (no `req`:
`netpolicy-snooze`, `netpolicy-resume`, `watch`, `tag`, `note`) carry no access
class, so the system daemon takes them from root only and tells any other
client to update the panel; read-only legacy lines are unchanged. Reader group
members still cannot use the diagnostic transport as a command relay: it
answers `status\n` and nothing else.

The reads `kub0` and the panel make (`apps`, `conns`, `activity`, `history`,
`intel`, `investigate`, `policies`, `watches`, `brief`, with the older
`status`, `whoami`, `rules`, `endpoints`, `trusts`, `blocks`) are `Read` verbs:
anyone who can connect may make them, as anyone who can connect already gets
the greeting snapshot and the live stream of every row. They add no access a
member did not have; they answer from the daemon's own state. On the system
daemon a row names its owner, and `apps --mine` keeps the caller's own.

Some state is per daemon, and lives where it does something: network-policy
snoozes are the system daemon's, since only it enforces (a snooze on a user
daemon only quiets that daemon's alerts); a tag and a watch rule go to the
daemon the panel reads. Where the system daemon can be used that is the system
daemon, for the panel and for `kub0` alike (one daemon, #61): a name is on its
rows and on its heartbeat to the org, and its watch rules are the list both
show. A panel that runs its own daemon (capture on, or no usable system daemon)
keeps its watch rules there and sends a name to both; `kub0 --user` reaches
that daemon. On its own daemon the panel still reads its account card and
policy list from the system daemon (`status`, `policies`, `rules`) over its
request-only connection when that is reachable.

The only CLI is `/usr/lib/kub0/kub0d system-status`, matching the systemd
ExecStart installation path. It accepts no additional arguments, path override,
or environment override. It checks protected root-owned, non-symlink socket
ancestors, the socket inode, and the local authorization group, and authenticates
an actual Linux root peer with SO_PEERCRED. Darwin reports diagnostics unavailable.
The UI does not trust PATH, the checkout daemon, user flow JSON, or helper JSON.
A fixed OS Python interpreter checks installed CLI and all ancestors with lstat
before exec; the Quickshell Process clears its inherited environment, uses -I/-S,
and supplies only LANG/LC_ALL. The native child gets that same minimal environment.
The CLI must be a root-owned regular executable, without setuid/setgid or group/
other write permission, beneath protected root-owned non-symlink directories.

The wire protocol is exactly `status\n` followed by write EOF. The separate
handler requires the full request through EOF, rejects other input, caps input
at 128 bytes and output at 4096 bytes, and uses an absolute 750ms work deadline.
One worker and backlog eight bound reader concurrency; no reader spawns a thread
or touches the heartbeat/event loop. The snapshot reads only small metadata,
not policy rows, accounts, flow lists, endpoints, executable lists or denylists.
The client uses nonblocking local connect (full backlog fails immediately), root
peer authentication, deadline-bounded reads through EOF, and strict serde fields.
It rejects overflow, truncation, duplicate/unknown/missing keys and stale fields.
The UI uses one Process, a two-second timeout and generation guards; it rejects
any nonzero/timeout child outcome and preserves previous evidence with its age.

`observed_at` observes this in-memory response, not nft rules or policy freshness.
`policy_refresh_ok` is the last reported refresh result, with no invented refresh
time. Late account replacement/removal retires diagnostic metadata independently
of enforcement: a between-heartbeat replan still retries a failed clear but cannot
republish the retired account as known. A valid next account check/adoption or an
observed no-account disconnect resets that retirement. `policy_known` tracks whether the current account has a policy answer.
Initial startup without an account has no heartbeat producer or policy answer,
so it conservatively reports false. A running heartbeat that observes account
removal records that no account requires policy; clear failures remain visible
in enforcement state and retain the last apply acknowledgement. `reported_last_applied_at` is the last daemon helper
apply acknowledgement. A refresh failure may retain a same-account plan and
does not establish that kernel enforcement stopped. An unanswered account can
retain unknown kernel state. `current_kernel_verification` is always `unknown`:
this surface makes no claim about complete kernel contents, plan hash equality,
rule-presence or pause observation. No policy identifier/version is invented.
The producer version is the actual Cargo package version.

Diagnostics setup runs once in common server initialization, including the
default procfs system source and the other live sources. User mode never starts
the producer. Optional setup failure is nonfatal for supported command paths;
`--socket /run/kub0/kub0-status.sock` and effective dot/parent, relative or
parent-symlink aliases are rejected before unlink, bind or diagnostic setup.
The root effective GID is unchanged and command ownership/mode is rechecked.

Service keeps its clock in full-width epoch milliseconds. Current evidence
expires at elapsed age greater than 5000ms (including 5001ms); seconds are only
for display. Its clock dependency invalidates the binding on each health tick.
Invalid/nonfinite clocks report unavailable. Failed, nonzero and timeout outcomes
retain the last response and apply acknowledgement with their growing ages.

## Verification

Run from the clone:

```
cargo test -p vallumd --offline system_status -- --test-threads=1
cargo test -p vallumd --offline --bin kub0d diagnostics -- --test-threads=1
cargo test -p vallumd --offline --bin kub0d reserved_command_path -- --test-threads=1
node tests/test_system_status.js
node tests/test_system_status_provenance.js
unshare --user --map-root-user node tests/test_system_status_provenance.js
python3 tests/test_system_status_loader.py
python3 tests/test_system_status_service.py
qmllint Service.qml Panel.qml
```

The loader test compiles a private LD_PRELOAD constructor canary. A positive
Python control actually loads it; the real Quickshell Process with
clearEnvironment must neither inherit the variable nor execute the constructor.
All fixtures live beneath private temporary directories; none touches /run/kub0,
live account/preferences/firewall state or the installed service.

Where no sandbox blocks socket operations, run the ignored private
UID/GID fixture with a mapped namespace (the test binary path is printed by
`cargo test -p vallumd --lib --no-run`):

```
cargo test -p vallumd --offline --lib --no-run --message-format=json > /tmp/vallum-lib-tests.json
vallum_lib_test=$(python3 -c 'import json; print(next(x["executable"] for x in map(json.loads, open("/tmp/vallum-lib-tests.json")) if x.get("reason")=="compiler-artifact" and x.get("target",{}).get("kind")==["lib"] and x.get("executable")))')
unshare --user --map-root-user --map-auto "$vallum_lib_test" --exact system_status::tests::namespace_authorization_fixture --ignored --nocapture
```

That fixture checks root-owned protected fixture metadata, an authorized
non-root group reader with actual root SO_PEERCRED, unauthorized traversal,
command-socket denial, and a real non-root peer rejection. The private test
ancestry boundary stops at the fixture directory to avoid treating world-writable
/tmp as a production trusted ancestor. Production always validates through `/`
and exposes no override. Namespace UID0 is not proof of an installed host-root
service. The child probe test is only invoked by the parent fixture. The single-ID
namespace provenance test also uses a private ancestry boundary for its positive
control; it checks a root-owned executable fixture, writable executable/ancestor
rejection and symlink rejection before execution. The full-root-path production
bootstrap remains fixed.

In a sandbox that refuses Unix socket writes, pathname bind or `SO_PEERCRED`
(a Landlock build sandbox, some containers) the socket tests fail with `EPERM`
rather than skipping. That is a run that did not happen, not a result: run
them on a host that allows it.
