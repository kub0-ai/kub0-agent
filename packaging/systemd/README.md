# kub0d systemd unit

`sudo kub0 install` installs everything below idempotently (daemon, unit,
helper, polkit policy, geo databases when present, the exec gate's state
directory, the `kub0` CLI, the `kub0` group) and enables the units, from the
directory the binaries sit in (see "The `kub0` CLI" in the README);
`scripts/install-privileged.sh` runs it for the Omarchy plugin. On a 0.4.x
host it also does the rename (README, "Upgrading from 0.4.4"). By hand, on a
fresh host:

    getent group kub0 >/dev/null || sudo groupadd --system kub0
    sudo install -D -m0755 bin/kub0d /usr/lib/kub0/kub0d
    sudo install -D -m0755 bin/kub0-block /usr/lib/kub0/kub0-block
    sudo install -D -m0644 -t /usr/share/kub0/geoip data/geoip/dbip-country-lite.mmdb \
      data/geoip/dbip-asn-lite.mmdb data/geoip/ATTRIBUTION.txt
    sudo cp packaging/systemd/kub0d.service packaging/systemd/kub0-expiry.* /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now kub0d kub0-expiry.timer

<!-- rename-compat: the 0.4.x names, on purpose; the parity test skips this region -->
`kub0d.service` has one name: the `Alias=vallumd.service` that 0.4.5 and
0.4.6 carried is gone (remove a leftover `/etc/systemd/system/vallumd.service`
link by hand, or let `kub0 install` do it).
Its `ExecStartPre=+/usr/lib/kub0/kub0d migrate-state` runs outside the
sandbox and moves a 0.4.x `/var/lib/vallum` to `/var/lib/kub0` (one
`rename(2)`, never a copy) before the daemon starts; it has no
`StateDirectory=`, which would create `/var/lib/kub0` ahead of that move.
`RuntimeDirectory=kub0 vallum` makes `/run/kub0` for the sockets and, for one
release, `/run/vallum`, where the daemon keeps only a symlink to the command
socket under its old name.
<!-- /rename-compat -->

`--system` uses `/run/kub0/kub0.sock` (0660), `/var/lib/kub0/daemon` (0700,
root's alone; who reads what under `/var/lib/kub0` is a table in
`SECURITY.md`) and `/usr/share/kub0`. Without the ASN database, or without the country database while
a country block rule applies, it applies no new org block rules and leaves any
already in the kernel. It reads both once, at start or at its first country rule, so
after installing a missing one restart it: `sudo systemctl restart kub0d`. The
panel reads the per-user daemon, not this one: the system kub0d's errors are in
`journalctl -u kub0d`, and its state is the fleet frame's `netpolicyEnforcement`
and `netpolicyRefreshOk` on `/run/kub0/kub0.sock`.
The Omarchy plugin's per-user daemon is unaffected without `--system`.

When kub0 cannot be reached, or rejects the token (401/403), the system kub0d
keeps enforcing the last policy it received. To take a host out of its org's policy,
disconnect it locally with `sudo kub0 logout`; the
running service clears its rules on its next heartbeat, and the exec gate drops the
org's keys and goes idle at the same time.

That last policy lives in memory only. A restart while kub0 is unreachable leaves
whatever rules are already in the kernel but cannot put back any that are gone, and
nftables does not keep them across a reboot: a host rebooted during an outage
enforces no org block rules until kub0 answers again.

## Exec gate

The system unit is the only place the exec content gate runs, and it runs by
default: the unit sets `Environment=KUB0_EXEC_GATE=1` explicitly, and setting it
to `0` turns the gate off. The per-user daemon never reads the variable (fanotify
permission events need CAP_SYS_ADMIN).

At start the gate opens its fanotify group. It marks no filesystem and hashes
nothing until it holds a non-empty key set: the org deny list (every heartbeat,
and live over `/detonate/api/events/stream`), or `KUB0_EXEC_GATE_DENY_FILE`, an
optional local file of sha256 digests, one per line, unioned with the org list.
It then logs `exec gate ON: N keys`. When the key set empties again (a local
disconnect, an org list that went to zero) it flushes its marks and logs
`exec gate idle`.

The gate does not wait for the network to hold the org's keys. Every list the
kub0 API returns is also written to `/var/lib/kub0/execgate/org-list.json`
(mode 0600; it names the account), and the next start loads it for the same
account: `exec gate: N key(s) from the org list saved 3h 12m ago; the first
sync replaces it`, then `exec gate ON: N keys`. So a restart, or a boot, while
the API cannot be reached leaves the gate armed with the list as of its last
sync, and `kub0 status` and `kub0 doctor` say how old that is until a sync
replaces it. Only a list the API returned replaces the keys; a failed fetch,
or a 200 that carries no `entries`, changes nothing. The list belongs to the
account it arrived under: `kub0 logout` removes the file with the keys, a
login as another account (or on another server) takes the previous account's
keys out at once, and a file saved under another account is removed, not
loaded. A list that could not be written takes the older file with it, so a
restart never loads a list the org has since changed. With no saved list (a
first start, or after a logout) the log line is `exec gate loaded, idle until
the first deny-list sync`, and `kub0 doctor` warns that the gate has no org
list in use.

Every match is logged with its path and decision (`BLOCKED`, `allowed once`,
`allowed (trusted here)`, `NOT blocked (fail-open)`), kept in a ring for the
panel, and written to `/var/lib/kub0/execgate/state.json`, which the per-user
daemon mirrors into its fleet frame so the panel and the desktop notification
can show it. That directory is `root:kub0`, mode 2750, and the file 0640: a
per-user daemon mirrors it only in a session that is in the `kub0` group. In
one that is not (an account never added, or a session begun before it was)
the mirror reads nothing and the panel shows no exec gate until the next
login. The owner's answers come back through the polkit helper
(`kub0-block execgate-trust|execgate-allow-once|execgate-untrust <sha256>`),
which appends to `/var/lib/kub0/execgate/requests.ndjson`; the daemon applies
each request within a second and keeps `trusted.json` and `allow-once.json`
there. A trusted digest is subtracted from the key set on every refresh, and
from the saved org list at start; a one-shot allow lets the next exec of that
digest through and expires after five minutes. Nothing in that directory is
sent to kub0.

Stopping the unit closes the fanotify group fd, and the kernel then allows every
exec that was waiting and every exec after that.

`sudo bash tests/execgate-selftest.sh` proves that gate on a root Linux host with no kub0 server: it builds kub0d, starts it in system mode, and keys it only from `KUB0_EXEC_GATE_DENY_FILE`. A sample whose sha256 is listed must be refused, the same bytes under another name must be refused, one extra byte must run and print the sentinel, and the original sample must run again after the daemon exits. It needs root. On the way out, including after a failure, it kills the daemon it started and removes the temporary directory and the private state directory it created.
