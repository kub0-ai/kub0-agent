# Temporary app-to-IP rules

Select an app in Apps, choose an observed IP, then block it for 5 minutes,
15 minutes, or 1 hour. The rule covers that app's currently verified process
tree and newly created sockets to the selected literal IP, across ports and
TCP/UDP. Other destinations remain available. Cancellation remains available
when monitoring is stale. A new rule requires current observations.

The helper checks caller ownership, PID start times, and migration before
creating a cgroup-scoped nftables drop with a timed address-set element.
nftables expires the element independently of kub0 or the desktop shell.
Only existing connected sockets to the chosen IP are closed. Existing
unconnected UDP sockets may retain their old socket cgroup; the result warns
when complete enforcement cannot be established. Scoped operations do not
flush other applications' conntrack entries.

This version allows one active timed destination per app. Cancel it before
choosing another IP or switching to whole-app blocking. It does not persist
a launch-time policy for future independent process trees. Kernel state does
not survive reboot. There is no host-name/CIDR/port/once/allow rule UI yet.

Root-owned, per-UID records in `/var/lib/kub0/scoped` are readable only by
root and the owner's primary group. Writes are serialized, atomic, validated
and refuse symlinks or unsafe ownership. Internal cgroup names have a reserved
namespace; ordinary helper verbs cannot address them. Expiry housekeeping
checks membership as well as UID and PID start time before restoring processes.
It never moves a process that has since joined another group.

`scripts/install-privileged.sh` installs `kub0-expiry.timer`, which cleans
expired sets and cgroups once a minute. This timer handles housekeeping;
the nftables element controls the actual enforcement deadline.

Verification includes off-device owner/input/state tests, helper status
classification, QML rendering and `tests/test_scoped_nft.py`. The latter must
run in a fresh `unshare -Urn` namespace: it proves a selected IP is blocked,
another remains reachable, connectivity returns after kernel expiry, and
IPv4/IPv6 timed elements disappear. Full helper process migration and installed
timer validation require an authenticated root session.
