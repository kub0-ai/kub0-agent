# Optional Linux capture

Capture supplements the procfs sampler with cgroup connect4/connect6 and
UDP sendmsg4/sendmsg6 hooks. It is off by default. TCP/connected-UDP live
counts and TCP bandwidth still come from the sampler. The hooks return allow
without rewriting addresses or changing another program's verdict.

Captured records describe an **attempt**, including calling PID, UID, command,
destination, protocol and event time. They do not establish success, lifetime,
an executable path, transferred bytes or an enforcement verdict. History and
the evidence drawer keep those distinctions. Brief TCP attempts and unconnected
UDP destinations are retained even when there is no socket at the next sample.
Repeated UDP sends are separate attempts; QUIC protocol identification is not
claimed. Retention remains seven days / 10,000 records.

## DNS answers

The collector also attaches a pair of `cgroup_skb` programs to the same user
slice. The egress program remembers every UDP query to port 53 from a socket
the invoking UID owns, keyed by the socket's cookie and the transaction id,
with a hash of the question name and the server the query went to (an LRU map
of 4,096 entries). The ingress program recognises a DNS response structurally
(UDP from port 53, QR set, not truncated, rcode 0, exactly one question, at
least one answer, names under 254 bytes with 63-byte labels) and reports it
**only when the same socket asked**: the key must be present, the question
name must hash the same, and the response must come from the server the
query was sent to. The entry is then removed. A datagram from port 53 that
fails any of these is counted as `dnsUnmatched` and otherwise ignored, so an
off-path sender has to guess the id, the port and the name, which is the bar
the resolver itself applies; nothing arriving at a socket that never asked is
believed at all. Each A and AAAA record is reported tagged with the
**question** name, which is what the app asked for, and with the `server`
that answered; a CNAME in between is walked past, not reported. The packet is
always allowed and never rewritten.

The daemon adds its own gate: the server must be a resolver named in
`/etc/resolv.conf` (re-read when the file changes; when it is unreadable or
names nothing, only a loopback server is accepted, since a local stub is the
one resolver that needs no file). A same-uid process that asks a server of
its own choosing therefore names nothing; the refused answers are counted as
`dnsForeign` on the capture status. The daemon then validates the name again
(hostname characters only), stores address → name with the TTL clamped to one
minute and one day, and uses it as the row's `hostname` with
`hostnameSource: dns`, ahead of a PTR answer, both at first sight and when
the answer lands later. Host-suffix watch rules and the PTR indicator rungs
then apply to attributed rows without `--rdns`.

Not seen: DNS over TCP, DoT, DoH, responses to another user's sockets,
responses to queries sent before the programs were attached, IPv6 datagrams
behind an extension header, and later IPv4 fragments (only an unfragmented or
first fragment is parsed). Where a name is resolved matters too: an app that
asks systemd-resolved's stub at `127.0.0.53:53` gets its answer over loopback
UDP, which both hooks see; an app whose glibc goes through `nss-resolve`
(varlink or D-Bus to resolved, the default when `resolve` precedes `dns` in
`nsswitch.conf`) sends no UDP at all, and nothing is seen. A host where
`dnsQueries` and `dnsReceived` stay at zero with `dns: true` is usually the
second case; `dnsUnmatched` rising while `dnsReceived` stays at zero means
responses arrive that nothing in this slice asked for. A kernel that refuses
either program keeps the four address hooks and attaches neither; the status
line's `dns` field says which, and names then come only from PTR lookups. The
ring and queue limits above cover DNS events too (`dnsReceived`,
`dnsDropped`).

**Verification status.** On 2026-10-12 the BPF object was built with clang
and libbpf 1.3 in a Linux 6.18 container and loaded through libbpf with
nothing attached: the kernel verifier accepted all six programs, `dns_egress`
at 192 instructions and `dns_ingress` at 1,907. The daemon's decoder, cache
and resolver gate are unit tested. Not exercised in this change: attaching
the programs to a cgroup v2 user slice (the container has only cgroup v1
mounts) and a real query and response flowing through them, including the
cookie match across the two hooks. `tests/verify-root-enhancements.sh` on a
real host is the acceptance for those: inside its private network namespace
it runs a fixture resolver on `127.0.0.1:53` that answers every query with
two forgeries first (another transaction id from the right server, the right
id from `127.0.0.2:53`) and then the real answer, and its report's
`dnsCapture` key says whether exactly the matched answer was reported, both
forgeries were counted as unmatched, and a root-owned socket's query and
answer in the same cgroup were ignored. Until it has passed, DNS capture is
"verifier-accepted", not "verified live".

Build with `bash capture/build.sh` (clang with BPF support, libbpf development
headers, pkg-config and a C compiler). `scripts/install-capture.sh` installs the
root-owned collector and a path-specific polkit action. Installation attaches
nothing. Enable **Optional capture** in Settings, or start the user-mode daemon
with `--capture`; administrator authorization is then requested through pkexec.
Changing the setting restarts the user monitor. Capture is unsupported for
system mode, replay and external sources, which reject the flag explicitly.

The collector attaches only to the authenticated caller's `user-UID.slice` and
filters actual kernel UID before reserving an event. The daemon accepts only
that UID's bounded frames. Apps moved into the helper's `vallum.slice` are
outside this subtree: their brief/UDP attempts are not captured until restored,
although procfs sampling continues. Settings and capture status expose this
coverage limit. A `--cgroup` collector argument may restrict capture
to a descendant of the same slice, for isolated verification. It cannot expand
capture to another user's slice. The binary and every parent must be root-owned
and not writable by group/others. No BPF objects are pinned. EOF, a stop request,
signals, pipe failure and parent death close the collector's owned links.

A 4 MiB kernel ring and 1,024-record daemon queue bound memory. Status exposes
kernel ring loss, nonblocking collector-output loss, daemon queue loss and
invalid frames independently. A slow reader cannot block the privileged loop.
Missing, rejected, stopped or stale capture continues procfs monitoring; capture
status never makes sampled socket data fresh. When capture runs, the daemon
drains its queue at no slower than 500 ms, including on battery; this is an
explicit cost of opting in. No overhead or successful kernel attachment is
claimed until the privileged verification below has actually passed.

After `cargo build --release --workspace` and `bash capture/build.sh`, run
`tests/verify-root-enhancements.sh > REPORT.json` from the operator's non-root
account. It requests sudo authentication and uses private mount/network
namespaces, a private bind-mounted helper state directory, loopback traffic and
unique disposable cgroups. It checks the real scoped helper, destination and
application isolation, kernel expiry and membership restoration, IPv4/IPv6
capture, UID/cgroup filtering, reported backpressure loss and kernel detachment.
It records baseline and captured sender CPU for 10,000 unconnected UDP calls;
these measurements are local evidence, not a general performance guarantee.
Ordinary tests do not attach hooks to the desktop's user slice.

The report includes the running kernel and SHA-256 hashes of the tested helper
and collector. A failed check returns a nonzero exit code and retains completed
checks with `status: "failed"`; `status: "passed"` also requires cleanup to pass.
Authentication prompts go to stderr so redirecting stdout produces JSON.
