# Fleet network policy

Status: **slices A, B and C built (2026-10-05).** Slice D (macOS enforcement) is not. It extends the org
deny-list idea to network destinations: block or watch traffic by country, by
kub0 threat intel, by literal IP, optionally scoped to one app, with policies
attached to kub0 host groups. Monitor shipped first; blocking followed with
slice C.

## Why this is not more deny-list rows

`GET /detonate/api/enforce/denylist` has two consumers. This agent reads it
for the exec gate. kub0's cluster node agent syncs it into kernel maps on every
cluster node, parses each row strictly as a process entry, and refuses a whole
snapshot above a size limit. A country or intel row on that endpoint would
either fail that parse or trip the limit, and both outcomes stop deny-list sync
across a fleet. Network policy therefore gets its own endpoint, and the
deny-list stays process-only.

## Model

A **rule** is one destination matcher, an optional app scope, and an action.

| kind | matches the remote address when | example `match` |
|---|---|---|
| `country` | its country (dbip-country-lite, already looked up for every flow) is in the list | `{"countries":["KP","IR"]}` |
| `intel` | it is in the materialised kub0 indicator set (see *Intel eligibility*) | `{"min_confidence":0.8,"sources":["threatfox","urlhaus"]}` |
| `ip` | it falls in the CIDR | `{"cidr":"203.0.113.0/24"}` |

`app_path` (optional, on any rule) narrows it to one executable: "this app may
not talk to country X". Without it the rule covers the whole host. App identity
in v1 is the exe path; it is not a signing identity, and a renamed copy escapes.

`action` is `monitor` or `block`.

A **policy** is a named, org-owned set of rules with its own `mode`
(`monitor`|`block`). The effective action of a rule is the weaker of its own
action and the policy mode, so setting a policy to `monitor` disarms every rule
in it at once. `user_can_snooze` (`monitor_only` by default, else `none` or
`all`) says whether the device's own user may snooze the policy's rules
locally; a snooze is reported on the heartbeat, never hidden.

**Attachment** is per host group: a policy is attached to one or more of the
org's host groups. A policy with `org_default = true` also applies to nodes in
no group. A node is put in a group with `POST /api/groups/{id}/assign`.

## Resolution endpoint

`GET /detonate/api/enforce/netpolicy?node=<node_name>` returns the org-default
policies plus the policies attached to that node's group.

- **Fails closed.** A missing or invalid token is a 401. This is deliberately
  unlike the deny-list, which falls back to the platform org so a tokenless
  probe keeps syncing. A network policy has no meaning without an org.
- The `ETag` header is a hash of the response; kub0d revalidates with
  `If-None-Match` and keeps its set on a 304. Each policy carries its own
  `version`, which match reports echo back.
- `intel` rules arrive with their IP set already materialised, each entry with
  its own expiry, so kub0d never queries the indicator store itself.

```json
{"policies":[{"id":"np-1","name":"Known C2","mode":"monitor","user_can_snooze":"monitor_only","version":12,"rules":[
  {"id":"nr-1","kind":"intel","action":"monitor","match":{"min_confidence":0.8,"sources":["threatfox","urlhaus"]},
   "set":[{"ip":"198.51.100.7","source":"threatfox","confidence":0.9,"expires":"2026-11-04T00:00:00Z"}],
   "suppressed":1,"withheld":0},
  {"id":"nr-2","kind":"country","action":"monitor","app_path":"/usr/bin/foo","match":{"countries":["KP"]}}]}]}
```

`suppressed` counts indicators in the never-block floor and `withheld` counts
indicators that are not TLP:CLEAR. Only TLP:CLEAR indicators leave the server,
under the same rule as the STIX export.

## Never-block floor

Checked in three places: when the server materialises an intel set, when
kub0d evaluates a flow, and (once blocking exists) in the root helper before
it writes nftables. A floor hit is counted and reported as `suppressed`, never
dropped silently, so a poisoned feed shows up instead of hiding.

- loopback, RFC 1918, RFC 6598 shared address space (the tailnet), link-local, multicast,
  broadcast, `fc00::/7`, `fe80::/10`
- the addresses the configured kub0 server resolves to, re-resolved every sync.
  `api.kub0.io` is Cloudflare-proxied, which is exactly the shared
  infrastructure a bad indicator is most likely to name. Blocking it would cut
  the channel that delivers the unblock.
- the host's configured DNS resolvers (`/etc/resolv.conf`, which macOS also
  generates). A default gateway is in practice always a private address, which
  the static ranges already cover.

## Intel eligibility

- **IP indicators only in v1.** The domain, hostname and URL indicators need
  a flow's hostname, which kub0d does not see on Linux. Out of scope.
- **Model-written indicators are never eligible.** They are claims, not
  observations, and a hallucinated resolver address would be a fleet outage.
  Default `sources` is `threatfox`, `urlhaus`; `otx` is opt-in.
- Every entry expires: `valid_until`, else `last_seen + 30d` (the deny-list's
  auto-TTL precedent).
- Shared infrastructure (CDNs, large clouds) cannot be blocked without
  collateral damage. v1 has no ASN data to recognise it; see open questions.

## Country caveat

Country is where the IP is registered or geolocated, not where the service
is. A CDN-fronted site resolves to the nearest point of presence. Country rules
earn their keep on direct-IP traffic and with an `app_path` scope. As a blanket
outbound block they over-block CDNs and under-block anything behind one, so
the UI defaults new country rules to `monitor`.

## Match reporting

This is the point of monitor mode. kub0d evaluates rules on every observed
flow. The panel shows local hit counts per policy and per rule, and a
*would block* badge on matching connections.

The heartbeat gains an additive `policy_matches` array. The ingest decodes
without rejecting unknown fields, so a new kub0d can send it before the API
reads it.

```json
"policy_matches":[{"policy_id":"np-1","rule_id":"nr-1","policy_version":12,
  "hits":3,"would_block":2,"blocked":2,"shared_infra":1,"suppressed":0,"snoozed":false,
  "dests":["198.51.100.7"]}]
```

A rule is evaluated once per connection, when kub0d first sees it. Flows a
source replays from history (older than 10 minutes) are never counted. Counts a
failed heartbeat did not deliver go back into the ledger for the next one.

Counts reset after each successful heartbeat. `dests` lists distinct remote
addresses, capped at 32 per rule per heartbeat, for every rule kind. For
`country` rules that is the owner's browsing leaving the device; it is sent
deliberately (decided 2026-10-05) because false-positive triage before any
promotion to block needs the addresses, and the panel says so.

The server keeps daily counts per node and rule. Promoting a rule from
monitor to block reads them. A rule with zero hits has not been
tested; an empty result is not a pass.

## Platform reach

| | monitor | block |
|---|---|---|
| Linux, system kub0d (root) | yes | **enforced**: `kub0-block fleet-sync` |
| Linux, user-mode kub0d | yes | reported as `would_block` |
| macOS kub0d | yes (libproc snapshots can miss short-lived flows) | reported as `would_block`; needs an `NEFilterDataProvider` system extension (slice D) |

Only the system kub0d enforces. Every kub0-block verb sits behind a polkit
`auth_admin` prompt, and a user-mode kub0d cannot answer one each time the org
changes a policy. Adding a no-prompt polkit action instead would let any process in
the session rewrite the firewall, so it was not done. The panel's enforcement line
says which case an endpoint is in.

## Enforcement (slice C)

The system kub0d plans after every policy refresh and whenever a snooze changes:

- **Block plan.** Every rule whose effective action is `block` (rule action *and*
  policy mode), unsnoozed and not app-scoped: `ip` rules as given, `intel` as one
  `/32` or `/128` per unexpired indicator, `country` as every range the bundled
  country database assigns to it (`/usr/share/kub0/geoip` for the system kub0d).
  A country rule that gets no ranges is reported as not enforced, never as covered.
  When that is because there is no country database (missing, or a file with no
  countries in it), the system kub0d applies no new block rules at all, as for the
  ASN database below: a plan without that country's ranges would take the ones an
  earlier run applied out of the kernel. App-scoped block rules are reported, not
  enforced, until per-app cgroup scoping exists for fleet rules.
- **Keep set.** `kub0-block` adds the static floor and this host's resolvers and
  gateways itself, root-side; the daemon adds the kub0 server's addresses and every
  range announced by a shared-infrastructure ASN (Cloudflare, Akamai, Fastly, Amazon,
  Google, Microsoft, Meta, Apple, Edgio, CDN77, Automattic) from DB-IP ASN Lite. A
  caller can only add to the keep set. With no shared-infrastructure ranges to keep
  (the ASN database missing, or one that holds no such records) the system kub0d
  applies no new block rules, since a block range could then cover a CDN. It reports
  an error naming the database and the data dir; rules an earlier run applied were
  built with their keep set and are left in place. Both databases are read once, so
  installing a missing one takes a restart of the system kub0d.
- **Kernel.** One `nft -f` transaction: `fleet4`/`fleet6` and `fleetkeep4`/`fleetkeep6`
  interval sets, refilled atomically, and one rule per family,
  `ip daddr @fleet4 ip daddr != @fleetkeep4 counter drop`, below the panel's pause
  rule, so pausing kub0 pauses these too. An unchanged plan is not re-sent; it is
  re-sent when the earliest intel indicator in it expires. Each heartbeat reads the
  kernel back with `nft -a list chain inet vallum out`: read-only, rules only (no set
  elements), no root-helper call, killed after 10 seconds. Rules removed underneath
  (a teardown, an nftables reload) are re-applied, and whether the pause rule sits
  ahead of them is read from the same listing, so `enforcing` is only reported for
  rules the kernel was seen to hold. A read that fails or times out reports that the
  rules cannot be confirmed, not `enforcing`, and changes nothing. Only nft's own
  answer for a table or chain that is not there (exit 1, `Error: No such file or
  directory` for the chain it was asked to list) reads as an empty kernel; nft that
  cannot start, a loader that cannot find libnftables included, or that is killed,
  is a read that failed. One family's drop rule without the other's is not
  `enforcing`, but it still drops, so it counts as rules held: re-applied under a
  current plan, and cleared like any other once the server says there are none.
- **Removal.** Apart from a snooze on the device, only two things take block rules
  out of the kernel: the server saying there are none (a 200 with `"policies":[]`,
  or policies this kub0d reads in full with no effective block rule) and a local
  disconnect. Until the current account's policy has arrived (after a restart, an
  account change including a token rotation, or while every fetch fails), an empty
  set changes nothing, and the state is an error saying the rules already in the
  kernel were left in place. A restarted kub0d clears an earlier run's rules once
  the server says there are none. A clear that fails is an error, not `none`, and is
  retried.
- **Refresh.** Only a 200 whose body has a `policies` array replaces the set; `[]`
  clears it. A 304 counts only against a set received with an ETag. A 404, any other
  error status, or a body without `policies` keeps the last set received, and the
  fleet frame's `netpolicyRefreshOk` goes false. A 401 or 403 is the same: a host
  whose token was revoked keeps enforcing its last policy indefinitely. Take it out
  with a local disconnect, `sudo kub0 logout`; the running system kub0d
  clears its rules on its next heartbeat (with it stopped,
  `sudo /usr/lib/kub0/kub0-block fleet-clear`). An account file that exists but
  cannot be read or parsed is not a disconnect, whether a heartbeat reads it at its
  start or at its end: it changes nothing until it reads again.
- **Unreadable sets.** A 200 with a set this kub0d cannot read in full is a failed
  refresh too: a policy or rule with no id, a `mode` or `action` other than
  `monitor` or `block`, or a block rule whose match it cannot read (a kind it does
  not know, a CIDR, country code, indicator address or expiry it would have to
  drop). Taken loosely, a new mode word would read as monitor and a policy with no
  id would be skipped, and either would take its block rules out. The log names the
  policy and rule by index and id, never a value. A monitor rule it cannot read is
  listed and never matches; it cannot take anything out of the kernel, so it fails
  nothing.
- **Restart during an outage.** The last policy received lives in memory only. A
  kub0d restarted while the server is unreachable starts with none: it leaves the
  rules an earlier run put in the kernel, but cannot re-apply them if they are gone.
  nftables does not keep kub0's table across a reboot, so a host rebooted during a
  kub0 outage enforces no org block rules until the server answers.
- **Reporting.** `would_block` counts matches the rule would drop; `blocked` counts
  the ones this endpoint's kernel actually holds; `shared_infra` counts matches on
  shared infrastructure, which are never blocked. The system kub0d's state
  (`netpolicyEnforcement`, `netpolicyRefreshOk`) is in the fleet frame on
  `/run/kub0/kub0.sock`, which is the frame the panel shows when it reads the
  system daemon (a session in group `kub0`, capture off); on its own per-user
  kub0d the panel lays the system daemon's `status` and `policies` over it. Its
  errors are in `journalctl -u kub0d`.
- **Snooze.** A policy's `user_can_snooze` (`none`, `monitor_only` by default, or
  `all`) decides which rules the panel offers to snooze, for an hour, capped at a day.
  A snoozed rule leaves the block plan at once, its matches carry `snoozed: true`,
  and the snooze lives only on the device.

## Slices

- **A, the kub0 API.** Policies, attach and detach, the resolution endpoint,
  and `policy_matches`. Live since 2026-10-05.
- **B, this agent.** Fetch, monitor matches, the Network policies section, heartbeat
  counts. Merged 2026-10-05.
- **C, this agent and the kub0 API.** Linux enforcement as above, `block` accepted by the
  API, `blocked` and `shared_infra` stored, snooze.
- **D, separate project.** The macOS network filter.

## Verification for A and B

- **Positive canary.** A monitor `ip` rule on one public, non-resolver address;
  `curl` it; the panel count and the server's count both rise.
- **Near miss.** A second address outside the rule stays at 0.
- **Floor canary.** An `ip` rule naming the kub0 server's address is reported
  `suppressed` and never `would_block`.
- **Deny list untouched.** `GET /api/enforce/denylist` is byte-identical before
  and after slice A.

## Decisions (2026-10-05)

1. **Snooze** is a per-policy flag, `user_can_snooze`. The default lets a user
   snooze monitor rules and not block rules.
2. **Intel sources** default to `threatfox` and `urlhaus`. `otx` is opt-in per
   rule. Model-written indicators are never eligible.
3. **Country matches send destinations**, not only counts (see *Match
   reporting*).
4. **ASN data** arrives with blocking, in slice C. Monitor-only slices cannot
   over-block, so they do not need it.
