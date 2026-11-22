# Third-Party Provenance

This file records what the kub0 agent took, from whom, and under what terms.
It is maintained **as code is taken**, not reconstructed afterwards. If you
copy, port, or closely adapt anything from outside this repo, add it here in
the same commit.

The obligations below attach to *distribution*: of this repository, and of the
binaries its releases publish.

The project was called *vallum* until 0.4.5, and a few internal names still
are (section 1.1).

---

## 1. Code base: omarchy-snitch

- **Upstream:** https://github.com/ccdwyer/omarchy-snitch
- **Author:** Christopher Dwyer ("chris")
- **License:** MIT (see `LICENSE`: his notice is retained, kub0's is added under it)
- **What we took:** everything. This repository starts from omarchy-snitch at
  `147efa6`: 13 commits, single author. The QML panel, world map, flag set,
  `snitchd` daemon, `snitch-block` polkit helper, cgroup machinery, and CI
  workflows all originate there.

**The history is the provenance record.** Upstream's 13 commits are in this
repository unchanged: `147efa6` and everything before it hash exactly as they
do in ccdwyer/omarchy-snitch, signatures included. Everything kub0 changed up
to the first public release is one commit on top of `147efa6` (that work was
done in a private repository), and the history is ordinary from there. So
"which parts are his?" is `git log 147efa6` (and `git ls-tree -r 147efa6` for
the files), and "what changed since?" is `git diff 147efa6 HEAD`, not anyone's
memory.

Do not rebase or rewrite upstream's commits. A rewrite re-hashes them, and a
tool that strips GPG signatures (`git filter-repo` does) re-hashes them
silently, because one of them, made on GitHub's web editor, is signed. The anchor then stops
matching upstream, which is the one thing this section exists to preserve.

**Obligation:** retain the MIT notice (upstream's line is in `LICENSE`, with
kub0's added below it) and credit Christopher Dwyer in the README. MIT asks
for essentially nothing else. Credit generously anyway.

### 1.1 The identity renames

Every system-global name moved from `snitch` to `vallum`, and then, in 0.4.5
to 0.4.7, to `kub0`: the plugin id, the polkit actions, the helper's root-owned
install path, the sockets, the units, the status group and the binaries. What
still carries the middle name is nothing a user types, though some of it shows
in `nft list ruleset` and `systemd-cgls`: the nftables table (`inet vallum`)
and its rule comments (`vallum-fleet`, `vallum-paused`), the cgroup slice
(`vallum.slice`), the Rust crates (`vallumd`, `vallum-block`), the panel's
internal property names, and the `agent` value the heartbeat reports, which
the kub0 API keys on.

The first rename was **not** a branding change, and the reason is worth keeping
here because it is the kind of thing that looks cosmetic in a diff. A polkit
action is scoped to an exec path. Had this fork's helper installed to upstream's
`/usr/lib/snitch/snitch-block`, installing it on a machine that already had
omarchy-snitch would overwrite a root-owned binary that upstream's still-present
policy file continues to authorize, in both directions, silently. Forking a
project that installs a privileged helper means the helper's path is part of
what you have to fork.

One consequence for anyone reading provenance later: diffs against upstream are
noisy in every file that names itself. The README's upgrade sections carry the
full mapping of old names to new.

`opensnitch`/`OpenSnitch` and `omarchy-snitch`/`ccdwyer` were explicitly
protected from those passes. The first names a different product; the second is
how upstream is cited. A blind `sed` would have renamed both.

## 2. Design inspiration: omasnatch

- **Upstream:** https://github.com/weedwhitesandwine/omasnatch
- **Author:** weedwhitesandwine
- **License:** MIT
- **What we took:** two file-hygiene patterns, ported to Rust in
  `daemon/src/fileguard.rs`. The approach of surfacing OpenSnitch's event
  database as a desktop panel originates here, as does the read-only-by-design
  posture.

Ported from `collector.py`, named explicitly because they were read before they
were written:

- `ro_uri` — percent-encoding the DB path into the SQLite URI so a crafted path
  cannot append its own `?mode=rwc` and defeat read-only opening. This
  version encodes `=` as well as `?`, so an injected parameter cannot even be
  parsed as a key/value pair.
- `read_capped` — capped reads with `realpath` + `O_NONBLOCK` + a regular-file
  check *on the opened descriptor*, so a planted FIFO cannot park a read forever
  and an oversized file is refused rather than loaded.

Not ported, and listed so nobody has to rediscover it: the atomic config write
staged under an exclusively-created temp name, following a symlink only to a
target the user owns. kub0 writes no OpenSnitch state, so there is nothing yet
for it to protect.

General techniques are not copyrightable and a clean reimplementation carries no
obligation. Credit the author regardless: the idea came from there.

**Not taken:** the SQL. omasnatch's queries aggregate for a summary panel;
this driver pages incrementally for a stream. The *column names* are shared
because they are facts about OpenSnitch's schema, not authorship.

## 3. Interop dependency: OpenSnitch

- **Upstream:** https://github.com/evilsocket/opensnitch
- **Author:** Simone Margaritelli (evilsocket) and contributors
- **License:** **GPL-3.0**
- **What we took: NO CODE. This is an interop relationship only.**

> ### Clean-room rule (binding)
>
> kub0 reads OpenSnitch's event database, and may one day write rule files it
> consumes or speak its gRPC protocol. **Interoperating with GPL software does
> not create a derivative work. Copying or adapting its source does.**
>
> To write code here, read OpenSnitch's **protocol, schema, database layout,
> and documentation**. Do not read its implementation source. If understanding
> a kernel interface requires reading their code, record that here and
> re-derive the implementation from kernel documentation and man pages instead.
>
> The licenses do not mix in that direction: this repository is MIT, and
> GPL-3.0 code cannot be folded into it without relicensing every binary built
> from it. Contamination is cheap to avoid now and effectively impossible to
> remove later, because you cannot prove you un-saw code.

Interface facts that are safe to study in full: the `connections` table shape,
the rule JSON format, the settings keys, the gRPC protobuf definitions.

**Obligation:** none, provided the rule above held. Credit OpenSnitch and name
its license in the README. Do not imply endorsement, do not
reuse its branding, and do not put it in the product name.

## 4. Bundled data

| Asset | Source | License | Obligation |
|---|---|---|---|
| `data/geoip/dbip-country-lite.mmdb` | [DB-IP](https://db-ip.com) Country Lite | CC-BY-4.0 | Attribution required. `data/geoip/ATTRIBUTION.txt` retained. |
| `data/geoip/dbip-asn-lite.mmdb` | [DB-IP](https://db-ip.com) ASN Lite (2026-10) | CC-BY-4.0 | Attribution required. `data/geoip/ATTRIBUTION.txt` retained. Keeps shared infrastructure out of org block rules, and since the Intel work names each public peer's ASN and registrant on the row. |
| ATT&CK technique ids and names in `daemon/src/intel.rs` | [MITRE ATT&CK®](https://attack.mitre.org) | MITRE's ATT&CK terms of use permit use with attribution | Seven technique identifiers and their names, used as vocabulary on indicators. "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." No ATT&CK data files are bundled. |
| `data/world-paths.json` | [Natural Earth](https://www.naturalearthdata.com/) 110m | Public domain | None. `data/MAP-ATTRIBUTION.txt` retained. |
| `data/flags/*.svg`, `data/flag-recipes.json` | Bundled geometric SVGs and their recipes (upstream-authored) | MIT, with omarchy-snitch | Covered by section 1. |
| `data/country-centroids.json` | Came with omarchy-snitch, which states no source. The values are those of Google's [`countries.csv`](https://developers.google.com/public-data/docs/canonical/countries_csv) (DSPL canonical concepts), rounded to four places. | CC-BY-4.0, under Google Developers' [site policies](https://developers.google.com/site-policies) | Attribution, given here. One latitude and longitude per ISO country code. |

## 5. The capture program

`capture/capture.bpf.c` and `capture/collector.c` are this project's own. The
eBPF program is offered under **MIT or GPL-2.0-only**, at your choice, and
declares `Dual MIT/GPL` to the kernel, which is how a program tells the
verifier it may call GPL-only helpers. It is built on the machine that opts in
to capture (`scripts/install-capture.sh`); releases ship no capture binary.

Building it includes libbpf's helper headers (LGPL-2.1 or BSD-2-Clause) and the
kernel's UAPI headers (GPL-2.0 with the Linux syscall note, which exists so
that including them does not make a program a derivative work), and the
collector links the system's libbpf dynamically. None of the three is copied
into this repository.
