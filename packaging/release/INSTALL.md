# kub0 agent

This directory is one release for one architecture: the `kub0` command, the
`kub0d` daemon, the `kub0-block` helper, and the two geo databases they read.
The binaries are static (musl) and need nothing else to run.

```sh
sudo ./kub0 install      # binaries, kub0d.service, the kub0 group, the geo databases
kub0 doctor              # what is installed, what is missing, and the package to install for it
kub0 status              # after logging in again, as a member of the kub0 group
```

`install` is safe to run again, and it is also the upgrade: unpack a newer
release and run its `./kub0 install`.

Blocking needs `nftables`, `conntrack` and cgroup v2; `kub0 doctor` names the
package for your distribution. Watching connections needs none of them.

An account is optional, and accounts are not open to the public yet. For an
org that has one, `sudo kub0 login` connects the machine to it.

On Omarchy the panel is a separate step:
`omarchy plugin add https://github.com/kub0-ai/kub0-agent`.

Everything else: https://github.com/kub0-ai/kub0-agent

`LICENSE` covers this project. `THIRD-PARTY.md` records what it took from other
projects, `THIRD-PARTY-LICENSES.md` carries the license of every Rust crate in
the build graph, of Rust's standard library and of musl libc, and
`geoip/ATTRIBUTION.txt` the terms of the databases (DB-IP, CC-BY-4.0).
