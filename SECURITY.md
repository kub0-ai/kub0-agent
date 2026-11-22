# Security

## Reporting a vulnerability

Report it privately: on this repository, **Security**, then **Report a
vulnerability**. Please do not open a public issue for something exploitable.

What helps: the version (`kub0 --version`), the distribution and kernel, what
you ran, what you expected and what happened. `kub0 doctor` output is useful
and holds no secrets; an account file or a token never is.

Fixes land on `main` and in the next release. Only the latest release is
supported.

## What this software runs as

- `kub0d --system`: a root daemon (`kub0d.service`) that watches connections,
  enforces the org's network policy and runs the exec gate.
- `kub0-block`: a root helper, reached through polkit, that writes nftables
  rules and moves processes between cgroups.
- `kub0-expiry.service`: a root timer that runs `kub0-block expire-scoped`,
  which lifts timed blocks when they run out.
- `kub0-capture`: an optional root collector that loads an eBPF program,
  reached through polkit. It is off unless you turn capture on.
- `kub0` and the panel run as you. They talk to the daemon on
  `/run/kub0/kub0.sock`, which members of the `kub0` group can read, and can
  use for changes that do not lower protection (a block, a resume, a watch
  rule, a network's name). A change that lowers it takes root: `sudo kub0 …`
  in a terminal, or from the panel `pkexec /usr/bin/kub0 …`, where polkit asks
  for a password each time. `sudo kub0 install` runs as root too.

## What we want to hear about

- Someone outside the `kub0` group changing firewall state, reading another
  account's connections, or reaching the daemon's socket.
- A member of the `kub0` group doing what is documented as root-only: lifting
  a block, pausing enforcement, turning destination sharing on, logging the
  host out.
- Lowering protection without the polkit prompt the README describes.
- A response from the server, or from any network peer, that leads to code
  execution, a write outside the state directories, or a block on an address
  in the never-block floor (`docs/FLEET-NETWORK-POLICY.md`).
- The exec gate holding an exec it should have released. It is fail-open by
  design; a way to make it freeze a machine is a bug.
- The account's token anywhere it should not be: a log, a status answer,
  `kub0 doctor`, a panel frame, or any request other than the `Authorization`
  header to the kub0 server. (The GitHub username and node name are shown by
  design.)

## What is a documented limit, not a vulnerability

The README's *Honest limitations* lists them. The two that come up most: app
identity is a name the process chooses, so anything running as you can appear
under another app's row; and a per-app block stops an honest app's traffic, not
a hostile one that asks another process to connect for it.
