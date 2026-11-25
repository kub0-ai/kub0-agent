#!/usr/bin/env bash
# Install the kub0 release that matches this panel: download it, check it,
# and run its own `kub0 install` under sudo. The panel's Install button runs
# this in a terminal; it is the same as doing the steps in the README by hand.
#
# What it does, in order, and nothing else:
#   1. reads the panel's version from manifest.json and the machine's
#      architecture from `uname -m`
#   2. reads the sha256 that scripts/release-digests, in this checkout, gives
#      for kub0-agent-<version>-<target>.tar.gz, and stops if there is none
#   3. downloads that tarball from that version's GitHub release, over HTTPS
#   4. refuses unless the tarball has exactly that sha256
#   5. unpacks into a temporary directory and runs `sudo ./kub0 install`
#
# The digest comes from the plugin's own source, not from the release. What
# runs as root is therefore fixed by the same commit as this script: a
# release whose files are replaced later, checksum file and all, is refused
# here. Each digest was taken from a tarball whose build provenance was
# verified first (CONTRIBUTING.md, "Releasing"); `gh attestation verify` (see
# the README) repeats that check for anyone.
#
# KUB0_RELEASE_BASE overrides where the tarball comes from (a mirror, or a
# directory of files you already downloaded: file:///path). It changes where
# the file is fetched from, never what it must be.
# KUB0_INSTALL_SUDO replaces /usr/bin/sudo; the tests use it, so that nothing
# in them runs as root.
set -euo pipefail
cd "$(dirname "$0")/.."

# Say which tool is missing, not that a download or a digest check failed.
for tool in awk curl sha256sum tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "install-release: this needs $tool, and it is not installed; nothing was installed" >&2
    exit 1
  fi
done
# By path, not through PATH: this is the step that becomes root.
sudo="${KUB0_INSTALL_SUDO:-/usr/bin/sudo}"

version="$(awk -F'"' '/"version"[[:space:]]*:/{print $4; exit}' manifest.json)"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "install-release: manifest.json has no usable version ('$version')" >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64 | amd64) target="x86_64-unknown-linux-musl" ;;
  aarch64 | arm64) target="aarch64-unknown-linux-musl" ;;
  *)
    echo "install-release: no release is built for $(uname -m). Build from source instead: ./build.sh, then ./scripts/install-privileged.sh" >&2
    exit 1
    ;;
esac

base="${KUB0_RELEASE_BASE:-https://github.com/kub0-ai/kub0-agent/releases/download/v$version}"
name="kub0-agent-$version-$target"
pins="scripts/release-digests"

# The digest this checkout pins for that tarball: one line that names it,
# whole, with 64 hex digits in front. No line, two lines, or anything else in
# front is no pin, and without one there is nothing to check a download
# against, so nothing is downloaded.
pinned=""
if [[ -f "$pins" ]]; then
  pinned="$(awk -v f="$name.tar.gz" '!/^[[:space:]]*#/ && $2 == f { print $1 }' "$pins")"
fi
if [[ ! "$pinned" =~ ^[0-9a-f]{64}$ ]]; then
  echo "install-release: this checkout pins no digest for $name.tar.gz ($pins), so there is nothing to check a download against; nothing was downloaded or installed" >&2
  echo "install-release: a release's digests are added to the plugin once it is published. Get them with: omarchy plugin update. Or build from source instead: ./build.sh, then ./scripts/install-privileged.sh" >&2
  exit 1
fi

proto=(--proto '=https' --tlsv1.2)
if [[ "$base" == file://* ]]; then
  proto=(--proto '=file')
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "kub0 $version for $target"
echo "from $base"
if [[ -n "${KUB0_RELEASE_BASE:-}" ]]; then
  echo "KUB0_RELEASE_BASE is set: the tarball comes from there, not from GitHub, and is checked against the same pinned digest."
fi
if ! curl --fail --location --silent --show-error "${proto[@]}" -o "$tmp/$name.tar.gz" "$base/$name.tar.gz"; then
  echo "install-release: could not download $base/$name.tar.gz" >&2
  echo "install-release: nothing was installed. See the releases page, or build from source (./build.sh)." >&2
  exit 1
fi

if ! (cd "$tmp" && printf '%s  %s\n' "$pinned" "$name.tar.gz" | sha256sum --check --strict --status -); then
  echo "install-release: $name.tar.gz is not the file this checkout pins (sha256 $pinned); nothing was installed" >&2
  exit 1
fi
echo "digest ok: sha256 $pinned"

tar -xzf "$tmp/$name.tar.gz" -C "$tmp"
if [[ ! -x "$tmp/$name/kub0" ]]; then
  echo "install-release: the release has no kub0 in it; nothing was installed" >&2
  exit 1
fi

echo
echo "Installing: sudo will ask for your password."
"$sudo" "$tmp/$name/kub0" install
echo
if id -Gn | tr ' ' '\n' | grep -qx kub0; then
  echo "kub0 is installed, and this session is already in the kub0 group."
elif id -Gn "$(id -un)" | tr ' ' '\n' | grep -qx kub0; then
  echo "kub0 is installed. Log out and back in once: this session joins the kub0"
  echo "group then, and the panel can read the daemon. If it still cannot after"
  echo "that, reboot: a user service manager that outlives the logout keeps the"
  echo "old groups."
else
  echo "kub0 is installed, but this account is not in the kub0 group, which is what"
  echo "lets the panel read the daemon. Add it, then log out and back in:"
  echo "  sudo gpasswd -a $(id -un) kub0"
fi
