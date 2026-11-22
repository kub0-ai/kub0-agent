#!/usr/bin/env bash
# Install the kub0 release that matches this panel: download it, check it,
# and run its own `kub0 install` under sudo. The panel's Install button runs
# this in a terminal; it is the same as doing the steps in the README by hand.
#
# What it does, in order, and nothing else:
#   1. reads the panel's version from manifest.json and the machine's
#      architecture from `uname -m`
#   2. downloads kub0-agent-<version>-<target>.tar.gz and SHA256SUMS-<target>
#      from that version's GitHub release, over HTTPS
#   3. refuses unless the tarball's sha256 is the one the checksum file lists
#   4. unpacks into a temporary directory and runs `sudo ./kub0 install`
#
# The checksum proves the download is the file the release published, not
# who published it. `gh attestation verify` (see the README) proves that.
#
# KUB0_RELEASE_BASE overrides where the two files come from (a mirror, or a
# directory of files you already downloaded: file:///path). The checksum then
# only proves the two files agree with each other.
# KUB0_INSTALL_SUDO replaces /usr/bin/sudo; the tests use it, so that nothing
# in them runs as root.
set -euo pipefail
cd "$(dirname "$0")/.."

# Say which tool is missing, not that a download or a checksum failed.
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
sums="SHA256SUMS-$target"

proto=(--proto '=https' --tlsv1.2)
if [[ "$base" == file://* ]]; then
  proto=(--proto '=file')
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fetch() {
  if ! curl --fail --location --silent --show-error "${proto[@]}" -o "$tmp/$1" "$base/$1"; then
    echo "install-release: could not download $base/$1" >&2
    echo "install-release: nothing was installed. If $version was tagged minutes ago its release may still be building; otherwise see the releases page, or build from source (./build.sh)." >&2
    exit 1
  fi
}

echo "kub0 $version for $target"
echo "from $base"
if [[ -n "${KUB0_RELEASE_BASE:-}" ]]; then
  echo "KUB0_RELEASE_BASE is set: these are not GitHub's files, and the checksum below is checked against a file from the same place."
fi
fetch "$name.tar.gz"
fetch "$sums"

# Exactly one line of the checksum file must name the tarball, and it must match.
line="$(awk -v f="$name.tar.gz" '$2 == f || $2 == "*" f' "$tmp/$sums")"
if [[ "$(printf '%s\n' "$line" | grep -c .)" != "1" ]]; then
  echo "install-release: $sums does not list $name.tar.gz exactly once; nothing was installed" >&2
  exit 1
fi
if ! (cd "$tmp" && printf '%s\n' "$line" | sha256sum --check --strict --status -); then
  echo "install-release: $name.tar.gz does not match its checksum; nothing was installed" >&2
  exit 1
fi
echo "checksum ok"

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
