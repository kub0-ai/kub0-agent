#!/usr/bin/env bash
# Package one target's release: a tarball someone can unpack and install from,
# the same three binaries under their target-suffixed names, the license
# notices, and one checksum file over all of it.
#
#   scripts/package-release.sh <target> [<out dir>]
#
# Reads the binaries from target/<target>/release (KUB0_PACKAGE_BIN_DIR
# overrides it, for the test) and writes to dist/ unless told otherwise:
#
#   kub0-agent-<version>-<target>.tar.gz   kub0, kub0d, kub0-block, geoip/,
#                                          INSTALL.md, LICENSE, THIRD-PARTY.md,
#                                          THIRD-PARTY-LICENSES.md
#   kub0-<target>, kub0d-<target>, kub0-block-<target>
#   THIRD-PARTY-LICENSES.md
#   SHA256SUMS-<target>
#
# The tarball unpacks to one directory, and `sudo ./kub0 install` run inside
# it finds the binaries and the geo databases beside itself. The archive is
# built the same way every time (sorted, root-owned, fixed modes, the commit's
# date, no gzip timestamp), so two builds of the same binaries give the same
# bytes whatever the umask. Nothing is written to the out dir until the
# tarball exists, so a failure leaves no half release there.
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <target> [<out dir>]" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
target="$1"
out="${2:-$ROOT/dist}"
bin="${KUB0_PACKAGE_BIN_DIR:-$ROOT/target/$target/release}"

version="$(awk -F'"' '/^version = /{print $2; exit}' "$ROOT/Cargo.toml")"
if [[ -z "$version" ]]; then
  echo "package-release: no version in Cargo.toml" >&2
  exit 1
fi
name="kub0-agent-$version-$target"

for b in kub0 kub0d kub0-block; do
  if [[ ! -x "$bin/$b" ]]; then
    echo "package-release: $bin/$b is missing or not executable (build --release --target $target first)" >&2
    exit 1
  fi
done

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name/geoip"
chmod 0755 "$stage/$name" "$stage/$name/geoip"

for b in kub0 kub0d kub0-block; do
  install -m0755 "$bin/$b" "$stage/$name/$b"
done
for f in dbip-country-lite.mmdb dbip-asn-lite.mmdb ATTRIBUTION.txt; do
  install -m0644 "$ROOT/data/geoip/$f" "$stage/$name/geoip/$f"
done
install -m0644 "$ROOT/packaging/release/INSTALL.md" "$ROOT/LICENSE" "$ROOT/THIRD-PARTY.md" "$stage/$name/"

# Every target's crates in one file, so the copy beside the loose binaries is
# the same whichever job attached it. KUB0_PACKAGE_LICENSES names a file made
# earlier (the test does; a release never should).
if [[ -n "${KUB0_PACKAGE_LICENSES:-}" ]]; then
  install -m0644 "$KUB0_PACKAGE_LICENSES" "$stage/$name/THIRD-PARTY-LICENSES.md"
else
  (cd "$ROOT" && python3 scripts/third-party-licenses.py \
    --target x86_64-unknown-linux-musl --target aarch64-unknown-linux-musl \
    --out "$stage/$name/THIRD-PARTY-LICENSES.md")
fi

# The archive's clock is the commit's, never the build's: a build with no
# commit to read and no SOURCE_DATE_EPOCH has no honest date to give.
epoch="${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)}"
if [[ ! "$epoch" =~ ^[0-9]+$ ]]; then
  echo "package-release: no commit date to stamp the archive with; set SOURCE_DATE_EPOCH" >&2
  exit 1
fi
tar --format=gnu --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" \
  -C "$stage" -cf - "$name" | gzip -n -9 > "$stage/$name.tar.gz"

mkdir -p "$out"
install -m0644 "$stage/$name.tar.gz" "$out/$name.tar.gz"
install -m0644 "$stage/$name/THIRD-PARTY-LICENSES.md" "$out/THIRD-PARTY-LICENSES.md"
for b in kub0 kub0d kub0-block; do
  install -m0755 "$bin/$b" "$out/$b-$target"
done

(cd "$out" && sha256sum "$name.tar.gz" "kub0-$target" "kub0d-$target" "kub0-block-$target" \
  THIRD-PARTY-LICENSES.md > "SHA256SUMS-$target")
cat "$out/SHA256SUMS-$target"
