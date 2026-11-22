#!/usr/bin/env bash
# Build kub0d (the daemon), kub0-block (the privileged helper) and kub0 (the CLI).
# On the Omarchy/Linux box this produces native binaries in ./bin.
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is missing — installing the rust package…"
  omarchy pkg add rust
  hash -r 2>/dev/null || true
  export PATH="/usr/bin:${HOME}/.cargo/bin:${PATH}"
fi
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is still missing after installing rust." >&2
  exit 1
fi

echo "building kub0d + kub0-block + kub0 (release)"
cargo build --release --workspace

mkdir -p bin
cp -f target/release/kub0d bin/kub0d
cp -f target/release/kub0-block bin/kub0-block
cp -f target/release/kub0 bin/kub0
chmod +x bin/kub0d bin/kub0-block bin/kub0
if [[ ${KUB0_BUILD_CAPTURE:-0} == 1 ]]; then
  bash capture/build.sh
  cp target/capture/kub0-capture bin/kub0-capture
fi

SUM=bin/SHA256SUMS
if command -v sha256sum >/dev/null 2>&1; then
  (cd bin && sha256sum kub0d kub0-block kub0 > SHA256SUMS)
elif command -v shasum >/dev/null 2>&1; then
  (cd bin && shasum -a 256 kub0d kub0-block kub0 > SHA256SUMS)
else
  echo "no sha256 tool; skipping checksums" >&2
  SUM=""
fi

echo "built:"
ls -l bin/kub0d bin/kub0-block bin/kub0
if [[ -n "$SUM" && -f "$SUM" ]]; then
  cat "$SUM"
fi

echo
echo "optional: ./scripts/install-privileged.sh"
echo "  sudo installs kub0d, kub0-block, the polkit policy and the kub0 CLI"
