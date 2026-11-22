#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/target/capture"
mkdir -p "$OUT"
includes=(-I/usr/include)
multiarch="$(cc -print-multiarch 2>/dev/null || true)"
if [[ -n "$multiarch" && -d "/usr/include/$multiarch" ]]; then
  includes+=("-I/usr/include/$multiarch")
fi
clang -g -O2 -target bpf "${includes[@]}" -c "$ROOT/capture/capture.bpf.c" -o "$OUT/capture.bpf.o"
python3 - "$OUT/capture.bpf.o" "$OUT/capture_blob.h" <<'PY'
from pathlib import Path
import sys
b=Path(sys.argv[1]).read_bytes()
Path(sys.argv[2]).write_text('static const unsigned char capture_blob[] = {'+','.join(str(n) for n in b)+'};\n')
PY
cc -O2 -g -Wall -Wextra -Werror -Wno-misleading-indentation "$ROOT/capture/collector.c" -I"$OUT" -o "$OUT/kub0-capture" $(pkg-config --cflags --libs libbpf)
echo "$OUT/kub0-capture"
