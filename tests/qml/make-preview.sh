#!/usr/bin/env bash
# Make preview.png, the picture a plugin listing shows: the panel's Overview
# and Apps views side by side.
#
# Nothing in it is a real connection. The panel is rendered offscreen by the
# QML harness (tests/qml/run-runtime.sh, in its sandbox) from the "showcase"
# model in tests/qml/Fixture.js, where every address is from a documentation
# range and every host name ends in .example. tests/test_showcase_fixture.js
# holds the fixture to that.
#
#   tests/qml/make-preview.sh [out.png]     (default: preview.png at the root)
#
# Needs what the harness needs (quickshell, bwrap) and ImageMagick. The text is
# drawn with this machine's sans-serif font, so two machines make two slightly
# different pictures; it is a picture for people, and no check reads it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
out="${1:-$ROOT/preview.png}"
for tool in magick bwrap quickshell; do
  command -v "$tool" >/dev/null 2>&1 || { echo "make-preview: this needs $tool" >&2; exit 1; }
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
shots="overview:normal:normal:normal:tall:::showcase apps:normal:normal:normal:tall:::showcase"
if ! VALLUM_SHOTS="$shots" bash "$ROOT/tests/qml/run-runtime.sh" >"$tmp/run.log" 2>&1; then
  cat "$tmp/run.log" >&2
  echo "make-preview: the harness did not render the panel" >&2
  exit 1
fi
overview="$(awk '$1 == "SHOT" && $2 ~ /shot-overview-/ {print $2}' "$tmp/run.log")"
apps="$(awk '$1 == "SHOT" && $2 ~ /shot-apps-/ {print $2}' "$tmp/run.log")"
[[ -f "$overview" && -f "$apps" ]] || { cat "$tmp/run.log" >&2; echo "make-preview: no pictures came back" >&2; exit 1; }

# Each view is a 560x664 card (the panel at its normal width, cut where a
# scrolling list would be cut), on a 1280x720 canvas.
w=560; h=664; left=53; right=667; top=28
magick -size "${w}x${h}" xc:none -fill white -draw "roundrectangle 0,0,$((w - 1)),$((h - 1)),12,12" "$tmp/mask.png"
for view in overview apps; do
  src="$overview"; [[ "$view" == apps ]] && src="$apps"
  magick "$src" -crop "${w}x${h}+0+0" +repage -alpha set "$tmp/mask.png" -compose DstIn -composite "$tmp/$view.png"
done
magick -size 1280x720 xc:'#0d0d10' \
  "$tmp/overview.png" -geometry "+$left+$top" -compose Over -composite \
  "$tmp/apps.png" -geometry "+$right+$top" -compose Over -composite \
  -fill none -stroke '#34343a' -strokewidth 1 \
  -draw "roundrectangle $((left - 1)),$((top - 1)),$((left + w)),$((top + h)),12,12" \
  -draw "roundrectangle $((right - 1)),$((top - 1)),$((right + w)),$((top + h)),12,12" \
  -alpha off -depth 8 -strip -define png:exclude-chunks=date,time "$out"
echo "make-preview: $out ($(magick identify -format '%wx%h' "$out"))"
