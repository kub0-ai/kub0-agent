#!/usr/bin/env bash
# Print one version's section of CHANGELOG.md, without its heading: the body
# of that version's GitHub Release.
#
#   scripts/release-notes.sh 0.5.1 [<changelog>]
#
# Fails when the changelog has no section for the version, or an empty one: a
# release whose notes say nothing is a release nobody wrote down.
set -euo pipefail
if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 <version> [<changelog>]" >&2
  exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
version="${1#v}"
changelog="${2:-$ROOT/CHANGELOG.md}"
notes="$(awk -v v="$version" '
  /^## / { on = ($2 == v); next }
  on { print }
' "$changelog")"
if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "release-notes: $(basename "$changelog") has no notes under '## $version'" >&2
  exit 1
fi
printf '%s\n' "$notes" | sed -e '/./,$!d'
