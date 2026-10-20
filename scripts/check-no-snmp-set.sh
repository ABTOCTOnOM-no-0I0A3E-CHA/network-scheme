#!/usr/bin/env bash
# Fails if any Go file uses an SNMP SET: gosnmp.SetRequest anywhere, or a ".Set("
# call in any file that imports gosnmp. usage: check-no-snmp-set.sh [dir]
# With a dir argument the directory is scanned as plain files (no git needed).
set -euo pipefail

if [ $# -gt 0 ]; then
  cd "$1"
  mode=(--no-index)
else
  cd "$(dirname "$0")/.."
  mode=(--untracked)
fi

# git grep: 0 = match, 1 = no match, anything else = error (fail closed)
search() {
  local rc=0
  git grep "${mode[@]}" "$@" || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "git grep failed (exit $rc)" >&2
    exit 2
  fi
  return "$rc"
}

status=0
if search -n -E 'gosnmp\.SetRequest' -- '*.go'; then
  status=1
fi
files="$(search -l 'gosnmp/gosnmp' -- '*.go' || true)"
while IFS= read -r f; do
  [ -n "$f" ] || continue
  if search -n -E '\.Set\(' -- "$f"; then
    status=1
  fi
done <<<"$files"

if [ "$status" -ne 0 ]; then
  echo "SNMP SET usage found: automation must be read-only" >&2
fi
exit "$status"
