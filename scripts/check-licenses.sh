#!/usr/bin/env bash
# Fails if a dependency uses a license outside the allowlist.
# usage: check-licenses.sh go|js <dir>
set -euo pipefail

ALLOWED="MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,PostgreSQL,OFL-1.1,EPL-2.0,Unlicense,0BSD"

mode="${1:?usage: check-licenses.sh go|js <dir>}"
dir="${2:?usage: check-licenses.sh go|js <dir>}"

case "$mode" in
  go)
    cd "$dir"
    # the project's own module is not a third-party dependency
    go-licenses check ./... --allowed_licenses="$ALLOWED" --ignore "$(go list -m)"
    ;;
  js)
    # exclude only the scanned project itself (private, so "UNLICENSED"); every dependency stays checked
    root="$(bun -e 'const p=require(process.argv[1]);console.log(p.name+"@"+p.version)' "$(cd "$dir" && pwd)/package.json")"
    # a Bun workspace member keeps its dependencies in the workspace root: scan through a directory that links them
    start="$(bun "$(dirname "$0")/license-start.ts" "$dir")"
    trap 'bun "$(dirname "$0")/license-start.ts" --clean "$start"' EXIT
    bunx license-checker-rseidelsohn@5.0.1 --start "$start" --production --excludePackages "$root" --onlyAllow "${ALLOWED//,/;}"
    # a scan that found nothing would pass vacuously (dependencies not installed, or not where the checker looks)
    found="$(bunx license-checker-rseidelsohn@5.0.1 --start "$start" --production --excludePackages "$root" --json | bun -e 'console.log(Object.keys(JSON.parse(await Bun.stdin.text())).length)')"
    if [ "$found" -eq 0 ]; then
      echo "check-licenses: no dependencies found for $dir (run bun install first)" >&2
      exit 1
    fi
    ;;
  *)
    echo "unknown mode: $mode (expected go or js)" >&2
    exit 2
    ;;
esac
