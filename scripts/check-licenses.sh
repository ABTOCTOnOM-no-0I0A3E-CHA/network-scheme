#!/usr/bin/env bash
# Fails if a dependency uses a license outside the allowlist.
# usage: check-licenses.sh go|js <dir>
set -euo pipefail

ALLOWED="MIT,Apache-2.0,BSD-2-Clause,BSD-3-Clause,ISC,MPL-2.0,PostgreSQL,OFL-1.1,EPL-2.0"

mode="${1:?usage: check-licenses.sh go|js <dir>}"
dir="${2:?usage: check-licenses.sh go|js <dir>}"

case "$mode" in
  go)
    cd "$dir"
    # the project's own module is not a third-party dependency
    go-licenses check ./... --allowed_licenses="$ALLOWED" --ignore "$(go list -m)"
    ;;
  js)
    bunx license-checker-rseidelsohn --start "$dir" --production --excludePrivatePackages --onlyAllow "${ALLOWED//,/;}"
    ;;
  *)
    echo "unknown mode: $mode (expected go or js)" >&2
    exit 2
    ;;
esac
