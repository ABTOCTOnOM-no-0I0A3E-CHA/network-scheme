#!/usr/bin/env bash
# Fails if any cmd/* binary except cmd/executor depends on cmd/executor/* packages.
set -euo pipefail

dir="${1:?usage: check-isolation.sh <module-dir>}"
cd "$dir"

module="$(go list -m)"
status=0

for d in cmd/*/; do
  [ -d "$d" ] || continue
  name="$(basename "$d")"
  [ "$name" = "executor" ] && continue
  while IFS= read -r pkg; do
    case "$pkg" in
      "$module"/cmd/executor/*)
        echo "isolation violation: cmd/$name depends on ${pkg#"$module"/}" >&2
        status=1
        ;;
    esac
  done < <(go list -deps "./cmd/$name" | tr -d '\r')
done

exit "$status"
