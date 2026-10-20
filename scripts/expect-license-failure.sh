#!/usr/bin/env bash
# Asserts check-licenses.sh rejects a fixture AND names the offender (not just any failure).
# usage: expect-license-failure.sh go|js <dir> <expected-substring>
set -euo pipefail

mode="${1:?usage: expect-license-failure.sh go|js <dir> <expected-substring>}"
dir="${2:?missing dir}"
needle="${3:?missing expected substring}"

cd "$(dirname "$0")/.."

status=0
out="$(scripts/check-licenses.sh "$mode" "$dir" 2>&1)" || status=$?

if [ "$status" -ne 1 ]; then
  echo "expected exit 1 from check-licenses.sh $mode $dir, got $status" >&2
  echo "$out" >&2
  exit 1
fi
if ! grep -qF -- "$needle" <<<"$out"; then
  echo "check-licenses.sh $mode $dir failed without mentioning '$needle':" >&2
  echo "$out" >&2
  exit 1
fi
echo "ok: $mode $dir rejected ($needle)"
