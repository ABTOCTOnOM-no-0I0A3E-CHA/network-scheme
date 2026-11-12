#!/usr/bin/env bash
# Builds the UNSIGNED update bundle of nmsctl update from the images nms/{api,gateway,executor}:TAG
# already in the local Docker: OUT/nms-TAG.tar = manifest.json (first) + one "docker save" per image.
# Signing is offline, by the maintainer: scripts/sign-bundle.sh. MIN_SCHEMA (default 1) is the
# oldest schema version the bundle upgrades; the target is the newest migration in the tree.
# usage: build-bundle.sh TAG OUT
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 TAG OUT" >&2; exit 2; }
tag=$1 out=$2
[[ $tag =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || { echo "bad tag: $tag" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
to=$(ls "$root"/internal/store/migrations/*.sql | sed -E 's|.*/0*([0-9]+)_[^/]*$|\1|' | sort -n | tail -1)
from=${MIN_SCHEMA:-1}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/images"
images=""
for name in api gateway executor; do
  docker save -o "$work/images/$name.tar" "nms/$name:$tag"
  sum=$(sha256sum "$work/images/$name.tar" | cut -d' ' -f1)
  images+="${images:+,}{\"ref\":\"nms/$name:$tag\",\"file\":\"images/$name.tar\",\"sha256\":\"$sum\"}"
done
printf '{"format":1,"version":"%s","image_tag":"%s","schema":{"from":%d,"to":%d},"images":[%s]}\n' \
  "$tag" "$tag" "$from" "$to" "$images" > "$work/manifest.json"

mkdir -p "$out"
tar -C "$work" -cf "$out/nms-$tag.tar" manifest.json images/api.tar images/gateway.tar images/executor.tar
echo "$out/nms-$tag.tar (unsigned; sign offline with scripts/sign-bundle.sh)"
