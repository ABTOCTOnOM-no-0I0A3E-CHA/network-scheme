#!/usr/bin/env bash
# Demo only: builds everything the server demo needs on THIS machine (Docker, Go, Bun required here) into one archive,
# so the server compiles nothing and keeps no images or build cache of its own:
#   test/demo/bundle.sh [OUT.tar]   (default: test/demo/.bundle/nms-demo-bundle.tar)
# The archive holds the host image, the stack images (loaded straight into the stand's own Docker on the server),
# nmsctl and sshemud for linux/amd64, the simulator files and the seed with its node_modules. See SERVER.md.
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
DEMO=test/demo TAG=demo ARCH="${ARCH:-amd64}"
OUT="${1:-$DEMO/.bundle/nms-demo-bundle.tar}"
STAGE="$DEMO/.bundle/stage"
for cmd in docker go bun tar gzip; do command -v "$cmd" > /dev/null || { echo "$cmd is required"; exit 1; }; done
step() { printf '\n==> %s\n' "$*"; }

DB_IMAGE="$(sed -n 's/^const DefaultDBImage = "\(.*\)"/\1/p' internal/install/render.go)"
BUN_IMAGE="$(sed -n 's/^FROM \(oven\/bun:[^ ]*\) AS web$/\1/p' deploy/docker/gateway.Dockerfile | head -1)"
[ -n "$DB_IMAGE" ] && [ -n "$BUN_IMAGE" ] || { echo "cannot read the pinned images"; exit 1; }

step "Building the images (linux/$ARCH)"
docker build -q --platform "linux/$ARCH" -t nms-demo-host -f "$DEMO/host.Dockerfile" "$DEMO" > /dev/null
docker build -q --platform "linux/$ARCH" -t "nms/api:$TAG" -f deploy/docker/api.Dockerfile . > /dev/null
docker build -q --platform "linux/$ARCH" -t "nms/gateway:$TAG" -f deploy/docker/gateway.Dockerfile . > /dev/null
docker build -q --platform "linux/$ARCH" -t "nms/executor:$TAG" -f deploy/docker/executor.Dockerfile . > /dev/null
docker build -q --platform "linux/$ARCH" -t "nms-snmpsim:$TAG" test/sim/snmpsim > /dev/null
docker image inspect "$DB_IMAGE" > /dev/null 2>&1 || docker pull --platform "linux/$ARCH" "$DB_IMAGE"
docker image inspect "$BUN_IMAGE" > /dev/null 2>&1 || docker pull --platform "linux/$ARCH" "$BUN_IMAGE"
# images pulled by digest have no tag; docker save keeps names by tag, so give them one
docker tag "$DB_IMAGE" "${DB_IMAGE%@*}"
docker tag "$BUN_IMAGE" nms-demo-bun:1

step "Building nmsctl and sshemud"
rm -rf "$STAGE"; mkdir -p "$STAGE/bin" "$STAGE/files" "$(dirname "$OUT")"
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath -o "$STAGE/bin/nmsctl" ./cmd/nmsctl
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath -o "$STAGE/bin/sshemud" ./test/sim/sshemu/sshemud

step "Saving the images"
docker save nms-demo-host | gzip -1 > "$STAGE/host.tar.gz"
docker save "nms/api:$TAG" "nms/gateway:$TAG" "nms/executor:$TAG" "nms-snmpsim:$TAG" "${DB_IMAGE%@*}" nms-demo-bun:1 \
  | gzip -1 > "$STAGE/stack.tar.gz"
printf '%s\n' "$DB_IMAGE" > "$STAGE/db-image"

step "The simulator files and the seed"
cp -r test/fixtures/snmp "$STAGE/files/snmp"
cp -r test/fixtures/configs "$STAGE/files/configs"
cp test/e2e/send_events.py "$STAGE/files/"
for f in devices.sh devices.txt enrich.py; do sed 's/\r$//' "$DEMO/$f" > "$STAGE/files/$f"; done
mkdir -p "$STAGE/seed"
cp "$DEMO/seed.ts" "$DEMO/package.json" "$DEMO/bun.lock" "$STAGE/seed/"
(cd "$STAGE/seed" && bun install --frozen-lockfile --silent)
sed 's/\r$//' "$DEMO/server.sh" > "$STAGE/server.sh"
cp "$DEMO/SERVER.md" "$STAGE/"

tar -cf "$OUT" -C "$STAGE" .
rm -rf "$STAGE"
ls -la "$OUT"
echo "Copy it to the server and run there: mkdir nms-demo && tar -xf $(basename "$OUT") -C nms-demo && cd nms-demo && bash server.sh --domain DEMO.EXAMPLE"
