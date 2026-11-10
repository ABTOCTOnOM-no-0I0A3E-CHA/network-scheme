#!/usr/bin/env bash
# Demo only: the same stand as up.sh, for a Linux server with a domain. The server needs only Docker (24+) and access
# to Docker Hub: nmsctl and the simulator tools are built and seeded in throwaway containers, so Go and Bun are not
# needed. Run it from the root of the source tree: test/demo/server.sh --domain demo.example.com
#
#   --domain D       DNS name of the panel (required); it must resolve to this server and is checked by the panel
#                    as the exact Origin, so open the demo by this name only
#   --listen A:P     where the panel is published on this server (default 0.0.0.0:443); use 127.0.0.1:9443 when a
#                    reverse proxy with a real certificate of your own terminates TLS in front (see SERVER.md)
#   --down           remove the stand (the image cache volumes stay); --down --purge removes them too
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
DEMO=test/demo RUN=test/demo/.run HOST=nms-demo TAG=demo
DOMAIN="" LISTEN="0.0.0.0:443" ACTION=up PURGE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --listen) LISTEN="${2:-}"; shift 2 ;;
    --down) ACTION=down; shift ;;
    --purge) PURGE=1; shift ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
step() { printf '\n==> %s\n' "$*"; }
in_host() { docker exec "$HOST" "$@"; }
command -v docker > /dev/null || { echo "docker is required"; exit 1; }

if [ "$ACTION" = down ]; then
  if docker container inspect "$HOST" > /dev/null 2>&1; then
    docker exec "$HOST" sh -c 'docker rm -f $(docker ps -aq) > /dev/null 2>&1; docker volume prune -af > /dev/null; docker network prune -f > /dev/null' || true
    docker rm -f "$HOST" > /dev/null
    echo "removed container $HOST"
  fi
  rm -rf "$RUN"
  if [ -n "$PURGE" ]; then
    docker volume rm -f nms-demo-docker nms-demo-containerd nms-demo-gocache nms-demo-gobuild > /dev/null
    docker image rm -f nms-demo-host "nms/api:$TAG" "nms/gateway:$TAG" "nms/executor:$TAG" "nms-snmpsim:$TAG" > /dev/null 2>&1 || true
    echo "removed the cache volumes and the demo images"
  fi
  exit 0
fi

[ -n "$DOMAIN" ] || { echo "--domain is required, for example: $0 --domain demo.example.com"; exit 2; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "--domain must be a DNS name"; exit 2; }
[[ "$LISTEN" =~ ^[0-9.]+:[0-9]+$ ]] || { echo "--listen must look like ADDRESS:PORT"; exit 2; }
PORT="${LISTEN##*:}"
if docker container inspect "$HOST" > /dev/null 2>&1; then
  echo "The stand is already there (container $HOST). Run: $0 --down"; exit 1
fi
case "$(docker info -f '{{.Architecture}}')" in aarch64 | arm64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac
GO_IMAGE="$(sed -n 's/^FROM \(golang:[^ ]*\) AS build$/\1/p' deploy/docker/api.Dockerfile | head -1)"
BUN_IMAGE="$(sed -n 's/^FROM \(oven\/bun:[^ ]*\) AS web$/\1/p' deploy/docker/gateway.Dockerfile | head -1)"
DB_IMAGE="$(sed -n 's/^const DefaultDBImage = "\(.*\)"/\1/p' internal/install/render.go)"
[ -n "$GO_IMAGE" ] && [ -n "$BUN_IMAGE" ] && [ -n "$DB_IMAGE" ] || { echo "cannot read the pinned base images from the Dockerfiles"; exit 1; }

step "Building images (product images with tag $TAG, the host, the simulator); a few minutes the first time"
docker build -q -t nms-demo-host -f "$DEMO/host.Dockerfile" "$DEMO" > /dev/null
docker build -q -t "nms/api:$TAG" -f deploy/docker/api.Dockerfile . > /dev/null
docker build -q -t "nms/gateway:$TAG" -f deploy/docker/gateway.Dockerfile . > /dev/null
docker build -q -t "nms/executor:$TAG" -f deploy/docker/executor.Dockerfile . > /dev/null
docker build -q -t "nms-snmpsim:$TAG" test/sim/snmpsim > /dev/null
docker image inspect "$DB_IMAGE" > /dev/null 2>&1 || docker pull "$DB_IMAGE"
# an image pulled by digest has no tag, and docker save below goes by the tag: give it one (harmless if it exists)
docker tag "$DB_IMAGE" "${DB_IMAGE%@*}"

step "Building nmsctl and sshemud (in a Go container)"
mkdir -p "$RUN/bin" "$RUN/creds"
for target in ./cmd/nmsctl:nmsctl ./test/sim/sshemu/sshemud:sshemud; do
  docker run --rm -v "$PWD:/src" -v nms-demo-gocache:/go/pkg/mod -v nms-demo-gobuild:/root/.cache/go-build -w /src \
    -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=$ARCH -e GOFLAGS=-buildvcs=false "$GO_IMAGE" \
    go build -trimpath -o "/src/$RUN/bin/${target##*:}" "${target%%:*}"
done

step "Starting the host container $HOST (systemd + Docker), panel published on $LISTEN"
# /var/lib/docker and /var/lib/containerd are volumes: overlayfs cannot nest, and they keep the loaded images between runs
docker run -d --name "$HOST" --hostname "$HOST" --restart unless-stopped --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
  -v nms-demo-docker:/var/lib/docker -v nms-demo-containerd:/var/lib/containerd \
  -p "$LISTEN:443" nms-demo-host > /dev/null
for _ in $(seq 1 60); do in_host docker info > /dev/null 2>&1 && break; sleep 2; done
in_host docker info > /dev/null
# leftovers of an earlier stand in the cached volume: its containers restart by themselves when the daemon starts and a
# bind mount of a missing file makes Docker create a directory (e.g. /var/lib/nms/gateway/keys.json), which fails the
# install; so remove the containers first, then the directories, then the unused volumes and networks (the images stay)
in_host sh -c 'docker rm -f $(docker ps -aq) > /dev/null 2>&1; rm -rf /var/lib/nms /etc/nms; docker volume prune -af > /dev/null; docker network prune -f > /dev/null'

step "Loading images into the host (only the changed ones)"
for img in "nms/api:$TAG" "nms/gateway:$TAG" "nms/executor:$TAG" "nms-snmpsim:$TAG" "$DB_IMAGE"; do
  want="$(docker image inspect -f '{{.Id}}' "$img")"
  if [ "$(in_host docker image inspect -f '{{.Id}}' "$img" 2>/dev/null)" != "$want" ]; then
    echo "  $img"
    docker save "${img%@*}" | docker exec -i "$HOST" docker load > /dev/null
  fi
done

step "Copying the simulator files"
in_host mkdir -p /opt/demo
docker cp "$RUN/bin/." "$HOST:/opt/demo/bin/"
docker cp test/fixtures/snmp "$HOST:/opt/demo/snmp"
docker cp test/fixtures/configs "$HOST:/opt/demo/configs"
docker cp test/e2e/send_events.py "$HOST:/opt/demo/send_events.py"
for f in devices.sh devices.txt enrich.py; do sed 's/\r$//' "$DEMO/$f" | docker exec -i "$HOST" sh -c "cat > /opt/demo/$f"; done
in_host install -m 0755 /opt/demo/bin/nmsctl /usr/local/bin/nmsctl
# nmsctl install refuses to run in a container (it looks for /.dockerenv); this container plays the server, so drop the marker
in_host rm -f /.dockerenv

step "nmsctl install for $DOMAIN (a few minutes)"
head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$RUN/creds/admin-password"
docker cp "$RUN/creds/admin-password" "$HOST:/root/admin-password"
if ! in_host nmsctl install --non-interactive --public-host "$DOMAIN" --admin-user admin \
  --admin-password-file /root/admin-password --totp-secret-out /root/totp-secret --image-tag "$TAG" \
  --mgmt-subnet 172.30.1.0/24 > "$RUN/creds/install.log" 2>&1; then
  grep -vE 'TOTP secret|[█▀▄]|^  [A-Z2-7]{16}$' "$RUN/creds/install.log"; exit 1
fi
docker cp "$HOST:/root/totp-secret" "$RUN/creds/totp-secret"
docker cp "$HOST:/etc/nms/secrets/ca.crt" "$RUN/ca.crt"
in_host rm -f /root/admin-password

step "Starting the simulated devices and event senders"
in_host bash /opt/demo/devices.sh

step "Seeding the demo data through the API (in a Bun container)"
BASE="https://$DOMAIN"; [ "$PORT" = 443 ] || BASE="$BASE:$PORT"
# the seed talks to the published port from this server; the name resolves to the loopback so no DNS or firewall is involved
docker run --rm --network host --add-host "$DOMAIN:127.0.0.1" -e "DEMO_BASE=$BASE" -v "$PWD/$DEMO:/app" -w /app "$BUN_IMAGE" \
  sh -c 'bun install --frozen-lockfile --silent && bun seed.ts'

SECRET="$(cat "$RUN/creds/totp-secret")"
cat <<EOF

The demo is up.
  URL:       https://$DOMAIN   (published here on $LISTEN)
  Login:     admin
  Password:  $PWD/$RUN/creds/admin-password
  TOTP:      key $SECRET (time-based, 6 digits, 30 s, account "admin"); the QR code is in $PWD/$RUN/creds/install.log
  CA:        $PWD/$RUN/ca.crt  (the panel's certificate is signed by it; see SERVER.md for a trusted certificate)
  Stop:      $0 --down
EOF
