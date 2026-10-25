#!/usr/bin/env bash
# Demo only: one-command local stand with simulated devices (Windows + Docker Desktop with Git Bash, or Linux).
# Everything runs inside one privileged container with systemd and its own Docker daemon (the "server"): nmsctl install,
# the stack, the device simulators and the event senders, as in the CI job e2e. Only HTTPS (443) is published, because
# Docker Desktop's UDP port publishing breaks SNMP from the host to the simulators. See README.md.
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
DEMO=test/demo RUN=test/demo/.run HOST=nms-demo TAG=demo
step() { printf '\n==> %s\n' "$*"; }
in_host() { docker exec "$HOST" "$@"; }

for cmd in docker go bun; do command -v "$cmd" > /dev/null || { echo "$cmd is required"; exit 1; }; done
if docker container inspect "$HOST" > /dev/null 2>&1; then
  echo "The stand is already there (container $HOST). Run $DEMO/down.sh first."; exit 1
fi

step "Building images (product images with tag $TAG, the host, the simulator)"
docker build -q -t nms-demo-host -f "$DEMO/host.Dockerfile" "$DEMO" > /dev/null
docker build -q -t "nms/api:$TAG" -f deploy/docker/api.Dockerfile . > /dev/null
docker build -q -t "nms/gateway:$TAG" -f deploy/docker/gateway.Dockerfile . > /dev/null
docker build -q -t "nms-snmpsim:$TAG" test/sim/snmpsim > /dev/null
DB_IMAGE="$(sed -n 's/^const DefaultDBImage = "\(.*\)"/\1/p' internal/install/render.go)"
[ -n "$DB_IMAGE" ] || { echo "DefaultDBImage not found in internal/install/render.go"; exit 1; }
docker image inspect "$DB_IMAGE" > /dev/null 2>&1 || docker pull "$DB_IMAGE"

step "Building nmsctl and sshemud"
case "$(docker info -f '{{.Architecture}}')" in aarch64 | arm64) ARCH=arm64 ;; *) ARCH=amd64 ;; esac
mkdir -p "$RUN/bin" "$RUN/creds"
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath -o "$RUN/bin/nmsctl" ./cmd/nmsctl
GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -trimpath -o "$RUN/bin/sshemud" ./test/sim/sshemu/sshemud

step "Starting the host container $HOST (systemd + Docker)"
# /var/lib/docker and /var/lib/containerd are volumes: overlayfs cannot nest, and they keep the loaded images between runs
docker run -d --name "$HOST" --hostname "$HOST" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  --tmpfs /run --tmpfs /run/lock -v nms-demo-docker:/var/lib/docker -v nms-demo-containerd:/var/lib/containerd \
  -p 443:443 nms-demo-host > /dev/null
for _ in $(seq 1 60); do in_host docker info > /dev/null 2>&1 && break; sleep 2; done
in_host docker info > /dev/null
# leftovers of an interrupted run in the cached volume: start from a clean daemon (images stay)
in_host sh -c 'docker rm -f $(docker ps -aq) > /dev/null 2>&1; docker volume prune -af > /dev/null; docker network prune -f > /dev/null'

step "Loading images into the host (only the changed ones)"
for img in "nms/api:$TAG" "nms/gateway:$TAG" "nms-snmpsim:$TAG" "$DB_IMAGE"; do
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
# scripts and tables without CR, whatever the checkout's line endings
for f in devices.sh devices.txt; do sed 's/\r$//' "$DEMO/$f" | docker exec -i "$HOST" sh -c "cat > /opt/demo/$f"; done
in_host install -m 0755 /opt/demo/bin/nmsctl /usr/local/bin/nmsctl
# nmsctl install refuses to run in a container (it looks for /.dockerenv); this container plays the server, so drop the marker
in_host rm -f /.dockerenv

step "nmsctl install (a few minutes)"
# Throwaway credentials of this stand, generated now into the gitignored .run/creds.
head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$RUN/creds/admin-password"
docker cp "$RUN/creds/admin-password" "$HOST:/root/admin-password"
if ! in_host nmsctl install --non-interactive --public-host localhost --admin-user admin \
  --admin-password-file /root/admin-password --totp-secret-out /root/totp-secret --image-tag "$TAG" \
  --mgmt-subnet 172.30.1.0/24 > "$RUN/creds/install.log" 2>&1; then
  grep -vE 'TOTP secret|[█▀▄]|^  [A-Z2-7]{16}$' "$RUN/creds/install.log"; exit 1
fi
docker cp "$HOST:/root/totp-secret" "$RUN/creds/totp-secret"
docker cp "$HOST:/etc/nms/secrets/ca.crt" "$RUN/ca.crt"
in_host rm -f /root/admin-password

step "Starting the simulated devices and event senders"
in_host bash /opt/demo/devices.sh

step "Seeding the demo data through the API"
(cd "$DEMO" && bun install --frozen-lockfile --silent && bun seed.ts)

SECRET="$(cat "$RUN/creds/totp-secret")"
cat <<EOF

The stand is up.
  URL:       https://localhost   (the certificate is signed by the stand's CA: $DEMO/.run/ca.crt)
  Login:     admin
  Password:  $DEMO/.run/creds/admin-password
  TOTP:      $DEMO/.run/creds/totp-secret
             Add it to an authenticator app (Google Authenticator, Aegis, 1Password...) as a key entered
             manually: account "admin", key $SECRET, time-based, 6 digits, 30 s.
             Or scan the QR code in $DEMO/.run/creds/install.log.
  Stop:      $DEMO/down.sh   (--purge also drops the image cache)
EOF
