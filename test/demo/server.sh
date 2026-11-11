#!/usr/bin/env bash
# Demo only: starts the demo stand on a Linux server from the archive test/demo/bundle.sh built elsewhere. The server
# needs only Docker (24+, cgroup v2); it compiles nothing and keeps no images or build cache besides the stand's host
# image. Hard limits keep the stand away from the server's other services:
#   - disk: the stand's own Docker and database live in ONE preallocated file of --disk-gb (default 10) mounted inside
#     the stand; when it is full the stand fails, the server's disk does not fill up;
#   - memory and CPU: --memory (default 2560m, also the swap) and --cpus (default 2) on the stand's container;
#   - its own cgroup namespace (not the host's tree), and no restart on its own after a reboot of the server.
# Run it in the unpacked bundle:  bash server.sh --domain demo.example.com [--listen 0.0.0.0:443]
#   --domain D        DNS name of the panel (required), the exact Origin the panel accepts: open the demo by this name
#   --listen A:P      where the panel is published here (default 0.0.0.0:443; 127.0.0.1:9443 behind a reverse proxy)
#   --disk-gb G       size of the stand's disk file (default 10); --memory M; --cpus N
#   --keep-free-gb G  refuse to start if less than G GB would stay free on Docker's disk (default 5)
#   --down            remove the stand, its disk file and its host image
set -euo pipefail
cd "$(dirname "$0")"
HOST=nms-demo RUN=.run DOMAIN="" LISTEN="0.0.0.0:443" ACTION=up DISK_GB=10 MEMORY=2560m CPUS=2 KEEP_FREE_GB=5
while [ $# -gt 0 ]; do
  case "$1" in
    --domain) DOMAIN="${2:-}"; shift 2 ;;
    --listen) LISTEN="${2:-}"; shift 2 ;;
    --disk-gb) DISK_GB="${2:-}"; shift 2 ;;
    --memory) MEMORY="${2:-}"; shift 2 ;;
    --cpus) CPUS="${2:-}"; shift 2 ;;
    --keep-free-gb) KEEP_FREE_GB="${2:-}"; shift 2 ;;
    --down) ACTION=down; shift ;;
    *) echo "unknown argument: $1"; exit 2 ;;
  esac
done
step() { printf '\n==> %s\n' "$*"; }
in_host() { docker exec "$HOST" "$@"; }
command -v docker > /dev/null || { echo "docker is required"; exit 1; }

if [ "$ACTION" = down ]; then
  if docker container inspect "$HOST" > /dev/null 2>&1; then
    docker exec "$HOST" sh -c 'systemctl stop docker docker.socket containerd; umount /var/lib/docker /var/lib/containerd /mnt/disk' > /dev/null 2>&1 || true
    docker rm -f "$HOST" > /dev/null
    echo "removed container $HOST"
  fi
  docker volume rm -f nms-demo-disk > /dev/null 2>&1 && echo "removed the stand's disk file" || true
  docker image rm nms-demo-host > /dev/null 2>&1 && echo "removed the host image" || true
  rm -rf "$RUN"
  exit 0
fi

[ -n "$DOMAIN" ] || { echo "--domain is required, for example: bash server.sh --domain demo.example.com"; exit 2; }
[[ "$DOMAIN" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || { echo "--domain must be a DNS name"; exit 2; }
[[ "$LISTEN" =~ ^[0-9.]+:[0-9]+$ ]] || { echo "--listen must look like ADDRESS:PORT"; exit 2; }
[[ "$DISK_GB" =~ ^[0-9]+$ && "$KEEP_FREE_GB" =~ ^[0-9]+$ ]] || { echo "--disk-gb and --keep-free-gb are whole GB"; exit 2; }
for f in host.tar.gz stack.tar.gz bin/nmsctl bin/sshemud files/devices.sh seed/seed.ts; do
  [ -e "$f" ] || { echo "$f is missing: run server.sh inside the unpacked bundle of test/demo/bundle.sh"; exit 1; }
done
if docker container inspect "$HOST" > /dev/null 2>&1; then echo "The stand is already there. Run: bash server.sh --down"; exit 1; fi
# the stand's systemd gets a cgroup namespace of its own; on cgroup v1 that is impossible: refuse rather than share the host's
[ "$(docker info -f '{{.CgroupVersion}}')" = 2 ] || { echo "cgroup v2 is required"; exit 1; }
ROOT="$(docker info -f '{{.DockerRootDir}}')"
free_gb="$(df -BG --output=avail "$ROOT" | tail -1 | tr -dc 0-9)"
need=$((DISK_GB + 2 + KEEP_FREE_GB)) # the disk file, the host image (~1 GB) with room, and what must stay free
if [ "${free_gb:-0}" -lt "$need" ]; then
  echo "$free_gb GB free on $ROOT; the stand needs $((DISK_GB + 2)) GB and $KEEP_FREE_GB GB must stay free for the other services"
  echo "(use a smaller --disk-gb, at least 6, or free some space)"
  exit 1
fi

step "Loading the host image"
gunzip -c host.tar.gz | docker load -q

step "Starting the stand ($MEMORY memory, $CPUS CPUs, a $DISK_GB GB disk file), panel on $LISTEN"
docker volume create nms-demo-disk > /dev/null
docker run -d --name "$HOST" --hostname "$HOST" --restart no --privileged --cgroupns=private \
  --memory "$MEMORY" --memory-swap "$MEMORY" --cpus "$CPUS" --tmpfs /run --tmpfs /run/lock \
  -v nms-demo-disk:/data -p "$LISTEN:443" nms-demo-host > /dev/null
for _ in $(seq 1 60); do in_host docker info > /dev/null 2>&1 && break; sleep 2; done
# the stand's Docker and containerd move onto the fixed-size file before anything is loaded: they can never grow past it
in_host sh -euc "
  systemctl stop docker docker.socket containerd
  if [ ! -f /data/disk.img ]; then fallocate -l ${DISK_GB}G /data/disk.img; mkfs.ext4 -q -F /data/disk.img; fi
  mkdir -p /mnt/disk && mount -o loop /data/disk.img /mnt/disk
  mkdir -p /mnt/disk/docker /mnt/disk/containerd
  rm -rf /var/lib/docker/* /var/lib/containerd/*
  mount --bind /mnt/disk/docker /var/lib/docker && mount --bind /mnt/disk/containerd /var/lib/containerd
  systemctl start containerd docker
"
for _ in $(seq 1 60); do in_host docker info > /dev/null 2>&1 && break; sleep 2; done
in_host docker info > /dev/null
in_host df -h /var/lib/docker | tail -1

step "Loading the stack images into the stand (straight onto its disk file)"
gunzip -c stack.tar.gz | docker exec -i "$HOST" docker load -q

step "Copying the simulator files"
in_host mkdir -p /opt/demo/seed/.run/creds
docker cp bin/. "$HOST:/opt/demo/bin/"
docker cp files/. "$HOST:/opt/demo/"
docker cp seed/. "$HOST:/opt/demo/seed/"
in_host install -m 0755 /opt/demo/bin/nmsctl /usr/local/bin/nmsctl
# nmsctl install refuses to run in a container (it looks for /.dockerenv); this container plays the server
in_host rm -f /.dockerenv

step "nmsctl install for $DOMAIN (a few minutes)"
mkdir -p "$RUN/creds"
head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > "$RUN/creds/admin-password"
docker cp "$RUN/creds/admin-password" "$HOST:/root/admin-password"
if ! in_host nmsctl install --non-interactive --public-host "$DOMAIN" --admin-user admin \
  --admin-password-file /root/admin-password --totp-secret-out /root/totp-secret --image-tag demo \
  --mgmt-subnet 172.30.1.0/24 > "$RUN/creds/install.log" 2>&1; then
  grep -vE 'TOTP secret|[█▀▄]|^  [A-Z2-7]{16}$' "$RUN/creds/install.log"; exit 1
fi
docker cp "$HOST:/root/totp-secret" "$RUN/creds/totp-secret"
in_host sh -c 'cp /root/totp-secret /root/admin-password /opt/demo/seed/.run/creds/ && cp /etc/nms/secrets/ca.crt /opt/demo/seed/.run/ && rm -f /root/admin-password'

step "Starting the simulated devices and event senders"
in_host bash /opt/demo/devices.sh

step "Seeding the demo data through the API (inside the stand)"
# the stand's own port 443, reached inside it under the panel's name (the Origin the panel accepts)
in_host docker run --rm --network host --add-host "$DOMAIN:127.0.0.1" -e "DEMO_BASE=https://$DOMAIN" \
  -v /opt/demo/seed:/app -w /app nms-demo-bun:1 bun seed.ts
in_host rm -rf /opt/demo/seed/.run

step "Disk use"
echo "stand's disk file: $(in_host df -h /var/lib/docker | tail -1)"
echo "server:            $(df -h "$ROOT" | tail -1)"

SECRET="$(cat "$RUN/creds/totp-secret")"
cat <<EOF

The demo is up.
  URL:       https://$DOMAIN   (published here on $LISTEN)
  Login:     admin
  Password:  $PWD/$RUN/creds/admin-password
  TOTP:      key $SECRET (time-based, 6 digits, 30 s, account "admin"); the QR code is in $PWD/$RUN/creds/install.log
  Stop:      bash server.sh --down
EOF
