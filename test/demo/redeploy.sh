#!/usr/bin/env bash
# Demo only: rebuilds the product images (api, poller, eventd, migrate share nms/api; the web bundle is in nms/gateway)
# from the current checkout and restarts what changed inside the running stand of up.sh, without a reinstall: data,
# credentials and simulators stay. A new migration runs, because compose recreates the migrate service with the image.
# Usage: test/demo/redeploy.sh [api|gateway]...   (default: both)
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
HOST=nms-demo TAG=demo COMPOSE=/etc/nms/compose.yaml
docker container inspect "$HOST" > /dev/null 2>&1 || { echo "No stand (container $HOST): run test/demo/up.sh first."; exit 1; }

targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(api gateway)
changed=0
for t in "${targets[@]}"; do
  case "$t" in api | gateway) ;; *) echo "unknown image $t (api or gateway)"; exit 1 ;; esac
  img="nms/$t:$TAG"
  echo "==> building $img"
  docker build -q -t "$img" -f "deploy/docker/$t.Dockerfile" . > /dev/null
  if [ "$(docker exec "$HOST" docker image inspect -f '{{.Id}}' "$img" 2>/dev/null)" != "$(docker image inspect -f '{{.Id}}' "$img")" ]; then
    echo "    loading into the stand"
    docker save "$img" | docker exec -i "$HOST" docker load > /dev/null
    changed=1
  else
    echo "    unchanged"
  fi
done
[ "$changed" = 1 ] || { echo "Nothing changed."; exit 0; }

echo "==> restarting the changed services"
# compose recreates exactly the containers whose image changed (migrate first: the services depend on it)
docker exec "$HOST" docker compose -f "$COMPOSE" up -d --wait --wait-timeout 300
docker exec "$HOST" docker image prune -f > /dev/null
docker exec "$HOST" docker compose -f "$COMPOSE" ps --format '{{.Service}}\t{{.Status}}'
