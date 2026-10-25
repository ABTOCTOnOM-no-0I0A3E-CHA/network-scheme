#!/usr/bin/env bash
# Demo only: removes the stand of up.sh with its data and generated credentials. The volumes with the loaded images
# stay for a faster next run; --purge removes them and the demo images too.
set -euo pipefail
cd "$(dirname "$0")/../.."
HOST=nms-demo TAG=demo
if docker container inspect "$HOST" > /dev/null 2>&1; then
  # the stack, the simulators and their volumes inside the host; the images stay in the cache volume
  docker exec "$HOST" sh -c 'docker rm -f $(docker ps -aq) > /dev/null 2>&1; docker volume prune -af > /dev/null; docker network prune -f > /dev/null' || true
  docker rm -f "$HOST" > /dev/null
  echo "removed container $HOST"
fi
rm -rf test/demo/.run
if [ "${1:-}" = --purge ]; then
  docker volume rm -f nms-demo-docker nms-demo-containerd > /dev/null
  docker image rm -f nms-demo-host "nms/api:$TAG" "nms/gateway:$TAG" "nms-snmpsim:$TAG" > /dev/null 2>&1 || true
  echo "removed the image cache volumes and the demo images"
fi
