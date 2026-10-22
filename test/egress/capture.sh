#!/usr/bin/env bash
# Zero-egress check for the installed stack (NFR-NET-1, CI job e2e).
#
# usage: capture.sh start|check
#   start  runs tcpdump (nicolaka/netshoot, host network) on the Linux bridges of
#          the stack's "edge" and "devices" networks, the only networks with a
#          route out ("core" is internal: true). Packets are written to
#          $EGRESS_DIR/<network>.pcap.
#   check  stops the captures and counts IP packets leaving the stack:
#          edge     DESTINATION outside every subnet of the stack's docker
#                   networks, outside 127.0.0.0/8 and not multicast/broadcast
#                   (IPv4 224.0.0.0/4, 255.255.255.255, IPv6 multicast);
#          devices  DESTINATION outside the devices subnet (the CI management
#                   subnet) and not multicast/broadcast: the poller may talk to
#                   the simulated device only.
#          Expected 0 on both; otherwise prints the packets and exits 1.
#
# Filter rationale: on the edge bridge, everything the stack sends to the
# browser/ZAP on this host goes to the bridge gateway address, which lies in
# the edge subnet; anything else is a connection leaving the stack. On the
# devices bridge the bridge is promiscuous under tcpdump, so the poller's
# traffic to the simulator is captured too (an empty capture fails). Packets
# dropped later by the DOCKER-USER rules still count. Not seen here: DNS
# lookups (Docker's embedded resolver forwards them from the host namespace),
# so a lookup alone is not detected - only the connection after it.
set -euo pipefail

PROJECT="${NMS_PROJECT:-nms}"
EGRESS_DIR="${EGRESS_DIR:-/tmp/nms-egress}"
NAME=nms-egress-capture
# nicolaka/netshoot v0.16
IMAGE=nicolaka/netshoot@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70
CAPTURED=(edge devices)

networks() { docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" "$@"; }
network() { networks --filter "label=com.docker.compose.network=$1"; }
subnets() { docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$1"; }

# count NET FILTER: prints the packets of NET.pcap matching FILTER, returns their number in $count
count() {
  local out
  echo "$1 filter: $2"
  out="$(docker run --rm -v "$EGRESS_DIR:/cap:ro" "$IMAGE" tcpdump -n -r "/cap/$1.pcap" "$2" 2>/dev/null)"
  count=0
  [ -z "$out" ] || count="$(printf '%s\n' "$out" | wc -l)"
  echo "$1 egress packets: $count"
  [ "$count" -eq 0 ] || printf '%s\n' "$out" | head -n 200
}

case "${1:-}" in
  start)
    mkdir -p "$EGRESS_DIR"
    for net in "${CAPTURED[@]}"; do
      id="$(network "$net")"
      [ -n "$id" ] || { echo "no $net network of project $PROJECT" >&2; exit 1; }
      bridge="$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$id")"
      [ -n "$bridge" ] || bridge="br-${id:0:12}"
      rm -f "$EGRESS_DIR/$net.pcap"
      docker run -d --name "$NAME-$net" --net host --cap-add NET_RAW --cap-add NET_ADMIN \
        -v "$EGRESS_DIR:/cap" "$IMAGE" tcpdump -i "$bridge" -n -U --immediate-mode -Z root -s 128 -w "/cap/$net.pcap" >/dev/null
      # tcpdump creates the file once it listens
      for _ in $(seq 1 30); do [ -s "$EGRESS_DIR/$net.pcap" ] && break; sleep 1; done
      [ -s "$EGRESS_DIR/$net.pcap" ] || { docker logs "$NAME-$net" >&2; exit 1; }
      echo "capturing $net on $bridge"
    done
    ;;
  check)
    for net in "${CAPTURED[@]}"; do
      docker stop -t 5 "$NAME-$net" >/dev/null
      docker logs "$NAME-$net" 2>&1 | tail -n 3
      docker rm "$NAME-$net" >/dev/null
      # an empty capture would pass vacuously: the tests' traffic crosses both bridges
      total="$(docker run --rm -v "$EGRESS_DIR:/cap:ro" "$IMAGE" tcpdump -n -r "/cap/$net.pcap" 2>/dev/null | wc -l)"
      echo "$net captured packets: $total"
      [ "$total" -gt 0 ] || { echo "nothing captured on $net: wrong interface?" >&2; exit 1; }
    done

    base="ip and not ip multicast and not dst host 255.255.255.255"
    filter="$base and not dst net 127.0.0.0/8"
    for id in $(networks); do
      for subnet in $(subnets "$id"); do filter="$filter and not dst net $subnet"; done
    done
    count edge "($filter) or (ip6 and not ip6 multicast)"
    edge=$count

    filter="$base"
    for subnet in $(subnets "$(network devices)"); do filter="$filter and not dst net $subnet"; done
    count devices "($filter) or (ip6 and not ip6 multicast)"
    [ "$edge" -eq 0 ] && [ "$count" -eq 0 ] || exit 1
    ;;
  *)
    echo "usage: $0 start|check" >&2
    exit 2
    ;;
esac
