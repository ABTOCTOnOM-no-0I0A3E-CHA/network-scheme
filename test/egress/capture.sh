#!/usr/bin/env bash
# Zero-egress check for the installed stack (NFR-NET-1, CI job e2e).
#
# usage: capture.sh start|check
#   start  runs tcpdump (nicolaka/netshoot, host network) on the Linux bridge of
#          the stack's "edge" network, the only network with a route out ("core"
#          is internal: true). Packets are written to $EGRESS_DIR/egress.pcap.
#   check  stops the capture and counts IP packets whose DESTINATION is outside
#          every subnet of the stack's docker networks, outside 127.0.0.0/8 and
#          not multicast/broadcast (IPv4 224.0.0.0/4, 255.255.255.255, IPv6
#          multicast). Expected 0; otherwise prints the packets and exits 1.
#
# Filter rationale: on the edge bridge, everything the stack sends to the
# browser/ZAP on this host goes to the bridge gateway address, which lies in
# the edge subnet; anything else is a connection leaving the stack. Not seen
# here: DNS lookups (Docker's embedded resolver forwards them from the host
# namespace), so a lookup alone is not detected - only the connection after it.
set -euo pipefail

PROJECT="${NMS_PROJECT:-nms}"
EGRESS_DIR="${EGRESS_DIR:-/tmp/nms-egress}"
NAME=nms-egress-capture
# nicolaka/netshoot v0.16
IMAGE=nicolaka/netshoot@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70

networks() { docker network ls -q --filter "label=com.docker.compose.project=$PROJECT"; }

case "${1:-}" in
  start)
    edge="$(docker network ls -q --filter "label=com.docker.compose.project=$PROJECT" --filter "label=com.docker.compose.network=edge")"
    [ -n "$edge" ] || { echo "no edge network of project $PROJECT" >&2; exit 1; }
    bridge="$(docker network inspect -f '{{index .Options "com.docker.network.bridge.name"}}' "$edge")"
    [ -n "$bridge" ] || bridge="br-${edge:0:12}"
    mkdir -p "$EGRESS_DIR"
    rm -f "$EGRESS_DIR/egress.pcap"
    docker run -d --name "$NAME" --net host --cap-add NET_RAW --cap-add NET_ADMIN \
      -v "$EGRESS_DIR:/cap" "$IMAGE" tcpdump -i "$bridge" -n -U --immediate-mode -Z root -s 128 -w /cap/egress.pcap >/dev/null
    # tcpdump creates the file once it listens
    for _ in $(seq 1 30); do [ -s "$EGRESS_DIR/egress.pcap" ] && break; sleep 1; done
    [ -s "$EGRESS_DIR/egress.pcap" ] || { docker logs "$NAME" >&2; exit 1; }
    echo "capturing on $bridge"
    ;;
  check)
    docker stop -t 5 "$NAME" >/dev/null
    docker logs "$NAME" 2>&1 | tail -n 3
    docker rm "$NAME" >/dev/null
    # an empty capture would pass vacuously: the tests' traffic to the gateway crosses this bridge
    total="$(docker run --rm -v "$EGRESS_DIR:/cap:ro" "$IMAGE" tcpdump -n -r /cap/egress.pcap 2>/dev/null | wc -l)"
    echo "captured packets: $total"
    [ "$total" -gt 0 ] || { echo "nothing captured: wrong interface?" >&2; exit 1; }
    filter="ip and not dst net 127.0.0.0/8 and not ip multicast and not dst host 255.255.255.255"
    for id in $(networks); do
      for subnet in $(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$id"); do
        filter="$filter and not dst net $subnet"
      done
    done
    filter="($filter) or (ip6 and not ip6 multicast)"
    echo "filter: $filter"
    out="$(docker run --rm -v "$EGRESS_DIR:/cap:ro" "$IMAGE" tcpdump -n -r /cap/egress.pcap "$filter" 2>/dev/null)"
    count=0
    [ -z "$out" ] || count="$(printf '%s\n' "$out" | wc -l)"
    echo "egress packets: $count"
    if [ "$count" -ne 0 ]; then
      printf '%s\n' "$out" | head -n 200
      exit 1
    fi
    ;;
  *)
    echo "usage: $0 start|check" >&2
    exit 2
    ;;
esac
