#!/usr/bin/env bash
# Demo only; runs inside the demo host (up.sh copies it to /opt/demo). Starts one simulator container per line of
# devices.txt on the devices network, as the CI job e2e does: snmpsim answers SNMPv2c (the community is the data file
# name), sshemud serves the CLI of the Eltex models, send_events.py sends syslog and traps to eventd.
set -euo pipefail
D=/opt/demo
NET=nms_devices
IMAGE=nms-snmpsim:demo
# the read account of the simulated CLI: test values, the same in seed.ts
SSH_USER=demo-read SSH_PASSWORD=demo-read-pw

addr() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }
EVENTD="$(addr "$(docker compose -f /etc/nms/compose.yaml ps -q eventd)")"
[ -n "$EVENTD" ] || { echo "eventd has no address on $NET"; exit 1; }

# show_outputs DIR MODEL PROMPT: the outputs sshemud serves, one file per allowlisted command line without arguments
show_outputs() {
  local dir=$1 model=$2 name=${3%#}
  mkdir -p "$dir"
  cp "$D/configs/$model-secrets.txt" "$dir/show running-config"
  : > "$dir/terminal datadump"
  if [ "$model" = mes ]; then
    printf 'Active-image: flash://system/images/mes3300-4108.ros\n  Version: 4.0.21.2\n  Commit: 4b1c6a2e\n  Build: 1 (date 14-Mar-2024 time 11:02:17)\n' > "$dir/show version"
    printf 'System Description:                       MES2324 28-port 1G/10G Managed Switch\nSystem Up Time (days,hour:min:sec):       12,04:31:07\nSystem Contact:                           noc\nSystem Name:                              %s\nSystem Location:                          demo rack 1\nSystem MAC Address:                       e8:28:c1:00:00:11\nSystem Object ID:                         1.3.6.1.4.1.89.6.1.4\n' "$name" > "$dir/show system"
    printf 'Vlan       Name                Tagged Ports     UnTagged Ports   Created by\n---- ----------------- ------------------ ---------------- ----------\n 1           1                                gi1/0/3-24        D\n 10        users             gi1/0/1-2        gi1/0/5-12        S\n 20        voice             gi1/0/1-2                          S\n 99        mgmt              gi1/0/1                            S\n' > "$dir/show vlan"
  else
    printf 'Boot version:\n  1.23.3.2 (date 27/03/2024 time 21:13:26)\nSW version:\n  1.23.3 build 3[a1b2c3d4] (date 27/03/2024 time 21:13:26)\nHW version:\n  2v1\n' > "$dir/show version"
    printf 'System type:           Eltex ESR-1000 Service Router\nSystem name:           %s\nSoftware version:      1.23.3 build 3 (date 27/03/2024 time 21:13:26)\nHardware version:      2v1\nSystem uptime:         21 days, 7 hours, 12 minutes and 40 seconds\nSystem MAC address:    e8:28:c1:00:00:12\nSystem serial number:  NP00000012\n' "$name" > "$dir/show system"
  fi
  printf 'Port        Type         Duplex  Speed Neg      Flow  Link   Back   Mdix\n                                                ctrl  State  Pressure Mode\n----------- ------------ ------  ----- -------- ----  ------ -------- ----\ngi1/0/1     1G-Copper    Full    1000  Enabled  Off   Up     Disabled On\ngi1/0/2     1G-Copper    Full    1000  Enabled  Off   Up     Disabled On\ngi1/0/3     1G-Copper    --      --    --       --    Down   --       --\ngi1/0/4     1G-Copper    Full    100   Enabled  Off   Up     Disabled Off\n' > "$dir/show interfaces status"
  printf 'Aging time is 300 sec\n\n  Vlan        Mac Address         Port       Type\n-------- --------------------- ---------- ----------\n   1      e8:28:c1:00:00:11     0          self\n   10     00:1a:2b:3c:4d:01     gi1/0/5    dynamic\n   10     00:1a:2b:3c:4d:02     gi1/0/6    dynamic\n   99     e8:28:c1:00:00:12     gi1/0/1    dynamic\n' > "$dir/show mac address-table"
  printf '  Interface    IP address        HW address          status\n------------ --------------- ------------------- ---------\nvlan 99      172.30.1.1        02:42:ac:1e:01:01   dynamic\nvlan 10      10.10.10.25       00:1a:2b:3c:4d:01   dynamic\n' > "$dir/show arp"
  printf 'Device ID           Local Port      System Name     Port ID         Capabilities\n------------------- --------------- --------------- --------------- ------------\ne8:28:c1:00:00:12   gi1/0/1         esr-edge-1      gi1/0/1         R\n' > "$dir/show lldp neighbors"
  printf 'Codes: C - connected, S - static, O - OSPF\n\nS     0.0.0.0/0 [1/0] via 172.30.1.1, vlan 99\nC     172.30.1.0/24 is directly connected, vlan 99\nC     10.10.10.0/24 is directly connected, vlan 10\n' > "$dir/show ip route"
}

ready() { local logs; logs="$(docker logs "$1" 2>&1)"; grep -q 'Listening at UDP/IPv4 endpoint' <<<"$logs" && { [ "$2" = - ] || grep -q 'sshemud listening' <<<"$logs"; }; }

while read -r name address fixture community ssh events <&3; do
  [ "$fixture" = - ] && continue
  c="nms-demo-$name"
  args=(-d --name "$c" --network "$NET" --ip "$address" -v "$D/snmp/$fixture.snmprec:/data/$community.snmprec:ro" -v "$D/send_events.py:/send_events.py:ro")
  sshd=""
  if [ "$ssh" != - ]; then
    show_outputs "$D/ssh-$name" "$ssh" "$name#"
    args+=(-v "$D/ssh-$name:/ssh:ro" -v "$D/bin/sshemud:/sshemud:ro")
    sshd="/sshemud -prompt '$name#' -user $SSH_USER -password $SSH_PASSWORD -dir /ssh & "
  fi
  docker run "${args[@]}" "$IMAGE" sh -c "$sshd"'mkdir -p /tmp/idx && chmod 777 /tmp/idx && exec snmpsim-command-responder \
    --process-user=nobody --process-group=nogroup --cache-dir=/tmp/idx --data-dir=/data --agent-udpv4-endpoint=0.0.0.0:161' > /dev/null
  for _ in $(seq 1 60); do ready "$c" "$ssh" && break; sleep 1; done
  ready "$c" "$ssh" || { docker logs "$c"; exit 1; }
  marker="demo${name//[^a-z0-9]/}" # one word: event search matches whole words
  case "$events" in
    syslog) docker exec -d "$c" python3 /send_events.py "$EVENTD" "$marker" ;;
    # the control file makes send_events.py send its trap for TRAP_IFINDEX (2, down in the fixture) instead of ifIndex 1,
    # so the polls the trap causes agree with it and the problem stays open
    trap) docker exec "$c" sh -c 'echo linkDown > /tmp/trap-control'
          docker exec -d -e TRAP_CONTROL=/tmp/trap-control -e TRAP_IFINDEX=2 "$c" python3 /send_events.py "$EVENTD" "$marker" "$community" ;;
  esac
  echo "  $name at $address: $fixture, ssh $ssh, events $events"
done 3< <(grep -vE '^\s*(#|$)' "$D/devices.txt")
