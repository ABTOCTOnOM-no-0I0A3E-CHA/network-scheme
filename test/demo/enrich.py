#!/usr/bin/env python3
# Demo only; runs inside the demo host in the simulator image (devices.sh). Writes stand copies of the Eltex fixtures with
# what a live device has and the shared fixtures leave out: moving 64-bit traffic counters on the ports that are up
# (snmpsim's numeric variation, a steady rate per port), and the forwarding, VLAN, LLDP, ARP and route tables, with an
# LLDP link between mes-access-1 and esr-edge-1 so the map shows it. The shared fixtures in test/fixtures stay as they
# are (the Go simulator and the e2e tests read them). Usage: enrich.py SRC_DIR DST_DIR
import os
import sys

SRC, DST = sys.argv[1], sys.argv[2]
IF_OPER = "1.3.6.1.2.1.2.2.1.8."
HC_IN, HC_OUT = "1.3.6.1.2.1.31.1.1.1.6.", "1.3.6.1.2.1.31.1.1.1.10."
LLDP_LOC = "1.0.8802.1.1.2.1.3.7.1."
LLDP_REM = "1.0.8802.1.1.2.1.4.1.1."
LLDP_MAN = "1.0.8802.1.1.2.1.4.2.1.3.0."


def octets(s):
    return ".".join(str(int(x)) for x in s.split("."))


def mac_oid(mac):
    return ".".join(str(int(b, 16)) for b in mac.split(":"))


def mac_hex(mac):
    return mac.replace(":", "")


def lldp(lport, ifname, peer_name, peer_port, peer_mac, peer_ip):
    """The local port row and one neighbour on it (time mark 0, index 1)."""
    i = f"0.{lport}.1"
    return [
        f"{LLDP_LOC}2.{lport}|2|5",
        f"{LLDP_LOC}3.{lport}|4|{ifname}",
        f"{LLDP_REM}4.{i}|2|4",
        f"{LLDP_REM}5.{i}|4x|{mac_hex(peer_mac)}",
        f"{LLDP_REM}6.{i}|2|5",
        f"{LLDP_REM}7.{i}|4|{peer_port}",
        f"{LLDP_REM}8.{i}|4|uplink",
        f"{LLDP_REM}9.{i}|4|{peer_name}",
        f"{LLDP_MAN}{lport}.1.1.4.{octets(peer_ip)}|2|2",
    ]


def arp(ifindex, ip, mac):
    return f"1.3.6.1.2.1.4.35.1.4.{ifindex}.1.4.{octets(ip)}|4x|{mac_hex(mac)}"


def route(dest, plen, nh, ifindex, proto):
    return f"1.3.6.1.2.1.4.24.7.1.7.1.4.{octets(dest)}.{plen}.2.0.0.1.4.{octets(nh)}|2|{ifindex}", f"1.3.6.1.2.1.4.24.7.1.9.1.4.{octets(dest)}.{plen}.2.0.0.1.4.{octets(nh)}|2|{proto}"


MES_MAC, ESR_MAC = "e8:28:c1:00:00:11", "e8:28:c1:00:00:12"
EXTRA = {
    "eltex-mes": {
        "sysname": "mes-access-1",
        "rows": [
            # bridge port n is ifIndex n; VLANs with their FDB ids; learned MACs on the access ports and the uplink
            *[f"1.3.6.1.2.1.17.1.4.1.2.{n}|2|{n}" for n in range(1, 29)],
            *[f"1.3.6.1.2.1.17.7.1.4.2.1.3.0.{v}|66|{v}" for v in (1, 10, 20, 99)],
            *[f"1.3.6.1.2.1.17.7.1.4.3.1.1.{v}|4|{name}" for v, name in ((1, "default"), (10, "users"), (20, "voice"), (99, "mgmt"))],
            *[
                f"1.3.6.1.2.1.17.7.1.2.2.1.2.{v}.{mac_oid(m)}|2|{p}"
                for v, m, p in (
                    (99, ESR_MAC, 1),
                    (10, "00:1a:2b:3c:4d:01", 5),
                    (10, "00:1a:2b:3c:4d:02", 6),
                    (10, "00:1a:2b:3c:4d:08", 8),
                    (20, "00:0e:08:aa:10:11", 11),
                    (20, "00:0e:08:aa:10:12", 12),
                    (10, "00:1a:2b:3c:4d:15", 15),
                    (10, "00:1a:2b:3c:4d:17", 17),
                    (10, "00:1a:2b:3c:4d:20", 20),
                    (99, "02:42:ac:1e:01:0d", 2),
                )
            ],
            *lldp(1, "gi1/0/1", "esr-edge-1", "gi1/0/1", ESR_MAC, "172.30.1.12"),
            arp(1, "172.30.1.1", "02:42:ac:1e:01:01"),
            arp(1, "172.30.1.12", ESR_MAC),
            arp(5, "10.10.10.25", "00:1a:2b:3c:4d:01"),
            arp(6, "10.10.10.26", "00:1a:2b:3c:4d:02"),
            *route("0.0.0.0", 0, "172.30.1.12", 1, 3),
            *route("172.30.1.0", 24, "0.0.0.0", 1, 2),
            *route("10.10.10.0", 24, "0.0.0.0", 5, 2),
        ],
    },
    "eltex-esr": {
        "sysname": "esr-edge-1",
        "rows": [
            *lldp(1, "gi1/0/1", "mes-access-1", "gi1/0/1", MES_MAC, "172.30.1.11"),
            arp(1, "172.30.1.11", MES_MAC),
            arp(2, "198.51.100.1", "00:00:5e:00:01:01"),
            arp(3, "10.20.0.2", "00:1a:2b:3c:5e:02"),
            *route("0.0.0.0", 0, "198.51.100.1", 2, 3),
            *route("10.10.10.0", 24, "172.30.1.11", 1, 13),
            *route("172.30.1.0", 24, "0.0.0.0", 1, 2),
            *route("198.51.100.0", 30, "0.0.0.0", 2, 2),
        ],
    },
}


def key(line):
    return tuple(int(x) for x in line.split("|", 1)[0].split("."))


def enrich(lines, extra):
    up = {line.split("|")[0][len(IF_OPER):] for line in lines if line.startswith(IF_OPER) and line.endswith("|1")}
    out = []
    for line in lines:
        oid, tag, value = line.split("|", 2)
        for col, share in ((HC_IN, 1.0), (HC_OUT, 0.55)):
            idx = oid[len(col):] if oid.startswith(col) else None
            if idx in up and tag == "70":
                n = int(idx)
                # bytes per second: the uplink busiest, the access ports 4-90 Mbit/s, SFP+ ports several hundred
                mbit = 380 if n == 1 else (120 + n * 9) if n > 24 else 4 + (n * 37) % 86
                line = f"{oid}|70:numeric|initial={value},rate={int(mbit * 125000 * share)}"
        if oid == "1.3.6.1.2.1.1.5.0":
            line = f"{oid}|4|{extra['sysname']}"
        out.append(line)
    out += extra["rows"]
    return sorted(out, key=key)


os.makedirs(DST, exist_ok=True)
for f in os.listdir(SRC):
    if not f.endswith(".snmprec"):
        continue
    with open(os.path.join(SRC, f), encoding="utf-8") as fh:
        lines = [x.rstrip("\r\n") for x in fh if x.strip()]
    name = f[: -len(".snmprec")]
    if name in EXTRA:
        lines = enrich(lines, EXTRA[name])
    with open(os.path.join(DST, f), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
