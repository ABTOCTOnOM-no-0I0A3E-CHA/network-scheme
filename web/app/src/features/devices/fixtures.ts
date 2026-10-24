import type { TableRows } from "./api";

type Iface = TableRows["interfaces"];
const SEEN = "2026-10-02T10:00:00Z";

function iface(if_index: number, name: string, port_kind: Iface["port_kind"], speed_bps: number, oper_up = true): Iface {
  return { if_index, name, alias: "", speed_bps, oper_up, seen_at: SEEN, port_kind };
}

function range(n: number, f: (i: number) => Iface): Iface[] {
  return Array.from({ length: n }, (_, i) => f(i + 1));
}

/*
Interface inventories as the API returns them, with the port kinds the generic
classifier (internal/drivers/generic portKind) gives: Ethernet ifTypes with a
gi name are RJ-45, te names and 10G speeds SFP, everything else other.
*/

/** MES2324: 24 copper gigabit ports, 4 10G SFP+ uplinks, plus logical interfaces. */
export const MES_INTERFACES: Iface[] = [
  ...range(24, (i) => iface(48 + i, `gi1/0/${i}`, "rj45", 1e9, i % 3 !== 0)),
  ...range(4, (i) => iface(100 + i, `te1/0/${i}`, "sfp", 1e10, i === 1)),
  iface(1000, "Port-channel1", "other", 0),
  iface(100000, "vlan 1", "other", 0),
  iface(200000, "oob", "other", 1e8),
];

/** ESR-20: 4 copper gigabit ports, 2 SFP ports, plus a bridge and a loopback. */
export const ESR_INTERFACES: Iface[] = [
  ...range(4, (i) => iface(i, `gi1/0/${i}`, "rj45", 1e9, i <= 2)),
  ...range(2, (i) => iface(10 + i, `te1/0/${i}`, "sfp", 1e10, false)),
  iface(50, "bridge 1", "other", 0),
  iface(51, "loopback 1", "other", 0),
];

/** generic-switch fixture (test/fixtures/snmp/generic-switch.snmprec): three ethernetCsmacd 1G ports. */
export const GENERIC_INTERFACES: Iface[] = [iface(1, "Gi1/0/1", "rj45", 1e9, true), iface(2, "Gi1/0/2", "rj45", 1e9, false), iface(3, "Gi1/0/3", "rj45", 1e9, false)];
