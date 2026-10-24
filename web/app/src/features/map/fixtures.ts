import type { Topology } from "./semanticZoom";

type N = Topology["nodes"][number];
type L = Topology["links"][number];
type A = Topology["areas"][number];

export const node = (id: number, o: Partial<N> = {}): N => ({ device_id: id, name: `sw${id}`, state: "up", driver: "eltex-mes", pinned: false, ...o });
export const link = (id: number, a: number, b: number, o: Partial<L> = {}): L => ({
  id,
  a,
  b,
  a_if: 1,
  b_if: 2,
  a_port_name: "gi1/0/1",
  b_port_name: "gi1/0/2",
  speed_bps: 1e9,
  source: "lldp",
  confidence: 1,
  manual: false,
  ...o,
});
export const area = (id: number, o: Partial<A> = {}): A => ({
  id,
  parent_id: null,
  kind: "building",
  name: `area${id}`,
  x: 0,
  y: 0,
  w: 100,
  h: 100,
  device_count: 0,
  states: { up: 0, partial: 0, down: 0, unknown: 0 },
  status: "up",
  ...o,
});
