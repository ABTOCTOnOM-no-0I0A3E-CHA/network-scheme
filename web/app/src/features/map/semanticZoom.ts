import type { components } from "@/api/schema";
import type { EventSeverity } from "@/features/problems/api";
import { safeText } from "@/lib/text";
import { iconKey, iconUri, linkStyle, SEVERITY_COLOR, STATE_COLOR, worseState, type NodeState } from "./style";

type S = components["schemas"];
export type Topology = S["Topology"];
type Area = S["TopologyArea"];

/* Hysteresis around the threshold, so a zoom level near it does not flip the view on every wheel tick. */
export const COLLAPSE_BELOW = 0.3;
export const EXPAND_ABOVE = 0.4;
/* Zoom a collapsed area is opened to when it is clicked: safely above EXPAND_ABOVE. */
export const OPEN_ZOOM = 0.55;

/** Whether areas are collapsed at this zoom, given whether they were collapsed before. */
export function isCollapsed(prev: boolean, zoom: number): boolean {
  if (zoom < COLLAPSE_BELOW) return true;
  if (zoom > EXPAND_ABOVE) return false;
  return prev;
}

export type ModelNode = {
  id: string;
  kind: "device" | "area" | "group";
  parent?: string;
  /* the cytoscape data of the node, strings already made safe */
  data: Record<string, unknown>;
  /* absent = the node still needs a layout */
  pos?: { x: number; y: number };
  deviceId?: number;
  areaId?: number;
};
export type ModelEdge = { id: string; source: string; target: string; data: Record<string, unknown> };
export type MapModel = { nodes: ModelNode[]; edges: ModelEdge[] };

/** Client-side state not yet on the server: positions from a layout or a drag, and pins set by a drag. */
export type Overrides = { pos?: ReadonlyMap<number, { x: number; y: number }>; pinned?: ReadonlySet<number> };

export const deviceEid = (id: number) => `d${id}`;
export const areaEid = (id: number) => `a${id}`;
export const groupEid = (id: number) => `g${id}`;

const MAX_DEPTH = 64;

/** Top-level ancestor of each area (itself when it has no parent); cycles cannot exist server-side but are cut anyway. */
function rootOf(byId: Map<number, Area>): Map<number, number> {
  const out = new Map<number, number>();
  for (const a of byId.values()) {
    let cur = a;
    for (let i = 0; i < MAX_DEPTH && cur.parent_id !== null && byId.has(cur.parent_id); i++) cur = byId.get(cur.parent_id)!;
    out.set(a.id, cur.id);
  }
  return out;
}

/** Areas ordered so parents come before their children (cytoscape needs the parent to exist when a child is added). */
function parentsFirst(byId: Map<number, Area>): Area[] {
  const depth = (a: Area): number => {
    let d = 0;
    for (let cur = a; cur.parent_id !== null && byId.has(cur.parent_id) && d < MAX_DEPTH; d++) cur = byId.get(cur.parent_id)!;
    return d;
  };
  return [...byId.values()].sort((x, y) => depth(x) - depth(y) || x.id - y.id);
}

const SEVERITY_ORDER: EventSeverity[] = ["info", "warning", "average", "high", "disaster"];

/** Worst open-problem severity per device. */
export function severityByDevice(problems: { device_id: number | null; severity: EventSeverity }[]): Map<number, EventSeverity> {
  const m = new Map<number, EventSeverity>();
  for (const p of problems) {
    const cur = m.get(p.device_id ?? -1);
    if (p.device_id !== null && (cur === undefined || SEVERITY_ORDER.indexOf(p.severity) > SEVERITY_ORDER.indexOf(cur))) m.set(p.device_id, p.severity);
  }
  return m;
}

/**
 * Builds what the map shows. Expanded: areas are compound nodes around their devices (an area without devices is a plain
 * rectangle at its stored position). Collapsed (low zoom): every top-level area becomes one node with the area's aggregate
 * status and device count, devices outside areas stay, and links between collapsed groups merge into one edge.
 */
export function buildModel(topo: Topology, collapsed: boolean, severity: ReadonlyMap<number, EventSeverity>, ov: Overrides = {}): MapModel {
  const nodes: ModelNode[] = [];
  const edges: ModelEdge[] = [];
  const byId = new Map(topo.areas.map((a) => [a.id, a]));
  const roots = rootOf(byId);
  const devices = new Map(topo.nodes.map((n) => [n.device_id, n]));

  /* an area is a compound when anything lives under it */
  const hasChild = new Set<number>();
  for (const n of topo.nodes) {
    let a = n.area_id;
    for (let i = 0; a !== undefined && byId.has(a) && i < MAX_DEPTH; i++) {
      hasChild.add(a);
      a = byId.get(a)!.parent_id ?? undefined;
    }
  }
  for (const a of topo.areas) if (a.parent_id !== null && byId.has(a.parent_id)) hasChild.add(a.parent_id);

  const deviceGroup = new Map<number, string>();
  if (collapsed) {
    for (const n of topo.nodes) if (n.area_id !== undefined && roots.has(n.area_id)) deviceGroup.set(n.device_id, groupEid(roots.get(n.area_id)!));
    for (const a of byId.values()) {
      if (roots.get(a.id) !== a.id) continue;
      nodes.push({
        id: groupEid(a.id),
        kind: "group",
        areaId: a.id,
        pos: { x: a.x + a.w / 2, y: a.y + a.h / 2 },
        data: { kind: "group", label: `${safeText(a.name)} (${a.device_count})`, color: STATE_COLOR[a.status], icon: iconUri("area"), ring: 0, ringColor: "#000", w: 120, h: 64, pinned: false },
      });
    }
  } else {
    for (const a of parentsFirst(byId)) {
      const leaf = !hasChild.has(a.id);
      nodes.push({
        id: areaEid(a.id),
        kind: "area",
        areaId: a.id,
        parent: a.parent_id !== null && byId.has(a.parent_id) ? areaEid(a.parent_id) : undefined,
        pos: leaf ? { x: a.x + a.w / 2, y: a.y + a.h / 2 } : undefined,
        data: { kind: "area", label: `${safeText(a.name)} (${a.device_count})`, color: STATE_COLOR[a.status], icon: iconUri("area"), ring: 0, ringColor: "#000", w: Math.max(a.w, 1), h: Math.max(a.h, 1), pinned: false },
      });
    }
  }

  for (const n of topo.nodes) {
    if (deviceGroup.has(n.device_id)) continue;
    const sev = severity.get(n.device_id);
    nodes.push({
      id: deviceEid(n.device_id),
      kind: "device",
      deviceId: n.device_id,
      parent: !collapsed && n.area_id !== undefined && byId.has(n.area_id) ? areaEid(n.area_id) : undefined,
      pos: ov.pos?.get(n.device_id) ?? (n.x !== undefined && n.y !== undefined ? { x: n.x, y: n.y } : undefined),
      data: {
        kind: "device",
        label: safeText(n.name),
        color: STATE_COLOR[n.state],
        icon: iconUri(iconKey(n.driver)),
        ring: sev ? 3 : 0,
        ringColor: sev ? SEVERITY_COLOR[sev] : "#000",
        pinned: n.pinned || (ov.pinned?.has(n.device_id) ?? false),
      },
    });
  }

  const merged = new Map<string, { source: string; target: string; state: NodeState; count: number }>();
  for (const l of topo.links) {
    const na = devices.get(l.a);
    const nb = devices.get(l.b);
    if (!na || !nb) continue;
    const a = deviceGroup.get(l.a) ?? deviceEid(l.a);
    const b = deviceGroup.get(l.b) ?? deviceEid(l.b);
    if (collapsed) {
      if (a === b) continue;
      const [s, t] = a < b ? [a, b] : [b, a];
      const key = `${s}-${t}`;
      const cur = merged.get(key);
      const st = worseState(na.state, nb.state);
      merged.set(key, { source: s, target: t, state: cur ? worseState(cur.state, st) : st, count: (cur?.count ?? 0) + 1 });
      continue;
    }
    const st = linkStyle(l, na.state, nb.state);
    edges.push({
      id: `l${l.id}`,
      source: a,
      target: b,
      data: { width: st.width, color: st.color, dashed: st.dashed, portA: safeText(l.a_port_name), portB: safeText(l.b_port_name), nameA: safeText(na.name), nameB: safeText(nb.name) },
    });
  }
  for (const [key, m] of merged) {
    const st = linkStyle({ speed_bps: null, confidence: 1, manual: false }, m.state, m.state);
    edges.push({ id: `e${key}`, source: m.source, target: m.target, data: { width: Math.min(2 + Math.log2(m.count), 6), color: st.color, dashed: false, aggregate: m.count } });
  }
  return { nodes, edges };
}
