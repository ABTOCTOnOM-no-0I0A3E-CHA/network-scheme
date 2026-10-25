import ELK, { type ElkNode } from "elkjs/lib/elk-api";
import { deviceEid, type Topology } from "./semanticZoom";

export type Pos = { x: number; y: number };

const NODE = 40;
/*
 * Measured with ELK 0.12: cheap layered options take ~6 s for 1500 devices and ~110 s for 5000 (force: minutes already for
 * 1200). Above this many devices the devices are only packed into a grid; the admin pins what matters.
 */
const LAYERED_MAX = 1500;

/* Group key of the devices that are in no area; area ids start at 1. */
const OUTSIDE = 0;
/* Space kept between the areas and the devices that are in none. */
const OUTSIDE_GAP = 120;

type Area = Topology["areas"][number];

/**
 * ELK input for the devices of a topology: one compound per area holding that area's devices (and the links among them)
 * and one for the devices in no area. Each compound is laid out on its own (SEPARATE_CHILDREN), because the server
 * derives the area of a device from its position inside the area's stored rectangle: `placeDevices` fits every compound
 * into its rectangle afterwards. The packed layout for big graphs is flat inside the compounds.
 */
export function buildElkGraph(topo: Topology): ElkNode {
  const layered = topo.nodes.length <= LAYERED_MAX;
  const layoutOptions: Record<string, string> = layered
    ? {
        "elk.algorithm": "layered",
        "elk.direction": "DOWN",
        "elk.spacing.nodeNode": "40",
        "elk.layered.spacing.nodeNodeBetweenLayers": "60",
        "elk.layered.nodePlacement.strategy": "SIMPLE",
        "elk.layered.cycleBreaking.strategy": "GREEDY",
        "elk.layered.layering.strategy": "LONGEST_PATH",
        "elk.layered.thoroughness": "1",
        "elk.layered.crossingMinimization.strategy": "INTERACTIVE",
        "elk.padding": "[top=0,left=0,bottom=0,right=0]",
      }
    : { "elk.algorithm": "org.eclipse.elk.box", "elk.spacing.nodeNode": "40", "elk.padding": "[top=0,left=0,bottom=0,right=0]" };
  const known = new Set(topo.areas.map((a) => a.id));
  const keyOf = (n: Topology["nodes"][number]) => (n.area_id !== undefined && known.has(n.area_id) ? n.area_id : OUTSIDE);
  const groups = new Map<number, ElkNode>();
  const group = (key: number): ElkNode => {
    let g = groups.get(key);
    if (!g) groups.set(key, (g = { id: groupEid(key), layoutOptions: { ...layoutOptions }, children: [], edges: [] }));
    return g;
  };
  const where = new Map<number, number>();
  for (const n of topo.nodes) {
    const key = keyOf(n);
    where.set(n.device_id, key);
    group(key).children!.push({ id: deviceEid(n.device_id), width: NODE, height: NODE });
  }
  /* links between groups do not take part: they would only pull the groups apart inside their rectangles */
  for (const l of topo.links) {
    const k = where.get(l.a);
    if (k !== undefined && k === where.get(l.b)) group(k).edges!.push({ id: `l${l.id}`, sources: [deviceEid(l.a)], targets: [deviceEid(l.b)] });
  }
  return {
    id: "root",
    layoutOptions: { "elk.algorithm": "org.eclipse.elk.box", "elk.hierarchyHandling": "SEPARATE_CHILDREN" },
    children: [...groups.values()],
  };
}

const groupEid = (key: number) => `G${key}`;

/** The areas that win over `a` for a point inside both: smaller ones first, as the server picks the smallest area holding a node. */
function areaOrder(areas: readonly Area[]): Area[] {
  return [...areas].sort((p, q) => p.w * p.h - q.w * q.h || p.id - q.id);
}

const inside = (a: Area, p: Pos) => p.x >= a.x && p.x < a.x + a.w && p.y >= a.y && p.y < a.y + a.h;

/**
 * Centers of the laid-out devices, keyed by element id, such that no device changes its area: the devices of an area are
 * scaled down (never up) into its rectangle and kept out of the smaller areas inside it, the devices of no area go to the
 * right of every rectangle and of every device in `fixed` (the devices that keep their place, with their positions), so
 * that the moved ones cover neither. A device that has no free place in its area keeps the position it has.
 */
export function placeDevices(laid: ElkNode, topo: Topology, fixed?: ReadonlyMap<string, Pos>): Map<string, Pos> {
  const out = new Map<string, Pos>();
  const order = areaOrder(topo.areas);
  const rank = new Map(order.map((a, i) => [a.id, i]));
  const byEid = new Map(topo.nodes.map((n) => [deviceEid(n.device_id), n]));
  let right = topo.areas.reduce((m, a) => Math.max(m, a.x + a.w), -Infinity);
  let top = topo.areas.reduce((m, a) => Math.min(m, a.y), Infinity);
  for (const p of fixed?.values() ?? []) {
    right = Math.max(right, p.x + NODE / 2);
    top = Math.min(top, p.y - NODE / 2);
  }

  for (const g of laid.children ?? []) {
    const key = Number(g.id.slice(1));
    const kids = (g.children ?? []).map((c) => ({ id: c.id, x: (c.x ?? 0) + (c.width ?? NODE) / 2, y: (c.y ?? 0) + (c.height ?? NODE) / 2 }));
    if (kids.length === 0) continue;
    const minX = Math.min(...kids.map((k) => k.x));
    const minY = Math.min(...kids.map((k) => k.y));
    const area = key === OUTSIDE ? undefined : topo.areas.find((a) => a.id === key);

    if (!area) {
      /* the offset aligns the devices that move; those in `fixed` are only obstacles here */
      const moving = kids.filter((k) => !fixed?.has(k.id));
      const ref = moving.length > 0 ? moving : kids;
      const ox = Number.isFinite(right) ? right + OUTSIDE_GAP - Math.min(...ref.map((k) => k.x)) : 0;
      const oy = Number.isFinite(top) ? top - Math.min(...ref.map((k) => k.y)) : 0;
      for (const k of kids) out.set(k.id, { x: k.x + ox, y: k.y + oy });
      continue;
    }

    const ex = Math.max(...kids.map((k) => k.x)) - minX;
    const ey = Math.max(...kids.map((k) => k.y)) - minY;
    const mx = Math.min(NODE / 2 + 5, area.w / 4);
    const my = Math.min(NODE / 2 + 5, area.h / 4);
    const sw = area.w - 2 * mx;
    const sh = area.h - 2 * my;
    const sc = Math.min(1, ex > 0 ? sw / ex : 1, ey > 0 ? sh / ey : 1);
    const px = area.x + mx + (sw - ex * sc) / 2;
    const py = area.y + my + (sh - ey * sc) / 2;
    /* smaller areas overlapping this one take the points inside them */
    const holes = order.filter((o) => rank.get(o.id)! < rank.get(area.id)! && o.x < area.x + area.w && o.x + o.w > area.x && o.y < area.y + area.h && o.y + o.h > area.y);
    let free: Pos[] | undefined;
    const taken = new Set<Pos>();
    for (const k of kids) {
      const want = { x: px + (k.x - minX) * sc, y: py + (k.y - minY) * sc };
      if (!holes.some((h) => inside(h, want))) {
        out.set(k.id, want);
        continue;
      }
      if (!free) {
        const cols = Math.min(40, Math.ceil(sw / NODE) + 1);
        const rows = Math.min(40, Math.ceil(sh / NODE) + 1);
        free = [];
        for (let i = 0; i < cols; i++)
          for (let j = 0; j < rows; j++) {
            const c = { x: area.x + mx + (cols > 1 ? (i * sw) / (cols - 1) : sw / 2), y: area.y + my + (rows > 1 ? (j * sh) / (rows - 1) : sh / 2) };
            if (!holes.some((h) => inside(h, c))) free.push(c);
          }
      }
      let best: Pos | undefined;
      for (const c of free) {
        if (taken.has(c)) continue;
        if (!best || Math.hypot(c.x - want.x, c.y - want.y) < Math.hypot(best.x - want.x, best.y - want.y)) best = c;
      }
      best ??= free[0];
      if (best) {
        taken.add(best);
        out.set(k.id, best);
        continue;
      }
      /* nothing free: the position it has is valid by definition */
      const n = byEid.get(k.id);
      out.set(k.id, n?.x != null && n.y != null ? { x: n.x, y: n.y } : { x: area.x + area.w / 2, y: area.y + area.h / 2 });
    }
  }
  return out;
}

/**
 * Positions to apply after a layout: pinned devices are never moved, and only devices in `scope` (all when undefined)
 * take their new place.
 */
export function layoutMoves(laid: ReadonlyMap<string, Pos>, pinned: ReadonlySet<string>, scope?: ReadonlySet<string>): Map<string, Pos> {
  const out = new Map<string, Pos>();
  for (const [id, p] of laid) if (!pinned.has(id) && (!scope || scope.has(id))) out.set(id, p);
  return out;
}

/** Lays a graph out in a Web Worker (a bundled file under /assets/); the worker is discarded afterwards. */
export async function runLayout(graph: ElkNode): Promise<ElkNode> {
  const elk = new ELK({ workerFactory: () => new Worker(new URL("./layout.worker.ts", import.meta.url), { type: "module" }) });
  try {
    return await elk.layout(graph);
  } finally {
    elk.terminateWorker();
  }
}
