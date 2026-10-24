import ELK, { type ElkNode } from "elkjs/lib/elk-api";
import { areaEid, deviceEid, type Topology } from "./semanticZoom";

export type Pos = { x: number; y: number };

const NODE = 40;
/*
 * Measured with ELK 0.12: cheap layered options take ~6 s for 1500 devices and ~110 s for 5000 (force: minutes already for
 * 1200). Above this many devices the devices are only packed into a grid; the admin pins what matters.
 */
const LAYERED_MAX = 1500;

/**
 * ELK input for the devices of a topology. Layered layout nests devices in their areas (edges stay at the root and
 * ELK includes the children); the packed layout for big graphs is flat.
 */
export function buildElkGraph(topo: Topology): ElkNode {
  const layered = topo.nodes.length <= LAYERED_MAX;
  const edges = topo.links.map((l) => ({ id: `l${l.id}`, sources: [deviceEid(l.a)], targets: [deviceEid(l.b)] }));
  const dev = (n: Topology["nodes"][number]): ElkNode => ({ id: deviceEid(n.device_id), width: NODE, height: NODE });
  const layoutOptions: Record<string, string> = layered
    ? {
        "elk.algorithm": "layered",
        "elk.direction": "DOWN",
        "elk.spacing.nodeNode": "40",
        "elk.layered.spacing.nodeNodeBetweenLayers": "60",
        "elk.hierarchyHandling": "INCLUDE_CHILDREN",
        "elk.layered.nodePlacement.strategy": "SIMPLE",
        "elk.layered.cycleBreaking.strategy": "GREEDY",
        "elk.layered.layering.strategy": "LONGEST_PATH",
        "elk.layered.thoroughness": "1",
      }
    : { "elk.algorithm": "org.eclipse.elk.box", "elk.spacing.nodeNode": "40" };
  if (!layered || topo.areas.length === 0) {
    /* the cheap sweep is not allowed together with hierarchy handling */
    if (layered) layoutOptions["elk.layered.crossingMinimization.strategy"] = "INTERACTIVE";
    return { id: "root", layoutOptions, children: topo.nodes.map(dev), edges };
  }

  const byId = new Map(topo.areas.map((a) => [a.id, a]));
  const box = new Map<number, ElkNode>(topo.areas.map((a) => [a.id, { id: areaEid(a.id), children: [], layoutOptions: { "elk.padding": "[top=30,left=20,bottom=20,right=20]" } }]));
  const root: ElkNode = { id: "root", layoutOptions, children: [], edges };
  for (const a of topo.areas) (a.parent_id !== null && box.has(a.parent_id) ? box.get(a.parent_id)! : root).children!.push(box.get(a.id)!);
  for (const n of topo.nodes) (n.area_id !== undefined && byId.has(n.area_id) ? box.get(n.area_id)! : root).children!.push(dev(n));
  return root;
}

/** Centers of the laid-out device nodes (ELK gives top-left corners relative to the parent), keyed by element id. */
export function devicePositions(laidOut: ElkNode): Map<string, Pos> {
  const out = new Map<string, Pos>();
  const walk = (n: ElkNode, ox: number, oy: number) => {
    for (const c of n.children ?? []) {
      const x = ox + (c.x ?? 0);
      const y = oy + (c.y ?? 0);
      if (c.id.startsWith("d")) out.set(c.id, { x: x + (c.width ?? NODE) / 2, y: y + (c.height ?? NODE) / 2 });
      else walk(c, x, y);
    }
  };
  walk(laidOut, 0, 0);
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
