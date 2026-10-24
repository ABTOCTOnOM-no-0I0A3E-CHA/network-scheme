import type { Core, ElementDefinition, NodeSingular } from "cytoscape";
import type { MapModel, ModelNode } from "./semanticZoom";

export type SyncOptions = {
  /** Devices may be dragged (map.manage and a view to store the positions in). */
  canDrag: boolean;
};

/* distance (px) below which a position is considered unchanged */
const EPS = 0.5;

function changed(ele: { data(k: string): unknown }, data: Record<string, unknown>): Record<string, unknown> | undefined {
  let out: Record<string, unknown> | undefined;
  for (const k of Object.keys(data)) {
    if (ele.data(k) !== data[k]) (out ??= {})[k] = data[k];
  }
  return out;
}

/**
 * Brings the cytoscape graph in line with the model with the fewest changes (so the 30 s refresh does not rebuild
 * thousands of elements): removes what is gone, adds what is new, updates data and, positions.
 * Returns the ids of devices without a position, which still need a layout.
 */
export function syncElements(cy: Core, model: MapModel, o: SyncOptions): string[] {
  const needLayout: string[] = [];
  cy.batch(() => {
    const keep = new Set<string>();
    for (const n of model.nodes) keep.add(n.id);
    for (const e of model.edges) keep.add(e.id);
    cy.elements()
      .filter((e) => !keep.has(e.id()))
      .remove();

    const cols = Math.max(1, Math.ceil(Math.sqrt(model.nodes.length)));
    let placed = 0;
    const add: ElementDefinition[] = [];
    const existing: ModelNode[] = [];
    for (const n of model.nodes) {
      const ele = cy.getElementById(n.id);
      if (ele.empty()) {
        const pos = n.pos ?? { x: (placed % cols) * 60, y: Math.floor(placed / cols) * 60 };
        if (!n.pos) placed++;
        if (!n.pos && n.kind === "device") needLayout.push(n.id);
        add.push({ group: "nodes", data: { id: n.id, kind: n.kind, ...n.data, ...(n.parent ? { parent: n.parent } : {}) }, position: pos, grabbable: o.canDrag && n.kind === "device" });
        continue;
      }
      existing.push(n);
    }
    /* new nodes first: an existing device may move into a new area */
    cy.add(add);
    for (const n of existing) {
      const node = cy.getElementById(n.id) as NodeSingular;
      const d = changed(node, n.data);
      if (d) node.data(d);
      const parent = node.data("parent") as string | undefined;
      if (parent !== n.parent) node.move({ parent: n.parent ?? null });
      if (n.pos) {
        const p = node.position();
        if (Math.abs(p.x - n.pos.x) > EPS || Math.abs(p.y - n.pos.y) > EPS) node.position(n.pos);
      }
      const g = o.canDrag && n.kind === "device";
      if (node.grabbable() !== g) {
        if (g) node.grabify();
        else node.ungrabify();
      }
    }
    const edges: ElementDefinition[] = [];
    for (const e of model.edges) {
      const ele = cy.getElementById(e.id);
      if (ele.empty()) edges.push({ group: "edges", data: { id: e.id, source: e.source, target: e.target, ...e.data } });
      else {
        const d = changed(ele, e.data);
        if (d) ele.data(d);
      }
    }
    cy.add(edges);
  });
  return needLayout;
}
