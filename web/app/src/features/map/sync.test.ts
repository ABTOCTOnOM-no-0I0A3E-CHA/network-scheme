import cytoscape from "cytoscape";
import { describe, expect, it } from "vitest";
import { area, link, node } from "./fixtures";
import { buildModel, type Topology } from "./semanticZoom";
import { syncElements } from "./sync";

const topo: Topology = {
  areas: [area(1, { device_count: 2 })],
  nodes: [node(1, { area_id: 1, x: 10, y: 20 }), node(2, { area_id: 1, x: 30, y: 40 }), node(3)],
  links: [link(1, 1, 2), link(2, 2, 3)],
};
const opts = { canDrag: true };

describe("syncElements", () => {
  it("adds elements, reports devices without a position and parents them in areas", () => {
    const cy = cytoscape({ headless: true });
    const need = syncElements(cy, buildModel(topo, false, new Map()), opts);
    expect(need).toEqual(["d3"]);
    expect(cy.nodes()).toHaveLength(4);
    expect(cy.edges()).toHaveLength(2);
    expect(cy.getElementById("d1").parent().first().id()).toBe("a1");
    expect(cy.getElementById("d1").position()).toEqual({ x: 10, y: 20 });
    expect(cy.getElementById("d1").grabbable()).toBe(true);
  });

  it("updates data in place without touching positions that did not change", () => {
    const cy = cytoscape({ headless: true });
    syncElements(cy, buildModel(topo, false, new Map()), opts);
    cy.getElementById("d1").position({ x: 99, y: 99 });
    const n = cy.getElementById("d2");
    const down: Topology = { ...topo, nodes: topo.nodes.map((x) => (x.device_id === 2 ? { ...x, state: "down" as const } : x)) };
    syncElements(cy, buildModel(down, false, new Map([[2, "high" as const]])), opts);
    expect(cy.getElementById("d2")).toBe(n);
    expect(n.data("ring")).toBe(3);
    /* the model says (10, 20) again, so the canvas follows it */
    expect(cy.getElementById("d1").position()).toEqual({ x: 10, y: 20 });
    expect(n.position()).toEqual({ x: 30, y: 40 });
  });

  it("swaps areas for one node when collapsing, and back", () => {
    const cy = cytoscape({ headless: true });
    syncElements(cy, buildModel(topo, false, new Map()), opts);
    syncElements(cy, buildModel(topo, true, new Map()), opts);
    expect(cy.nodes().map((x) => x.id()).sort()).toEqual(["d3", "g1"]);
    expect(cy.edges().map((x) => x.id())).toEqual(["ed3-g1"]);
    syncElements(cy, buildModel(topo, false, new Map()), opts);
    expect(cy.nodes()).toHaveLength(4);
  });

  it("keeps hostile names as plain data, never as markup", () => {
    const cy = cytoscape({ headless: true });
    const evil = "<img src=x onerror=alert(1)>";
    const t: Topology = { areas: [], nodes: [node(1, { name: evil, x: 0, y: 0 })], links: [] };
    syncElements(cy, buildModel(t, false, new Map()), opts);
    expect(cy.getElementById("d1").data("label")).toBe(evil);
    expect(document.body.innerHTML).not.toContain("onerror");
  });

  it("makes devices non-draggable without map.manage", () => {
    const cy = cytoscape({ headless: true });
    syncElements(cy, buildModel(topo, false, new Map()), { canDrag: false });
    expect(cy.getElementById("d1").grabbable()).toBe(false);
    syncElements(cy, buildModel(topo, false, new Map()), opts);
    expect(cy.getElementById("d1").grabbable()).toBe(true);
  });
});
