// @vitest-environment node
import ELK from "elkjs/lib/elk.bundled.js";
import { describe, expect, it } from "vitest";
import { area, link, node } from "./fixtures";
import { buildElkGraph, layoutMoves, placeDevices } from "./layout";
import type { Topology } from "./semanticZoom";

const topo: Topology = {
  areas: [area(1, { device_count: 2 }), area(2, { parent_id: 1, x: 200, device_count: 1 })],
  nodes: [node(1, { area_id: 1 }), node(2, { area_id: 2 }), node(3), node(4, { pinned: true, x: 777, y: 888 })],
  links: [link(1, 1, 2), link(2, 2, 3), link(3, 3, 4)],
};

describe("layout", () => {
  it("lays out nested areas and links with ELK, giving every device a finite position", async () => {
    const laid = placeDevices(await new ELK().layout(buildElkGraph(topo)), topo);
    expect([...laid.keys()].sort()).toEqual(["d1", "d2", "d3", "d4"]);
    for (const p of laid.values()) {
      expect(Number.isFinite(p.x)).toBe(true);
      expect(Number.isFinite(p.y)).toBe(true);
    }
    expect(new Set([...laid.values()].map((p) => `${p.x},${p.y}`)).size).toBe(4);
  });

  it("never moves pinned devices and only moves those in scope", async () => {
    const laid = placeDevices(await new ELK().layout(buildElkGraph(topo)), topo);
    const pinned = new Set(["d4"]);
    const all = layoutMoves(laid, pinned);
    expect([...all.keys()].sort()).toEqual(["d1", "d2", "d3"]);
    expect(all.has("d4")).toBe(false);
    const some = layoutMoves(laid, pinned, new Set(["d1", "d4"]));
    expect([...some.keys()]).toEqual(["d1"]);
  });

  /* the server's rule: the smallest area whose half-open rectangle holds the point */
  const areaAt = (t: Topology, p: { x: number; y: number }) =>
    [...t.areas]
      .sort((a, b) => a.w * a.h - b.w * b.h || a.id - b.id)
      .find((a) => p.x >= a.x && p.x < a.x + a.w && p.y >= a.y && p.y < a.y + a.h)?.id;

  it("keeps every device in its area: inside the rectangle, outside the smaller areas within it, and unassigned devices outside all", async () => {
    const t: Topology = {
      areas: [
        area(1, { x: 0, y: 0, w: 600, h: 400 }),
        area(2, { parent_id: 1, x: 50, y: 50, w: 200, h: 200 }) /* a hole in the middle of area 1 */,
        area(3, { x: 1000, y: 0, w: 60, h: 60 }) /* too small for its devices at full size */,
        area(4, { x: 1200, y: 0, w: 100, h: 100 }) /* a hole in the middle of area 5 */,
        area(5, { x: 1190, y: -10, w: 120, h: 120 }),
      ].map((a) => ({ ...a })),
      nodes: [
        node(1, { area_id: 1, x: 500, y: 350 }),
        node(2, { area_id: 1, x: 400, y: 300 }),
        node(3, { area_id: 1, x: 300, y: 100 }),
        node(4, { area_id: 1, x: 450, y: 100 }),
        node(5, { area_id: 2, x: 100, y: 100 }),
        node(6, { area_id: 2, x: 120, y: 120 }),
        node(7, { area_id: 3, x: 10, y: 10 }),
        node(8, { area_id: 3, x: 20, y: 20 }),
        node(9, { area_id: 3, x: 30, y: 30 }),
        node(10, { area_id: 3, x: 40, y: 40 }),
        node(11),
        node(12, { x: 5000, y: 5000 }),
        node(13, { area_id: 5, x: 1195, y: -5 }),
      ],
      links: [link(1, 1, 2), link(2, 2, 5), link(3, 5, 6), link(4, 7, 8), link(5, 8, 9), link(6, 9, 10), link(7, 11, 12), link(8, 3, 11)],
    };
    const laid = placeDevices(await new ELK().layout(buildElkGraph(t)), t);
    expect(laid.size).toBe(t.nodes.length);
    for (const n of t.nodes) {
      const p = laid.get(`d${n.device_id}`)!;
      expect(Number.isFinite(p.x) && Number.isFinite(p.y)).toBe(true);
      expect(areaAt(t, p), `device ${n.device_id} at ${p.x},${p.y}`).toBe(n.area_id);
    }
  });

  it("packs big graphs into a grid instead of running a slow algorithm", async () => {
    const n = 3000;
    const big: Topology = { areas: [], nodes: Array.from({ length: n }, (_, i) => node(i + 1)), links: Array.from({ length: n - 1 }, (_, i) => link(i + 1, i + 1, i + 2)) };
    const g = buildElkGraph(big);
    expect(g.children?.every((c) => c.layoutOptions?.["elk.algorithm"]?.includes("box"))).toBe(true);
    const t0 = Date.now();
    const laid = placeDevices(await new ELK().layout(g), big);
    expect(laid.size).toBe(n);
    console.log(`ELK packed layout of ${n} devices: ${Date.now() - t0} ms`);
  }, 60000);
});
