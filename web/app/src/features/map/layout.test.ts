// @vitest-environment node
import ELK from "elkjs/lib/elk.bundled.js";
import { describe, expect, it } from "vitest";
import { area, link, node } from "./fixtures";
import { buildElkGraph, devicePositions, layoutMoves } from "./layout";
import type { Topology } from "./semanticZoom";

const topo: Topology = {
  areas: [area(1, { device_count: 2 }), area(2, { parent_id: 1, device_count: 1 })],
  nodes: [node(1, { area_id: 1 }), node(2, { area_id: 2 }), node(3), node(4, { pinned: true, x: 777, y: 888 })],
  links: [link(1, 1, 2), link(2, 2, 3), link(3, 3, 4)],
};

describe("layout", () => {
  it("lays out nested areas and links with ELK, giving every device a finite position", async () => {
    const laid = devicePositions(await new ELK().layout(buildElkGraph(topo)));
    expect([...laid.keys()].sort()).toEqual(["d1", "d2", "d3", "d4"]);
    for (const p of laid.values()) {
      expect(Number.isFinite(p.x)).toBe(true);
      expect(Number.isFinite(p.y)).toBe(true);
    }
    expect(new Set([...laid.values()].map((p) => `${p.x},${p.y}`)).size).toBe(4);
  });

  it("never moves pinned devices and only moves those in scope", async () => {
    const laid = devicePositions(await new ELK().layout(buildElkGraph(topo)));
    const pinned = new Set(["d4"]);
    const all = layoutMoves(laid, pinned);
    expect([...all.keys()].sort()).toEqual(["d1", "d2", "d3"]);
    expect(all.has("d4")).toBe(false);
    const some = layoutMoves(laid, pinned, new Set(["d1", "d4"]));
    expect([...some.keys()]).toEqual(["d1"]);
  });

  it("packs big graphs into a grid instead of running a slow algorithm", async () => {
    const n = 3000;
    const big: Topology = { areas: [], nodes: Array.from({ length: n }, (_, i) => node(i + 1)), links: Array.from({ length: n - 1 }, (_, i) => link(i + 1, i + 1, i + 2)) };
    const g = buildElkGraph(big);
    expect(g.layoutOptions?.["elk.algorithm"]).toContain("box");
    const t0 = Date.now();
    const laid = devicePositions(await new ELK().layout(g));
    expect(laid.size).toBe(n);
    console.log(`ELK packed layout of ${n} devices: ${Date.now() - t0} ms`);
  }, 60000);
});
