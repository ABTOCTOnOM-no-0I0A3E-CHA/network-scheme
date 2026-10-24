import { describe, expect, it } from "vitest";
import { area, link, node } from "./fixtures";
import { buildModel, COLLAPSE_BELOW, EXPAND_ABOVE, isCollapsed, severityByDevice, type Topology } from "./semanticZoom";
import { SEVERITY_COLOR, STATE_COLOR } from "./style";

describe("isCollapsed", () => {
  it("collapses below the threshold and expands above it, with hysteresis between", () => {
    expect(isCollapsed(false, COLLAPSE_BELOW - 0.01)).toBe(true);
    expect(isCollapsed(true, EXPAND_ABOVE + 0.01)).toBe(false);
    const mid = (COLLAPSE_BELOW + EXPAND_ABOVE) / 2;
    expect(isCollapsed(false, mid)).toBe(false);
    expect(isCollapsed(true, mid)).toBe(true);
  });
});

/* building 1 (floor 2 inside) holds devices 1-3, building 3 holds device 4, device 5 is outside every area */
const topo: Topology = {
  areas: [
    area(1, { name: "HQ", device_count: 3, status: "down", x: 0, y: 0, w: 200, h: 100 }),
    area(2, { parent_id: 1, kind: "floor", device_count: 1, status: "up" }),
    area(3, { name: "Branch", device_count: 1, status: "partial", x: 400, y: 0, w: 100, h: 100 }),
    area(9, { name: "Empty", device_count: 0, status: "unknown", x: 0, y: 300, w: 80, h: 40 }),
  ],
  nodes: [
    node(1, { area_id: 1, x: 10, y: 10, state: "down" }),
    node(2, { area_id: 2, x: 20, y: 20 }),
    node(3, { area_id: 1, x: 30, y: 30 }),
    node(4, { area_id: 3, x: 410, y: 10, state: "partial" }),
    node(5, { x: 0, y: 500 }),
  ],
  links: [link(1, 1, 2), link(2, 2, 3), link(3, 3, 4), link(4, 1, 4), link(5, 4, 5)],
};

describe("buildModel expanded", () => {
  const m = buildModel(topo, false, new Map());
  const byId = new Map(m.nodes.map((n) => [n.id, n]));
  it("nests devices in areas and areas in areas, parents first", () => {
    expect(byId.get("d1")?.parent).toBe("a1");
    expect(byId.get("d2")?.parent).toBe("a2");
    expect(byId.get("a2")?.parent).toBe("a1");
    expect(byId.get("d5")?.parent).toBeUndefined();
    const ids = m.nodes.map((n) => n.id);
    expect(ids.indexOf("a1")).toBeLessThan(ids.indexOf("a2"));
  });
  it("places an area without devices at its rectangle, and compounds without a position of their own", () => {
    expect(byId.get("a9")?.pos).toEqual({ x: 40, y: 320 });
    expect(byId.get("a1")?.pos).toBeUndefined();
  });
  it("keeps every link, styled", () => {
    expect(m.edges.map((e) => e.id).sort()).toEqual(["l1", "l2", "l3", "l4", "l5"]);
    expect(m.edges.find((e) => e.id === "l1")?.data.color).not.toBe(m.edges.find((e) => e.id === "l2")?.data.color);
  });
  it("colors by state and rings devices with open problems", () => {
    const m2 = buildModel(topo, false, new Map([[1, "high" as const]]));
    const d1 = m2.nodes.find((n) => n.id === "d1")!;
    expect(d1.data).toMatchObject({ color: STATE_COLOR.down, ring: 3, ringColor: SEVERITY_COLOR.high });
    expect(m2.nodes.find((n) => n.id === "d2")!.data.ring).toBe(0);
  });
  it("shows an unsaved position instead of the server one and marks the device pinned", () => {
    const m2 = buildModel(topo, false, new Map(), { pos: new Map([[5, { x: 7, y: 8 }]]), pinned: new Set([5]) });
    const d5 = m2.nodes.find((n) => n.id === "d5")!;
    expect(d5.pos).toEqual({ x: 7, y: 8 });
    expect(d5.data.pinned).toBe(true);
  });
});

describe("buildModel collapsed", () => {
  const m = buildModel(topo, true, new Map());
  it("turns every top-level area into one node and keeps devices outside areas", () => {
    expect(m.nodes.map((n) => n.id).sort()).toEqual(["d5", "g1", "g3", "g9"]);
  });
  it("gives the group the aggregate status and count of its area", () => {
    const g = m.nodes.find((n) => n.id === "g1")!;
    expect(g.data).toMatchObject({ color: STATE_COLOR.down, label: "HQ (3)" });
    expect(g.pos).toEqual({ x: 100, y: 50 });
  });
  it("merges links between groups and drops links inside one", () => {
    const e = m.edges.map((x) => [x.source, x.target, x.data.aggregate]).sort();
    expect(e).toEqual([
      ["d5", "g3", 1],
      ["g1", "g3", 2],
    ]);
  });
  it("has far fewer elements than the expanded model", () => {
    const big: Topology = {
      areas: [area(1, { device_count: 3000 })],
      nodes: Array.from({ length: 3000 }, (_, i) => node(i + 1, { area_id: 1, x: i, y: i })),
      links: Array.from({ length: 2999 }, (_, i) => link(i + 1, i + 1, i + 2)),
    };
    expect(buildModel(big, true, new Map()).nodes).toHaveLength(1);
    expect(buildModel(big, true, new Map()).edges).toHaveLength(0);
    expect(buildModel(big, false, new Map()).nodes).toHaveLength(3001);
  });
});

describe("hostile device data", () => {
  it("is made safe text before it reaches the canvas", () => {
    const evil = "<img src=x onerror=alert(1)>‮\u0000sw";
    const m = buildModel(
      {
        areas: [area(1, { name: "<script>x</script>‭", device_count: 1 })],
        nodes: [node(1, { name: evil, area_id: 1, x: 0, y: 0 }), node(2, { name: "b" })],
        links: [link(1, 1, 2, { a_port_name: evil, b_port_name: "\u0007" })],
      },
      false,
      new Map(),
    );
    const labels = [...m.nodes.map((n) => n.data.label as string), ...m.edges.flatMap((e) => [e.data.portA, e.data.portB, e.data.nameA] as string[])];
    /* eslint-disable-next-line no-control-regex */
    for (const l of labels) expect(l).not.toMatch(/[\u0000-\u001f‪-‮⁦-⁩]/);
    expect(m.nodes.find((n) => n.id === "d1")!.data.label).toBe("<img src=x onerror=alert(1)>��sw");
  });
});

describe("severityByDevice", () => {
  it("keeps the worst severity and ignores problems without a device", () => {
    const m = severityByDevice([
      { device_id: 1, severity: "warning" },
      { device_id: 1, severity: "high" },
      { device_id: 1, severity: "info" },
      { device_id: null, severity: "disaster" },
    ]);
    expect([...m]).toEqual([[1, "high"]]);
  });
});
