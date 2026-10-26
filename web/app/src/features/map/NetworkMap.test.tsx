import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@/i18n";
import { installCanvasStub } from "./canvasStub";
import { area, link, node } from "./fixtures";
import type { Core } from "cytoscape";
import { NetworkMap } from "./NetworkMap";
import type { Topology } from "./semanticZoom";

beforeAll(installCanvasStub);
afterEach(cleanup);

const topo: Topology = {
  areas: [area(1, { device_count: 2 })],
  nodes: [node(1, { area_id: 1, x: 10, y: 20, name: "<img src=x onerror=alert(1)>" }), node(2, { area_id: 1, x: 30, y: 40 })],
  links: [link(1, 1, 2)],
};

const props = { topology: topo, severity: new Map(), onOpenDevice: vi.fn() };
const cyOf = () => (screen.getByTestId("map-canvas") as unknown as { _cyreg: { cy: Core } })._cyreg.cy;

describe("NetworkMap", () => {
  /* canvasStub inserts the cytoscape marker <meta>, so this only guards the component; the real proof is build.test.ts and the e2e CSP guard. */
  it("never injects a <style> element or markup from device names", async () => {
    const before = document.querySelectorAll("style").length;
    const { container } = render(<NetworkMap {...props} />);
    await waitFor(() => expect(container.querySelector("canvas")).not.toBeNull());
    expect(document.querySelectorAll("style").length).toBe(before);
    expect(container.querySelector("img")).toBeNull();
    /* the label layer shows the name as literal text */
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(screen.getByText("192.0.2.1")).toBeInTheDocument();
  });

  it("layers the background as an <img> under the canvas", () => {
    const { container } = render(<NetworkMap {...props} backgroundUrl="/api/map/backgrounds/5" />);
    const img = container.querySelector("img");
    expect(img?.getAttribute("src")).toBe("/api/map/backgrounds/5");
    const host = screen.getByTestId("map-canvas");
    expect(img!.compareDocumentPosition(host) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("places the background at once, not at the first pan", async () => {
    const { container } = render(<NetworkMap {...props} backgroundUrl="/api/map/backgrounds/5" />);
    await waitFor(() => expect(container.querySelector("img")?.style.transform).toMatch(/^translate\(.*\) scale\(/));
  });

  it("has toolbar buttons with translated names and shows no editor layer by default", async () => {
    const { container } = render(<NetworkMap {...props} />);
    await userEvent.click(screen.getByRole("button", { name: "Показать всё" }));
    expect(screen.getByRole("button", { name: "Автораскладка" })).toBeInTheDocument();
    expect(container.querySelector("[data-testid='draw-surface'], [data-testid='area-1']")).toBeNull();
  });

  it("draws areas as zones, and shows the zone editor only in edit mode", () => {
    const { container } = render(<NetworkMap {...props} editor={{ tool: "select", onSelect: vi.fn(), onCreate: vi.fn(), onUpdate: vi.fn(), onDelete: vi.fn(), onMove: vi.fn(), onResize: vi.fn() }} />);
    expect(screen.getByTestId("zone-1")).toBeInTheDocument();
    expect(container.querySelector("[data-testid='area-1']")).not.toBeNull();
  });

  it("shows a hover card with the device data as text", async () => {
    const hostile: Topology = { ...topo, nodes: [node(1, { x: 10, y: 20, name: "<b>sw</b>", model: "<i>MES</i>", role: "switch", state: "down" })], links: [] };
    render(<NetworkMap {...props} topology={hostile} problems={new Map([[1, 3]])} />);
    const cy = cyOf();
    await waitFor(() => expect(cy.nodes()).toHaveLength(1));
    cy.getElementById("d1").emit("mouseover");
    const card = await screen.findByTestId("map-hover-card");
    expect(card.textContent).toContain("<i>MES</i>");
    expect(card.textContent).toContain("Коммутатор");
    expect(card.textContent).toContain("Недоступно");
    expect(card.textContent).toContain("3");
    expect(card.querySelector("b, i")).toBeNull();
  });

  it("drags devices only when positions can be saved", async () => {
    const { rerender } = render(<NetworkMap {...props} />);
    const cy = cyOf();
    await waitFor(() => expect(cy.nodes()).toHaveLength(2));
    expect(cy.getElementById("d1").grabbable()).toBe(false);
    rerender(<NetworkMap {...props} save={vi.fn(async () => {})} />);
    await waitFor(() => expect(cy.getElementById("d1").grabbable()).toBe(true));
  });
});
