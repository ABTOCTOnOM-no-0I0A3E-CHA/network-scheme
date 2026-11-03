import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import "@/i18n";
import { AreaEditor, AreaZones, type AreaEditing, type OverlayArea } from "./AreaOverlay";
import { containerOf, descendants, resizeRect, spanRect } from "./areas";

afterEach(cleanup);

describe("rectangle math", () => {
  it("spans two corners in any order", () => {
    expect(spanRect({ x: 50, y: 40 }, { x: 10, y: 10 })).toEqual({ x: 10, y: 10, w: 40, h: 30 });
  });
  it("resizes by one corner keeping the opposite one fixed", () => {
    const r = { x: 10, y: 10, w: 100, h: 50 };
    expect(resizeRect(r, "se", { x: 200, y: 100 })).toEqual({ x: 10, y: 10, w: 190, h: 90 });
    expect(resizeRect(r, "nw", { x: 0, y: 0 })).toEqual({ x: 0, y: 0, w: 110, h: 60 });
    expect(resizeRect(r, "ne", { x: 150, y: 0 })).toEqual({ x: 10, y: 0, w: 140, h: 60 });
  });
});

describe("nesting", () => {
  const tree = [
    { id: 1, parent_id: null, x: 0, y: 0, w: 1000, h: 1000 },
    { id: 2, parent_id: 1, x: 100, y: 100, w: 400, h: 400 },
    { id: 3, parent_id: 2, x: 150, y: 150, w: 100, h: 100 },
    { id: 4, parent_id: null, x: 2000, y: 0, w: 300, h: 300 },
  ];
  it("finds every sub-area", () => {
    expect([...descendants(tree, 1)].sort()).toEqual([2, 3]);
    expect([...descendants(tree, 3)]).toEqual([]);
  });
  it("drops a rectangle into the smallest area that holds it whole", () => {
    expect(containerOf(tree, { x: 160, y: 160, w: 20, h: 20 })).toBe(3);
    expect(containerOf(tree, { x: 120, y: 120, w: 200, h: 50 })).toBe(2);
    expect(containerOf(tree, { x: 900, y: 900, w: 200, h: 50 })).toBeNull();
    expect(containerOf(tree, { x: 2050, y: 50, w: 10, h: 10 })).toBe(4);
  });
  it("never nests an area into itself or its own sub-areas", () => {
    expect(containerOf(tree, { x: 160, y: 160, w: 20, h: 20 }, new Set([2, 3]))).toBe(1);
  });
});

const vp = { zoom: 2, pan: { x: 100, y: 50 } };
const hq: OverlayArea = { id: 1, name: "HQ", kind: "building", parent_id: null, status: "up", count: 2, x: 0, y: 0, w: 100, h: 50 };
const room: OverlayArea = { id: 2, name: "Room", kind: "room", parent_id: 1, status: "down", count: 1, x: 10, y: 20, w: 30, h: 20 };

function editing(o: Partial<AreaEditing> = {}): AreaEditing {
  return { tool: "select", onSelect: vi.fn(), onCreate: vi.fn(async () => {}), onUpdate: vi.fn(async () => {}), onDelete: vi.fn(async () => {}), onMove: vi.fn(async () => {}), onResize: vi.fn(async () => {}), ...o };
}

describe("AreaZones", () => {
  it("draws zones in screen coordinates with the name as text", () => {
    render(<AreaZones areas={[{ ...hq, name: "<img src=x onerror=alert(1)>" }]} viewport={vp} />);
    const z = screen.getByTestId("zone-1");
    expect(z.style.left).toBe("100px");
    expect(z.style.width).toBe("200px");
    expect(z.textContent).toContain("<img src=x onerror=alert(1)>");
    expect(document.querySelector("img")).toBeNull();
  });
});

describe("AreaEditor", () => {
  it("draws a zone in model units, then asks for its name and kind and creates it", async () => {
    const ed = editing({ tool: "draw", onDrawn: vi.fn() });
    render(<AreaEditor areas={[]} viewport={vp} editing={ed} />);
    const s = screen.getByTestId("draw-surface");
    /* screen (140,90) -> model ((140-100)/2, (90-50)/2) = (20,20); screen (340,190) -> (120,70) */
    fireEvent.pointerDown(s, { clientX: 140, clientY: 90, pointerId: 1, button: 0 });
    fireEvent.pointerMove(s, { clientX: 340, clientY: 190, pointerId: 1 });
    fireEvent.pointerUp(s, { pointerId: 1 });
    expect(ed.onDrawn).toHaveBeenCalled();
    const form = screen.getByRole("form", { name: "Зона" });
    expect(screen.getByRole("button", { name: "Создать" })).toBeDisabled();
    await userEvent.type(screen.getByLabelText("Название"), "Серверная");
    await userEvent.click(screen.getByRole("radio", { name: "Этаж" }));
    await userEvent.click(screen.getByRole("button", { name: "Создать" }));
    expect(ed.onCreate).toHaveBeenCalledWith({ x: 20, y: 20, w: 100, h: 50 }, "Серверная", "floor");
    await waitFor(() => expect(form).not.toBeInTheDocument());
  });

  it("ignores a tiny drag and cancels the form with Escape", async () => {
    const ed = editing({ tool: "draw" });
    render(<AreaEditor areas={[]} viewport={vp} editing={ed} />);
    const s = screen.getByTestId("draw-surface");
    fireEvent.pointerDown(s, { clientX: 140, clientY: 90, pointerId: 1 });
    fireEvent.pointerUp(s, { pointerId: 1 });
    expect(screen.queryByRole("form")).toBeNull();
    fireEvent.pointerDown(s, { clientX: 140, clientY: 90, pointerId: 1 });
    fireEvent.pointerMove(s, { clientX: 340, clientY: 190, pointerId: 1 });
    fireEvent.pointerUp(s, { pointerId: 1 });
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByRole("form")).toBeNull();
    expect(ed.onCreate).not.toHaveBeenCalled();
  });

  it("moves a zone by its title bar together with its sub-zones", async () => {
    const ed = editing();
    const onPreview = vi.fn();
    const onMoved = vi.fn();
    render(<AreaEditor areas={[hq, room]} viewport={vp} editing={ed} onPreview={onPreview} onMoved={onMoved} />);
    const bar = screen.getByTestId("area-1");
    fireEvent.pointerDown(bar, { clientX: 110, clientY: 55, pointerId: 1, button: 0 });
    expect(ed.onSelect).toHaveBeenCalledWith(1);
    fireEvent.pointerMove(bar, { clientX: 150, clientY: 75, pointerId: 1 });
    /* +40,+20 on screen at zoom 2 = +20,+10 in the model, for the zone and the room inside it */
    const [preview, move] = onPreview.mock.calls.at(-1)!;
    expect(move).toMatchObject({ id: 1, dx: 20, dy: 10 });
    expect(preview.get(2)).toMatchObject({ x: 30, y: 30 });
    expect(move.from).toEqual([hq, room]);
    fireEvent.pointerUp(bar, { pointerId: 1 });
    expect(ed.onMove).toHaveBeenCalledWith(1, { x: 20, y: 10, w: 100, h: 50 }, 20, 10);
    /* the devices inside are stored once the server took the move */
    await waitFor(() => expect(onMoved).toHaveBeenCalledWith(1, 20, 10));
  });

  it("puts a zone back when the server refuses the move", async () => {
    const ed = editing({ onMove: vi.fn(async () => Promise.reject(new Error("no"))) });
    const onPreview = vi.fn();
    const onMoved = vi.fn();
    render(<AreaEditor areas={[hq]} viewport={vp} editing={ed} onPreview={onPreview} onMoved={onMoved} />);
    const bar = screen.getByTestId("area-1");
    fireEvent.pointerDown(bar, { clientX: 110, clientY: 55, pointerId: 1, button: 0 });
    fireEvent.pointerMove(bar, { clientX: 150, clientY: 75, pointerId: 1 });
    fireEvent.pointerUp(bar, { pointerId: 1 });
    await waitFor(() => expect(onPreview).toHaveBeenLastCalledWith(undefined));
    expect(onMoved).not.toHaveBeenCalled();
  });

  it("resizes the selected zone by a corner handle", () => {
    const ed = editing({ selectedId: 1 });
    render(<AreaEditor areas={[hq]} viewport={vp} editing={ed} />);
    const h = screen.getByTestId("handle-se");
    fireEvent.pointerDown(h, { clientX: 300, clientY: 150, pointerId: 1 });
    fireEvent.pointerMove(h, { clientX: 400, clientY: 250, pointerId: 1 });
    fireEvent.pointerUp(h, { pointerId: 1 });
    expect(ed.onResize).toHaveBeenCalledWith(1, { x: 0, y: 0, w: 150, h: 100 });
    expect(ed.onMove).not.toHaveBeenCalled();
  });

  it("deletes the selected zone only after confirmation", async () => {
    const ed = editing({ selectedId: 2 });
    render(<AreaEditor areas={[hq, room]} viewport={vp} editing={ed} />);
    await userEvent.click(screen.getByRole("button", { name: "Удалить" }));
    expect(ed.onDelete).not.toHaveBeenCalled();
    expect(screen.getByText("Удалить «Room»?")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Удалить" }));
    expect(ed.onDelete).toHaveBeenCalledWith(2);
  });

  it("renames the selected zone through the form", async () => {
    const ed = editing({ selectedId: 1 });
    render(<AreaEditor areas={[hq]} viewport={vp} editing={ed} />);
    await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
    const name = screen.getByLabelText("Название");
    expect(name).toHaveValue("HQ");
    await userEvent.clear(name);
    await userEvent.type(name, "Lobby");
    await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    expect(ed.onUpdate).toHaveBeenCalledWith(1, "Lobby", "building");
  });

  it("shows a failed save in the form", async () => {
    const ed = editing({ selectedId: 1, onUpdate: vi.fn(async () => Promise.reject(new Error("boom"))) });
    render(<AreaEditor areas={[hq]} viewport={vp} editing={ed} />);
    await userEvent.click(screen.getByRole("button", { name: "Изменить" }));
    await userEvent.click(screen.getByRole("button", { name: "Сохранить" }));
    expect(await screen.findByRole("alert")).toBeInTheDocument();
  });
});
