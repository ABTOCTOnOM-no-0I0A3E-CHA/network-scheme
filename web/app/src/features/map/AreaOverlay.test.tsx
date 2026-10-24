import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";
import { AreaOverlay, resizeRect, spanRect } from "./AreaOverlay";

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

describe("AreaOverlay", () => {
  const vp = { zoom: 2, pan: { x: 100, y: 50 } };
  const area = { id: 1, name: "HQ", x: 0, y: 0, w: 100, h: 50 };

  it("draws a rectangle in model units, honoring zoom and pan", () => {
    const onDraw = vi.fn();
    render(<AreaOverlay areas={[]} viewport={vp} tool="draw" onSelect={vi.fn()} onDraw={onDraw} onChange={vi.fn()} />);
    const s = screen.getByTestId("draw-surface");
    /* screen (140,90) -> model ((140-100)/2, (90-50)/2) = (20,20); screen (340,190) -> (120,70) */
    fireEvent.pointerDown(s, { clientX: 140, clientY: 90, pointerId: 1 });
    fireEvent.pointerMove(s.closest("svg")!, { clientX: 340, clientY: 190, pointerId: 1 });
    fireEvent.pointerUp(s.closest("svg")!, { pointerId: 1 });
    expect(onDraw).toHaveBeenCalledWith({ x: 20, y: 20, w: 100, h: 50 });
  });

  it("ignores a tiny drag", () => {
    const onDraw = vi.fn();
    render(<AreaOverlay areas={[]} viewport={vp} tool="draw" onSelect={vi.fn()} onDraw={onDraw} onChange={vi.fn()} />);
    const s = screen.getByTestId("draw-surface");
    fireEvent.pointerDown(s, { clientX: 140, clientY: 90, pointerId: 1 });
    fireEvent.pointerUp(s.closest("svg")!, { pointerId: 1 });
    expect(onDraw).not.toHaveBeenCalled();
  });

  it("selects an area and resizes it by a corner handle", () => {
    const onSelect = vi.fn();
    const onChange = vi.fn();
    const { rerender } = render(<AreaOverlay areas={[area]} viewport={vp} tool="select" onSelect={onSelect} onDraw={vi.fn()} onChange={onChange} />);
    fireEvent.pointerDown(screen.getByTestId("area-1"), { clientX: 100, clientY: 50, pointerId: 1 });
    expect(onSelect).toHaveBeenCalledWith(1);
    fireEvent.pointerUp(screen.getByTestId("area-1").closest("svg")!, { pointerId: 1 });
    rerender(<AreaOverlay areas={[area]} viewport={vp} tool="select" selectedId={1} onSelect={onSelect} onDraw={vi.fn()} onChange={onChange} />);
    const h = screen.getByTestId("handle-se");
    fireEvent.pointerDown(h, { clientX: 300, clientY: 150, pointerId: 1 });
    fireEvent.pointerMove(h.closest("svg")!, { clientX: 400, clientY: 250, pointerId: 1 });
    fireEvent.pointerUp(h.closest("svg")!, { pointerId: 1 });
    expect(onChange).toHaveBeenCalledWith(1, { x: 0, y: 0, w: 150, h: 100 });
  });
});
