import { useRef, useState, type PointerEvent as RPointerEvent } from "react";
import { safeText } from "@/lib/text";

export type Rect = { x: number; y: number; w: number; h: number };
export type OverlayArea = Rect & { id: number; name: string };
export type Viewport = { zoom: number; pan: { x: number; y: number } };
export type Corner = "nw" | "ne" | "sw" | "se";

const MIN_SIZE = 10;
const HANDLE = 10;
const CORNERS: Corner[] = ["nw", "ne", "sw", "se"];

type Drag =
  | { kind: "draw"; from: { x: number; y: number }; rect: Rect }
  | { kind: "move"; id: number; from: { x: number; y: number }; orig: Rect; rect: Rect }
  | { kind: "resize"; id: number; corner: Corner; orig: Rect; rect: Rect };

/** Rectangle spanned by two corners (any order), in model units. */
export function spanRect(a: { x: number; y: number }, b: { x: number; y: number }): Rect {
  return { x: Math.min(a.x, b.x), y: Math.min(a.y, b.y), w: Math.abs(a.x - b.x), h: Math.abs(a.y - b.y) };
}

/** `orig` with the given corner moved to the point `p`, the opposite corner staying fixed. */
export function resizeRect(orig: Rect, corner: Corner, p: { x: number; y: number }): Rect {
  const fixed = { x: corner.includes("w") ? orig.x + orig.w : orig.x, y: corner.includes("n") ? orig.y + orig.h : orig.y };
  return spanRect(fixed, p);
}

type Props = {
  areas: OverlayArea[];
  viewport: Viewport;
  /** "draw": a drag on empty space makes a new rectangle; "select": only the existing ones react. */
  tool: "select" | "draw";
  selectedId?: number;
  onSelect: (id: number | undefined) => void;
  onDraw: (r: Rect) => void;
  onChange: (id: number, r: Rect) => void;
};

/**
 * SVG layer above the map for editing area rectangles. Coordinates are model units (the background image's pixels);
 * the layer converts with the map's zoom and pan. Everything else passes pointer events through to the map.
 */
export function AreaOverlay({ areas, viewport, tool, selectedId, onSelect, onDraw, onChange }: Props) {
  const svg = useRef<SVGSVGElement>(null);
  const [drag, setDrag] = useState<Drag | undefined>();
  const { zoom, pan } = viewport;

  const toModel = (e: { clientX: number; clientY: number }) => {
    const r = svg.current!.getBoundingClientRect();
    return { x: (e.clientX - r.left - pan.x) / zoom, y: (e.clientY - r.top - pan.y) / zoom };
  };
  const toScreen = (r: Rect) => ({ x: r.x * zoom + pan.x, y: r.y * zoom + pan.y, w: r.w * zoom, h: r.h * zoom });

  const begin = (e: RPointerEvent, d: Drag) => {
    e.stopPropagation();
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
    setDrag(d);
  };
  const move = (e: RPointerEvent) => {
    if (!drag) return;
    const p = toModel(e);
    if (drag.kind === "draw") setDrag({ ...drag, rect: spanRect(drag.from, p) });
    else if (drag.kind === "move") setDrag({ ...drag, rect: { ...drag.orig, x: drag.orig.x + p.x - drag.from.x, y: drag.orig.y + p.y - drag.from.y } });
    else setDrag({ ...drag, rect: resizeRect(drag.orig, drag.corner, p) });
  };
  const end = () => {
    if (!drag) return;
    setDrag(undefined);
    const r = drag.rect;
    const round = { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.w), h: Math.round(r.h) };
    if (drag.kind === "draw") {
      if (round.w >= MIN_SIZE && round.h >= MIN_SIZE) onDraw(round);
    } else if (round.w >= MIN_SIZE && round.h >= MIN_SIZE && (round.x !== drag.orig.x || round.y !== drag.orig.y || round.w !== drag.orig.w || round.h !== drag.orig.h)) {
      onChange(drag.id, round);
    }
  };

  return (
    <svg ref={svg} className="pointer-events-none absolute inset-0 h-full w-full text-foreground" aria-hidden="true" onPointerMove={move} onPointerUp={end} onPointerCancel={() => setDrag(undefined)}>
      {tool === "draw" && (
        <rect
          data-testid="draw-surface"
          width="100%"
          height="100%"
          fill="transparent"
          className="pointer-events-auto cursor-crosshair"
          onPointerDown={(e) => begin(e, { kind: "draw", from: toModel(e), rect: { ...toModel(e), w: 0, h: 0 } })}
        />
      )}
      {areas.map((a) => {
        const live = drag && (drag.kind === "move" || drag.kind === "resize") && drag.id === a.id ? drag.rect : a;
        const s = toScreen(live);
        const sel = a.id === selectedId;
        return (
          <g key={a.id}>
            <rect x={s.x} y={s.y} width={s.w} height={s.h} fill="none" stroke={sel ? "#0ea5e9" : "currentColor"} strokeWidth={sel ? 2.5 : 1.5} strokeDasharray="6 4" opacity={sel ? 1 : 0.55} />
            <text x={s.x + 4} y={s.y - 5} fontSize="11" fill="currentColor">
              {safeText(a.name)}
            </text>
            <rect
              data-testid={`area-${a.id}`}
              x={s.x}
              y={s.y}
              width={s.w}
              height={s.h}
              fill="none"
              stroke="transparent"
              strokeWidth={12}
              pointerEvents="stroke"
              className="cursor-move"
              onPointerDown={(e) => {
                onSelect(a.id);
                begin(e, { kind: "move", id: a.id, from: toModel(e), orig: a, rect: a });
              }}
            />
            {sel &&
              CORNERS.map((c) => (
                <rect
                  key={c}
                  data-testid={`handle-${c}`}
                  x={(c.includes("w") ? s.x : s.x + s.w) - HANDLE / 2}
                  y={(c.includes("n") ? s.y : s.y + s.h) - HANDLE / 2}
                  width={HANDLE}
                  height={HANDLE}
                  fill="#0ea5e9"
                  className="pointer-events-auto cursor-nwse-resize"
                  onPointerDown={(e) => begin(e, { kind: "resize", id: a.id, corner: c, orig: a, rect: a })}
                />
              ))}
          </g>
        );
      })}
      {drag?.kind === "draw" &&
        (() => {
          const s = toScreen(drag.rect);
          return <rect x={s.x} y={s.y} width={s.w} height={s.h} fill="#0ea5e9" fillOpacity={0.12} stroke="#0ea5e9" strokeWidth={2} />;
        })()}
    </svg>
  );
}
