import { useEffect, useRef, useState, type PointerEvent as RPointerEvent } from "react";
import { Check, Pencil, Trash2, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { errText } from "@/features/common/errText";
import { StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { descendants, resizeRect, roundRect, spanRect, type Corner, type Rect } from "./areas";
import type { NodeState } from "./style";

export type { Rect } from "./areas";
export type AreaKind = "organization" | "building" | "floor" | "room";
export type OverlayArea = Rect & { id: number; name: string; kind: AreaKind; parent_id: number | null; status: NodeState; count: number };
export type Viewport = { zoom: number; pan: { x: number; y: number } };

const MIN_SIZE = 10;
const HANDLE = 10;
const BAR = 22;
/* below this zoom the zone title bar would hide the devices it holds */
const BAR_MIN_ZOOM = 0.6;
const CORNERS: Corner[] = ["nw", "ne", "sw", "se"];
const KINDS: AreaKind[] = ["building", "floor", "room", "organization"];
const MAX_NAME = 100;

/* one colour family per kind of zone: a faint fill, a border and a title bar (static class strings for Tailwind) */
const KIND_CLASS: Record<AreaKind, { zone: string; bar: string }> = {
  organization: { zone: "border-slate-400/70 bg-slate-400/[0.05]", bar: "bg-slate-500/15 text-slate-800 dark:text-slate-100" },
  building: { zone: "border-sky-500/60 bg-sky-500/[0.06]", bar: "bg-sky-500/15 text-sky-900 dark:text-sky-100" },
  floor: { zone: "border-emerald-500/60 bg-emerald-500/[0.06]", bar: "bg-emerald-500/15 text-emerald-900 dark:text-emerald-100" },
  room: { zone: "border-amber-500/70 bg-amber-400/[0.07]", bar: "bg-amber-500/20 text-amber-900 dark:text-amber-100" },
};
const DOT: Record<NodeState, string> = { up: "bg-green-500", partial: "bg-amber-500", down: "bg-red-500", unknown: "bg-gray-400" };

const toScreen = (r: Rect, { zoom, pan }: Viewport): Rect => ({ x: r.x * zoom + pan.x, y: r.y * zoom + pan.y, w: r.w * zoom, h: r.h * zoom });
/* bigger zones first, so the smaller ones inside them stay on top */
const bySize = (areas: OverlayArea[]) => [...areas].sort((a, b) => b.w * b.h - a.w * a.h || a.id - b.id);

/**
 * Areas as translucent zones with a title bar (name, worst state, kind and device count), under the map canvas. Screen
 * coordinates from the map's zoom and pan; the title bar keeps its size down to a zoom where it would cover the devices
 * along the zone's top edge (the mini-map), then the name moves to a small tag in the bottom corner. Names are text only.
 */
export function AreaZones({ areas, viewport }: { areas: OverlayArea[]; viewport: Viewport }) {
  const { t } = useTranslation();
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" data-testid="area-zones">
      {bySize(areas).map((a) => {
        const s = toScreen(a, viewport);
        const k = KIND_CLASS[a.kind] ?? KIND_CLASS.room;
        return (
          <div key={a.id} data-testid={`zone-${a.id}`} className={cn("absolute rounded-md border-[1.5px]", k.zone)} style={{ left: s.x, top: s.y, width: s.w, height: s.h }}>
            {viewport.zoom >= BAR_MIN_ZOOM && s.h >= BAR + 4 && s.w >= 48 && (
              <div className={cn("flex h-[22px] items-center gap-1.5 overflow-hidden rounded-t-[5px] px-2 text-xs font-medium", k.bar)}>
                <span className={cn("size-2 shrink-0 rounded-full ring-1 ring-white/70", DOT[a.status])} />
                <span className="truncate">{safeText(a.name)}</span>
                {s.w >= 160 && (
                  <span className="ml-auto shrink-0 font-normal tabular-nums opacity-70">
                    {t(`map.areaKind.${a.kind}`)} · {a.count}
                  </span>
                )}
              </div>
            )}
            {viewport.zoom < BAR_MIN_ZOOM && s.h >= 20 && s.w >= 40 && (
              <span className={cn("absolute bottom-0.5 left-0.5 max-w-[calc(100%-4px)] truncate rounded-sm px-1 text-[10px] leading-4 font-medium", k.bar)}>{safeText(a.name)}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

type FormProps = { initial?: { name: string; kind: AreaKind }; submitLabel: string; onSubmit: (name: string, kind: AreaKind) => Promise<void>; onCancel: () => void };

/** Name and kind of a zone; a small floating form. Esc cancels. */
function AreaForm({ initial, submitLabel, onSubmit, onCancel }: FormProps) {
  const { t } = useTranslation();
  const [name, setName] = useState(initial?.name ?? "");
  const [kind, setKind] = useState<AreaKind>(initial?.kind ?? "room");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await onSubmit(name.trim(), kind);
    } catch (err) {
      if (!(err instanceof StepUpCancelled)) setError(errText(t, err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      aria-label={t("map.area.form")}
      className="grid w-64 gap-2 rounded-lg border bg-popover p-3 text-popover-foreground shadow-xl"
      onSubmit={(e) => void submit(e)}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          e.stopPropagation();
          onCancel();
        }
      }}
      onPointerDown={(e) => e.stopPropagation()}
    >
      <label className="grid gap-1 text-xs font-medium">
        {t("map.area.name")}
        <Input autoFocus value={name} maxLength={MAX_NAME} onChange={(e) => setName(e.target.value)} />
      </label>
      <div role="radiogroup" aria-label={t("map.area.kind")} className="grid grid-cols-2 gap-1">
        {KINDS.map((k) => (
          <button
            key={k}
            type="button"
            role="radio"
            aria-checked={kind === k}
            className={cn("flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs", kind === k ? "border-primary bg-primary/10 font-medium" : "hover:bg-muted")}
            onClick={() => setKind(k)}
          >
            <span className={cn("size-2.5 rounded-sm border", KIND_CLASS[k].zone, KIND_CLASS[k].bar)} />
            {t(`map.areaKind.${k}`)}
          </button>
        ))}
      </div>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" size="sm" variant="ghost" onClick={onCancel}>
          {t("map.area.cancel")}
        </Button>
        <Button type="submit" size="sm" disabled={name.trim() === "" || busy}>
          <Check />
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}

type Drag =
  | { kind: "draw"; from: { x: number; y: number }; rect: Rect }
  | { kind: "move"; id: number; from: { x: number; y: number }; orig: Rect; rect: Rect; moved: Set<number> }
  | { kind: "resize"; id: number; corner: Corner; orig: Rect; rect: Rect };

export type AreaEditing = {
  /** "draw": a drag on the map spans a new zone; "select": zones are moved and resized by their title bar and corners. */
  tool: "select" | "draw";
  selectedId?: number;
  onSelect: (id: number | undefined) => void;
  /** Called after a zone was drawn (to switch back to the select tool). */
  onDrawn?: () => void;
  onCreate: (r: Rect, name: string, kind: AreaKind) => Promise<void>;
  onUpdate: (id: number, name: string, kind: AreaKind) => Promise<void>;
  onDelete: (id: number) => Promise<void>;
  /** A zone was moved by (dx, dy) to `r`; its sub-zones moved with it. Rejects when the server refused. */
  onMove: (id: number, r: Rect, dx: number, dy: number) => Promise<void>;
  onResize: (id: number, r: Rect) => Promise<void>;
};

type EditorProps = {
  areas: OverlayArea[];
  viewport: Viewport;
  editing: AreaEditing;
  /**
   * Live rectangles while a zone is dragged (the zone and its sub-zones; with the offset of a move), undefined when a drag
   * is dropped without effect.
   */
  onPreview?: (m: ReadonlyMap<number, Rect> | undefined, move?: { id: number; dx: number; dy: number; from: Rect[] }) => void;
  /** A zone move was stored (the map then stores the devices it carried along). */
  onMoved?: (id: number, dx: number, dy: number) => void;
};

/**
 * Edit layer above the map canvas (map.manage, edit mode): title bars move zones (with their sub-zones), corner handles
 * resize the selected one, the draw tool spans a new one, and a small form asks for its name and kind. Zone interiors let
 * the pointer through, so devices inside stay draggable.
 */
export function AreaEditor({ areas, viewport, editing, onPreview, onMoved }: EditorProps) {
  const { t } = useTranslation();
  const root = useRef<HTMLDivElement>(null);
  const [drag, setDragState] = useState<Drag | undefined>();
  /* the live drag for the pointer handlers: state alone could be one move behind at pointerup */
  const dragRef = useRef<Drag | undefined>(undefined);
  const setDrag = (d: Drag | undefined) => {
    dragRef.current = d;
    setDragState(d);
  };
  const [draft, setDraft] = useState<Rect | undefined>();
  const [renaming, setRenaming] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<string | undefined>();
  const { zoom, pan } = viewport;
  const selected = areas.find((a) => a.id === editing.selectedId);

  /* a new selection starts without an open form or question */
  const [shownFor, setShownFor] = useState(editing.selectedId);
  if (shownFor !== editing.selectedId) {
    setShownFor(editing.selectedId);
    setRenaming(false);
    setConfirm(false);
    setError(undefined);
  }

  useEffect(() => {
    if (!draft && !renaming && !confirm) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      setDraft(undefined);
      setRenaming(false);
      setConfirm(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [draft, renaming, confirm]);

  const toModel = (e: { clientX: number; clientY: number }) => {
    const r = root.current!.getBoundingClientRect();
    return { x: (e.clientX - r.left - pan.x) / zoom, y: (e.clientY - r.top - pan.y) / zoom };
  };

  const begin = (e: RPointerEvent, d: Drag) => {
    e.stopPropagation();
    e.preventDefault();
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
    setDrag(d);
  };

  const preview = (d: Drag) => {
    if (d.kind === "draw") return;
    const m = new Map<number, Rect>([[d.id, d.rect]]);
    if (d.kind === "resize") return onPreview?.(m);
    const dx = d.rect.x - d.orig.x;
    const dy = d.rect.y - d.orig.y;
    const inner = areas.filter((a) => d.moved.has(a.id));
    for (const a of inner) m.set(a.id, { ...a, x: a.x + dx, y: a.y + dy });
    onPreview?.(m, { id: d.id, dx, dy, from: [d.orig, ...inner] });
  };

  const move = (e: RPointerEvent) => {
    const drag = dragRef.current;
    if (!drag) return;
    const p = toModel(e);
    let next: Drag;
    if (drag.kind === "draw") next = { ...drag, rect: spanRect(drag.from, p) };
    else if (drag.kind === "move") next = { ...drag, rect: { ...drag.orig, x: drag.orig.x + p.x - drag.from.x, y: drag.orig.y + p.y - drag.from.y } };
    else next = { ...drag, rect: resizeRect(drag.orig, drag.corner, p) };
    setDrag(next);
    preview(next);
  };

  const end = () => {
    const drag = dragRef.current;
    if (!drag) return;
    setDrag(undefined);
    const r = roundRect(drag.rect);
    const big = r.w >= MIN_SIZE && r.h >= MIN_SIZE;
    if (drag.kind === "draw") {
      if (big) setDraft(r);
      editing.onDrawn?.();
      return;
    }
    const o = drag.orig;
    const same = r.x === o.x && r.y === o.y && r.w === o.w && r.h === o.h;
    if (!big || same) {
      onPreview?.(undefined);
      return;
    }
    const id = drag.id;
    const dx = r.x - o.x;
    const dy = r.y - o.y;
    /* a refused change puts the zone (and what it carried) back */
    const undo = () => onPreview?.(undefined);
    if (drag.kind === "move") editing.onMove(id, r, dx, dy).then(() => onMoved?.(id, dx, dy), undo);
    else editing.onResize(id, r).catch(undo);
  };

  const cancel = () => {
    if (!dragRef.current) return;
    setDrag(undefined);
    onPreview?.(undefined);
  };

  const guarded = async (fn: () => Promise<void>) => {
    setError(undefined);
    try {
      await fn();
    } catch (e) {
      if (!(e instanceof StepUpCancelled)) setError(errText(t, e));
    }
  };

  const live = drag && drag.kind !== "draw" ? drag : undefined;
  const sel = selected ? toScreen(live && live.id === selected.id ? live.rect : selected, viewport) : undefined;
  const d = draft ? toScreen(draft, viewport) : undefined;

  return (
    <div ref={root} className="pointer-events-none absolute inset-0 overflow-hidden" data-testid="area-editor" onPointerMove={move} onPointerUp={end} onPointerCancel={cancel} onLostPointerCapture={() => dragRef.current && dragRef.current.kind !== "draw" && cancel()}>
      {editing.tool === "draw" && (
        <div
          data-testid="draw-surface"
          className="pointer-events-auto absolute inset-0 cursor-crosshair"
          onPointerDown={(e) => {
            const p = toModel(e);
            setDraft(undefined);
            begin(e, { kind: "draw", from: p, rect: { ...p, w: 0, h: 0 } });
          }}
        />
      )}
      {bySize(areas).map((a) => {
        const s = toScreen(live && live.id === a.id ? live.rect : a, viewport);
        return (
          <div
            key={a.id}
            data-testid={`area-${a.id}`}
            title={safeText(a.name)}
            className={cn("absolute h-[22px] cursor-move rounded-t-md", editing.tool === "draw" ? "pointer-events-none" : "pointer-events-auto hover:bg-primary/10")}
            style={{ left: s.x, top: s.y, width: Math.max(s.w, 24) }}
            onPointerDown={(e) => {
              if (e.button !== 0) return;
              editing.onSelect(a.id);
              const from = toModel(e);
              begin(e, { kind: "move", id: a.id, from, orig: a, rect: a, moved: descendants(areas, a.id) });
            }}
          />
        );
      })}
      {selected && sel && (
        <>
          <div className="pointer-events-none absolute rounded-md border-2 border-dashed border-sky-500" style={{ left: sel.x - 2, top: sel.y - 2, width: sel.w + 4, height: sel.h + 4 }} />
          {CORNERS.map((c) => (
            <div
              key={c}
              data-testid={`handle-${c}`}
              className={cn("pointer-events-auto absolute rounded-sm border-2 border-white bg-sky-500 shadow", c === "nw" || c === "se" ? "cursor-nwse-resize" : "cursor-nesw-resize")}
              style={{ left: (c.includes("w") ? sel.x : sel.x + sel.w) - HANDLE / 2, top: (c.includes("n") ? sel.y : sel.y + sel.h) - HANDLE / 2, width: HANDLE, height: HANDLE }}
              onPointerDown={(e) => e.button === 0 && begin(e, { kind: "resize", id: selected.id, corner: c, orig: selected, rect: selected })}
            />
          ))}
          {!live && (
            <div className="pointer-events-auto absolute flex items-center gap-1 rounded-md border bg-popover p-1 text-popover-foreground shadow-md" style={{ left: sel.x, top: Math.max(4, sel.y - 40) }} onPointerDown={(e) => e.stopPropagation()}>
              {confirm ? (
                <>
                  <span className="px-1 text-xs">{t("map.area.confirmDelete", { name: safeText(selected.name) })}</span>
                  <Button size="xs" variant="destructive" onClick={() => void guarded(() => editing.onDelete(selected.id))}>
                    {t("map.area.delete")}
                  </Button>
                  <Button size="xs" variant="ghost" onClick={() => setConfirm(false)}>
                    {t("map.area.cancel")}
                  </Button>
                </>
              ) : (
                <>
                  <Button size="xs" variant="ghost" onClick={() => setRenaming(true)}>
                    <Pencil />
                    {t("map.area.edit")}
                  </Button>
                  <Button size="xs" variant="ghost" className="text-destructive hover:text-destructive" onClick={() => setConfirm(true)}>
                    <Trash2 />
                    {t("map.area.delete")}
                  </Button>
                  <Button size="icon-xs" variant="ghost" aria-label={t("map.area.deselect")} onClick={() => editing.onSelect(undefined)}>
                    <X />
                  </Button>
                </>
              )}
              {error && (
                <span role="alert" className="px-1 text-xs text-destructive">
                  {error}
                </span>
              )}
            </div>
          )}
          {renaming && !live && (
            <div className="pointer-events-auto absolute z-10" style={{ left: sel.x, top: sel.y + BAR + 6 }}>
              <AreaForm
                initial={{ name: selected.name, kind: selected.kind }}
                submitLabel={t("map.area.save")}
                onSubmit={async (name, kind) => {
                  await editing.onUpdate(selected.id, name, kind);
                  setRenaming(false);
                }}
                onCancel={() => setRenaming(false)}
              />
            </div>
          )}
        </>
      )}
      {drag?.kind === "draw" &&
        (() => {
          const s = toScreen(drag.rect, viewport);
          return <div className="pointer-events-none absolute rounded-md border-2 border-sky-500 bg-sky-500/10" style={{ left: s.x, top: s.y, width: s.w, height: s.h }} />;
        })()}
      {draft && d && (
        <>
          <div className="pointer-events-none absolute rounded-md border-2 border-dashed border-sky-500 bg-sky-500/10" style={{ left: d.x, top: d.y, width: d.w, height: d.h }} />
          <div className="pointer-events-auto absolute z-10" style={{ left: d.x, top: d.y + Math.min(d.h, 40) + 6 }}>
            <AreaForm
              submitLabel={t("map.area.create")}
              onSubmit={async (name, kind) => {
                await editing.onCreate(draft, name, kind);
                setDraft(undefined);
              }}
              onCancel={() => setDraft(undefined)}
            />
          </div>
        </>
      )}
    </div>
  );
}
