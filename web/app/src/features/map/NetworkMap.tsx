import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore, type ComponentProps } from "react";
import cytoscape, { type Core, type EventObject, type NodeSingular } from "cytoscape";
import { Maximize, Minus, Plus, Workflow } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { safeText } from "@/lib/text";
import { AreaEditor, AreaZones, type AreaEditing, type OverlayArea, type Rect, type Viewport } from "./AreaOverlay";
import { insideRect } from "./areas";
import { buildElkGraph, layoutMoves, placeDevices, runLayout } from "./layout";
import { MapHoverCard } from "./MapHoverCard";
import { NodeLabels, type LabelItem } from "./NodeLabels";
import { PositionSaver, type PositionItem } from "./positions";
import { buildModel, deviceEid, isCollapsed, OPEN_ZOOM, type Topology } from "./semanticZoom";
import { buildStylesheet, LABEL_H, LABEL_W, NODE_H } from "./style";
import { syncElements } from "./sync";
import type { EventSeverity } from "@/features/problems/api";

/* above this many devices the renderer drops edges and uses a texture while panning, edges are straight and names are drawn on the canvas */
const LARGE = 1500;
/* below this zoom the HTML labels are too small to read and are hidden (the mini map shows them only when zoomed in) */
const LABEL_ZOOM = 0.45;
const LABEL_ZOOM_COMPACT = 0.8;
/* the dotted workspace grid: its pitch in model units, and the smallest pitch on screen it is drawn at */
const GRID = 24;
const GRID_MIN = 9;

/** Current zoom and pan of the canvas, for the layers drawn in screen coordinates (zones, the area editor). */
class ViewStore {
  private v: Viewport = { zoom: 1, pan: { x: 0, y: 0 } };
  private subs = new Set<() => void>();
  set(v: Viewport) {
    this.v = v;
    for (const f of this.subs) f();
  }
  get = () => this.v;
  subscribe = (f: () => void) => {
    this.subs.add(f);
    return () => void this.subs.delete(f);
  };
}

const useView = (s: ViewStore) => useSyncExternalStore(s.subscribe, s.get);
const LiveZones = ({ store, ...p }: { store: ViewStore } & Omit<ComponentProps<typeof AreaZones>, "viewport">) => <AreaZones {...p} viewport={useView(store)} />;
const LiveEditor = ({ store, ...p }: { store: ViewStore } & Omit<ComponentProps<typeof AreaEditor>, "viewport">) => <AreaEditor {...p} viewport={useView(store)} />;

type Props = {
  topology: Topology;
  severity: ReadonlyMap<number, EventSeverity>;
  /** Open problems per device, for the hover card. */
  problems?: ReadonlyMap<number, number>;
  /** Background image of the view (same-origin URL); drawn as an <img> layer under the canvas. */
  backgroundUrl?: string;
  /** Persists dragged positions into this view; devices are draggable only with it (edit mode). */
  save?: (items: PositionItem[]) => Promise<void>;
  onSaved?: (items: PositionItem[]) => void;
  onSaveError?: (err: unknown) => void;
  onOpenDevice: (id: number, name: string) => void;
  /** Edit mode: zone tools on the map. */
  editor?: AreaEditing;
  /** Widget mode (mini map): no autolayout button, no wheel zoom (the page keeps scrolling); same data and interactions otherwise. */
  compact?: boolean;
};

type Tip = { x: number; y: number; lines: string[] };
type Hover = { id: number; x: number; y: number; r: number; box: { w: number; h: number } };

function useDark(): boolean {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  useEffect(() => {
    const mo = new MutationObserver(() => setDark(document.documentElement.classList.contains("dark")));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => mo.disconnect();
  }, []);
  return dark;
}

const devId = (eid: string) => Number(eid.slice(1));

/**
 * The interactive map, in the manner of Packet Tracer's logical workspace: device pictograms and links on a Cytoscape
 * canvas, areas as zones under it (collapsed into one node each at low zoom), HTML labels and a hover card over it, ELK
 * autolayout in a Web Worker. In edit mode devices are dragged (pinned, saved in batches) and zones are drawn, moved and
 * resized. All device text is made safe and only ever drawn on the canvas or set as text content.
 */
export function NetworkMap({ topology, severity, problems, backgroundUrl, save, onSaved, onSaveError, onOpenDevice, editor, compact = false }: Props) {
  const { t } = useTranslation();
  const dark = useDark();
  const host = useRef<HTMLDivElement>(null);
  const img = useRef<HTMLImageElement>(null);
  const labelWorld = useRef<HTMLDivElement>(null);
  const ground = useRef<HTMLDivElement>(null);
  const labelEls = useRef(new Map<string, HTMLDivElement>());
  const cyRef = useRef<Core | undefined>(undefined);
  const [collapsed, setCollapsed] = useState(false);
  const collapsedRef = useRef(false);
  const [tip, setTip] = useState<Tip | undefined>();
  const [hover, setHover] = useState<Hover | undefined>();
  const [store] = useState(() => new ViewStore());
  const [layoutError, setLayoutError] = useState(false);
  const [large] = useState(() => topology.nodes.length > LARGE);
  const compactRef = useRef(compact);

  /* client-side state not on the server yet */
  const [posOv, setPosOv] = useState<ReadonlyMap<number, { x: number; y: number }>>(new Map());
  const [pinOv, setPinOv] = useState<ReadonlySet<number>>(new Set());
  /* zone rectangles while (and after) a zone is dragged, until the server's areas replace them */
  const [preview, setPreview] = useState<{ for: Topology["areas"]; map: ReadonlyMap<number, Rect> } | undefined>();
  const pinOvRef = useRef(pinOv);
  const posOvRef = useRef(posOv);
  const tried = useRef(new Set<string>());
  const fitted = useRef(false);
  const saver = useRef<PositionSaver | undefined>(undefined);
  const carried = useRef<{ id: number; nodes: { eid: string; x: number; y: number; pinned: boolean }[] } | undefined>(undefined);
  const live = useRef({ topology, onOpenDevice, editor, t });
  useEffect(() => {
    live.current = { topology, onOpenDevice, editor, t };
  });
  const canDrag = save !== undefined;
  const editing = editor !== undefined;
  const editingRef = useRef(editing);

  useEffect(() => {
    pinOvRef.current = pinOv;
    posOvRef.current = posOv;
    editingRef.current = editing;
  });

  /* batched saving of dragged positions */
  useEffect(() => {
    if (!save) return;
    const s = new PositionSaver(
      save,
      (items) => {
        const ids = new Set(items.map((i) => i.device_id));
        setPosOv((m) => new Map([...m].filter(([id]) => !ids.has(id))));
        setPinOv((p) => new Set([...p].filter((id) => !ids.has(id))));
        onSaved?.(items);
      },
      (e) => onSaveError?.(e),
    );
    saver.current = s;
    /* positions the client laid out are stored as soon as they can be, so zones and the server's areas see them too */
    for (const n of live.current.topology.nodes) {
      const p = posOvRef.current.get(n.device_id);
      if (p && (n.x == null || n.y == null)) s.queue({ device_id: n.device_id, x: p.x, y: p.y, pinned: false });
    }
    return () => {
      saver.current = undefined;
      s.dispose();
      void s.flush();
    };
  }, [save, onSaved, onSaveError]);

  const placeLabel = useCallback((eid: string, el: HTMLDivElement) => {
    const n = cyRef.current?.getElementById(eid);
    if (!n || n.empty()) {
      el.hidden = true;
      return;
    }
    const p = n.position();
    el.hidden = false;
    el.style.transform = `translate(${p.x - LABEL_W / 2}px, ${p.y + NODE_H / 2 + 2}px)`;
  }, []);
  const registerLabel = useCallback(
    (eid: string, el: HTMLDivElement | null) => {
      if (!el) return void labelEls.current.delete(eid);
      labelEls.current.set(eid, el);
      placeLabel(eid, el);
    },
    [placeLabel],
  );

  /* the canvas, created once */
  useEffect(() => {
    const cy = cytoscape({
      container: host.current,
      elements: [],
      minZoom: 0.02,
      maxZoom: 4,
      wheelSensitivity: 0.3,
      userZoomingEnabled: !compactRef.current,
      boxSelectionEnabled: false,
      autounselectify: true,
      hideEdgesOnViewport: large,
      textureOnViewport: large,
      /* a compact map renders a quarter finer, so it stays sharp while its dashboard widget is enlarged (bubble) */
      pixelRatio: large ? 1 : compactRef.current ? (window.devicePixelRatio || 1) * 1.25 : "auto",
    });
    cyRef.current = cy;

    const transform = () => {
      const z = cy.zoom();
      const p = cy.pan();
      const tf = `translate(${p.x}px, ${p.y}px) scale(${z})`;
      if (img.current) img.current.style.transform = tf;
      if (labelWorld.current) {
        labelWorld.current.style.transform = tf;
        labelWorld.current.classList.toggle("invisible", z < (compactRef.current ? LABEL_ZOOM_COMPACT : LABEL_ZOOM));
      }
      if (ground.current) {
        const g = GRID * z;
        ground.current.style.backgroundSize = g < GRID_MIN ? "0 0" : `${g}px ${g}px`;
        ground.current.style.backgroundPosition = `${p.x}px ${p.y}px`;
      }
    };
    const onViewport = () => {
      const z = cy.zoom();
      transform();
      /* zones follow in the same frame as the canvas */
      store.set({ zoom: z, pan: { ...cy.pan() } });
      setHover(undefined);
      setTip(undefined);
      if (live.current.topology.areas.length > 0) {
        const next = isCollapsed(collapsedRef.current, z);
        if (next !== collapsedRef.current) {
          collapsedRef.current = next;
          setCollapsed(next);
        }
      }
    };
    cy.on("viewport", onViewport);
    transform();

    cy.on("position", "node[kind = 'device']", (e: EventObject) => {
      const el = labelEls.current.get(e.target.id());
      if (el) placeLabel(e.target.id(), el);
    });

    cy.on("tap", (e: EventObject) => {
      if (e.target === cy) return live.current.editor?.onSelect(undefined);
      const n = e.target;
      if (!n.isNode()) return;
      const kind = n.data("kind") as string;
      if (kind === "device") live.current.onOpenDevice(devId(n.id()), String(n.data("label")));
      else if (kind === "group") cy.animate({ zoom: { level: OPEN_ZOOM, position: n.position() }, duration: 250 });
    });

    cy.on("dragfree", "node[kind = 'device']", (e: EventObject) => {
      const id = devId(e.target.id());
      const p = e.target.position();
      setPosOv((m) => new Map(m).set(id, { x: p.x, y: p.y }));
      setPinOv((s) => new Set(s).add(id));
      saver.current?.queue({ device_id: id, x: p.x, y: p.y, pinned: true });
    });

    cy.on("cxttap", "node[kind = 'device'][?pinned]", (e: EventObject) => {
      if (!saver.current) return;
      const id = devId(e.target.id());
      const p = e.target.position();
      setPinOv((s) => {
        const n = new Set(s);
        n.delete(id);
        return n;
      });
      e.target.data("pinned", false);
      saver.current.queue({ device_id: id, x: p.x, y: p.y, pinned: false });
    });

    cy.on("mouseover", "node, edge", (e: EventObject) => {
      const el = e.target;
      el.addClass("hover");
      if (host.current) host.current.style.cursor = el.isNode() ? (editingRef.current && el.grabbable() ? "grab" : "pointer") : "default";
      const d = el.data();
      if (el.isNode() && d.kind === "device") {
        (el as NodeSingular).connectedEdges().addClass("ports");
        const p = el.renderedPosition();
        setHover({ id: devId(el.id()), x: p.x, y: p.y, r: Math.max((el as NodeSingular).renderedWidth(), LABEL_W * cyRef.current!.zoom()) / 2, box: { w: host.current?.clientWidth ?? 0, h: host.current?.clientHeight ?? 0 } });
        return;
      }
      const lines: string[] = el.isEdge() ? (d.aggregate ? [live.current.t("map.tip.links", { count: d.aggregate })] : [`${d.nameA} ${d.portA}`, `${d.nameB} ${d.portB}`]) : [d.label];
      setTip({ x: e.renderedPosition.x, y: e.renderedPosition.y, lines: lines.map((l) => String(l).trim()).filter(Boolean) });
    });
    cy.on("mouseout", "node, edge", (e: EventObject) => {
      e.target.removeClass("hover");
      if (e.target.isNode()) (e.target as NodeSingular).connectedEdges().removeClass("ports");
      if (host.current) host.current.style.cursor = "default";
      setTip(undefined);
      setHover(undefined);
    });
    cy.on("grab", () => {
      setTip(undefined);
      setHover(undefined);
    });

    return () => {
      cy.destroy();
      cyRef.current = undefined;
    };
  }, [store, placeLabel, large]);

  useEffect(() => {
    cyRef.current?.style(buildStylesheet({ dark, large: large }));
  }, [dark, large]);

  /* a background that arrives (or changes) after the canvas was panned must follow the current view at once */
  useEffect(() => {
    const cy = cyRef.current;
    if (cy && img.current) img.current.style.transform = `translate(${cy.pan().x}px, ${cy.pan().y}px) scale(${cy.zoom()})`;
  }, [backgroundUrl]);

  /* zones are edited at full detail: no collapsing in edit mode */
  const shown = collapsed && !editing;
  const model = useMemo(() => buildModel(topology, shown, severity, { pos: posOv, pinned: pinOv }), [topology, shown, severity, posOv, pinOv]);
  const byDevice = useMemo(() => new Map(topology.nodes.map((n) => [n.device_id, n])), [topology.nodes]);
  const labels: LabelItem[] = useMemo(
    () =>
      large
        ? []
        : model.nodes.filter((n) => n.kind === "device").map((n) => ({ eid: n.id, name: String(n.data.label), address: safeText(byDevice.get(n.deviceId!)?.address) })),
    [model, byDevice, large],
  );

  const applyLayout = useCallback(async (scope: ReadonlySet<string> | undefined, persist: boolean) => {
    const topo = live.current.topology;
    try {
      const pinned = new Set(topo.nodes.filter((n) => n.pinned).map((n) => deviceEid(n.device_id)));
      for (const id of pinOvRef.current) pinned.add(deviceEid(id));
      /* devices that keep their place: new ones of no area are put clear of them */
      const fixed = new Map<string, { x: number; y: number }>();
      for (const n of topo.nodes) {
        const eid = deviceEid(n.device_id);
        const p = posOvRef.current.get(n.device_id) ?? (n.x != null && n.y != null ? { x: n.x, y: n.y } : undefined);
        if (p && (pinned.has(eid) || (scope && !scope.has(eid)))) fixed.set(eid, p);
      }
      const laid = placeDevices(await runLayout(buildElkGraph(topo)), topo, fixed);
      const moves = layoutMoves(laid, pinned, scope);
      const items: PositionItem[] = [...moves].map(([eid, p]) => ({ device_id: devId(eid), x: p.x, y: p.y, pinned: false }));
      setPosOv((m) => {
        const n = new Map(m);
        for (const it of items) n.set(it.device_id, { x: it.x, y: it.y });
        return n;
      });
      setLayoutError(false);
      if (persist && saver.current) for (const it of items) saver.current.queue(it);
    } catch {
      setLayoutError(true);
    }
  }, []);

  /* the whole picture in view: devices with their labels and the zones (HTML over the canvas, so cy.fit misses them), at most 125 % */
  const fit = useCallback(() => {
    const cy = cyRef.current;
    if (!cy || cy.width() === 0) return;
    const pad = compact ? 16 : 48;
    const b = cy.elements().boundingBox();
    let [x1, y1, x2, y2] = [b.x1, b.y1, b.x2, b.y2 + LABEL_H];
    for (const a of live.current.topology.areas) {
      [x1, y1, x2, y2] = [Math.min(x1, a.x), Math.min(y1, a.y), Math.max(x2, a.x + a.w), Math.max(y2, a.y + a.h)];
    }
    if (!(x2 > x1 && y2 > y1)) return;
    /* the zoom buttons take a column on the right */
    const right = pad + 40;
    const zoom = Math.min((cy.width() - pad - right) / (x2 - x1), (cy.height() - 2 * pad) / (y2 - y1), 1.25);
    cy.viewport({ zoom, pan: { x: pad + (cy.width() - pad - right - zoom * (x2 - x1)) / 2 - zoom * x1, y: (cy.height() - zoom * (y1 + y2)) / 2 } });
  }, [compact]);

  /* model -> canvas; devices without a position are laid out once */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const need = syncElements(cy, model, { canDrag, moving: new Set(carried.current?.nodes.map((n) => n.eid)) });
    /* moves fire "position" and place their labels; only labels of nodes just added still wait */
    for (const [eid, el] of labelEls.current) if (el.hidden) placeLabel(eid, el);
    const fresh = need.filter((id) => !tried.current.has(id));
    if (fresh.length > 0) {
      for (const id of fresh) tried.current.add(id);
      void applyLayout(new Set(fresh), true);
    } else if (!fitted.current && model.nodes.length > 0 && need.length === 0) {
      fitted.current = true;
      fit();
    }
  }, [model, canDrag, applyLayout, placeLabel, fit]);
  const zoomBy = (f: number) => {
    const cy = cyRef.current;
    if (cy) cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  const pv = preview?.for === topology.areas ? preview.map : undefined;
  const areas: OverlayArea[] = useMemo(
    () => topology.areas.map((a) => ({ ...a, ...pv?.get(a.id), id: a.id, name: a.name, kind: a.kind, parent_id: a.parent_id, status: a.status, count: a.device_count })),
    [topology.areas, pv],
  );

  /* devices inside a zone that is being moved go along with it */
  const onPreview = useCallback((m: ReadonlyMap<number, Rect> | undefined, mv?: { id: number; dx: number; dy: number; from: Rect[] }) => {
    const topoAreas = live.current.topology.areas;
    setPreview(m ? { for: topoAreas, map: m } : undefined);
    const cy = cyRef.current;
    if (!cy) return;
    if (!mv) {
      for (const n of carried.current?.nodes ?? []) cy.getElementById(n.eid).position({ x: n.x, y: n.y });
      carried.current = undefined;
      return;
    }
    if (carried.current?.id !== mv.id) {
      /* the devices inside the zone (and its sub-zones) where the drag started */
      const nodes = cy.nodes("[kind = 'device']").filter((n) => mv.from.some((r) => insideRect(r, n.position())));
      carried.current = { id: mv.id, nodes: nodes.map((n) => ({ eid: n.id(), pinned: n.data("pinned") === true, ...(n as NodeSingular).position() })) };
    }
    for (const n of carried.current.nodes) cy.getElementById(n.eid).position({ x: n.x + mv.dx, y: n.y + mv.dy });
  }, []);

  const carry = useCallback(
    (id: number, dx: number, dy: number) => {
      const cy = cyRef.current;
      const moved = carried.current?.id === id ? carried.current.nodes : [];
      carried.current = undefined;
      if (cy && moved.length > 0) {
        /* they keep their pin state: a zone move is not a decision about each device */
        const items = moved.map((n) => ({ device_id: devId(n.eid), x: n.x + dx, y: n.y + dy, pinned: n.pinned }));
        for (const it of items) cy.getElementById(deviceEid(it.device_id)).position({ x: it.x, y: it.y });
        setPosOv((m) => {
          const next = new Map(m);
          for (const it of items) next.set(it.device_id, { x: it.x, y: it.y });
          return next;
        });
        for (const it of items) saver.current?.queue(it);
      }
    },
    [],
  );

  const hovered = hover && byDevice.get(hover.id);

  return (
    <div
      ref={ground}
      className={`relative h-full w-full overflow-hidden rounded-md border bg-card bg-[radial-gradient(circle,var(--color-border)_1.2px,transparent_1.3px)] ${compact ? "min-h-0" : "min-h-96"} ${editing ? "border-primary/60 ring-2 ring-primary/25" : ""}`}
      data-testid="network-map"
      data-editing={editing || undefined}
    >
      {backgroundUrl && <img ref={img} src={backgroundUrl} alt="" draggable={false} className="pointer-events-none absolute left-0 top-0 max-w-none origin-top-left select-none" />}
      {!shown && areas.length > 0 && <LiveZones store={store} areas={areas} />}
      <div
        ref={host}
        className="absolute inset-0"
        data-testid="map-canvas"
        onPointerLeave={() => {
          /* the pointer went onto a layer above the canvas: cytoscape sees no mouseout then */
          setHover(undefined);
          setTip(undefined);
          cyRef.current?.elements(".hover, .ports").removeClass("hover ports");
        }}
      />
      {!large && <NodeLabels items={labels} world={labelWorld} register={registerLabel} />}
      {editor && <LiveEditor store={store} areas={areas} editing={editor} onPreview={onPreview} onMoved={carry} />}
      <div className="absolute right-2 top-2 flex flex-col gap-0.5 rounded-lg border bg-background/90 p-0.5 shadow-sm">
        <Button size="icon-sm" variant="ghost" aria-label={t("map.zoomIn")} title={t("map.zoomIn")} onClick={() => zoomBy(1.4)}>
          <Plus />
        </Button>
        <Button size="icon-sm" variant="ghost" aria-label={t("map.zoomOut")} title={t("map.zoomOut")} onClick={() => zoomBy(1 / 1.4)}>
          <Minus />
        </Button>
        <Button size="icon-sm" variant="ghost" aria-label={t("map.fit")} title={t("map.fit")} onClick={fit}>
          <Maximize />
        </Button>
        {!compact && (
          <Button size="icon-sm" variant="ghost" aria-label={t("map.layout")} title={t("map.layoutHint")} onClick={() => void applyLayout(undefined, canDrag)}>
            <Workflow />
          </Button>
        )}
      </div>
      {hovered && hover && <MapHoverCard node={hovered} problems={problems?.get(hovered.device_id) ?? 0} x={hover.x} y={hover.y} r={hover.r} box={hover.box} />}
      {tip && tip.lines.length > 0 && (
        <div role="tooltip" className="pointer-events-none absolute z-20 max-w-64 rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow" style={{ left: tip.x + 12, top: tip.y + 12 }}>
          {tip.lines.map((l, i) => (
            <div key={i} className="truncate">
              {l}
            </div>
          ))}
        </div>
      )}
      {shown && !compact && <div className="pointer-events-none absolute bottom-2 left-2 rounded-md bg-background/80 px-2 py-1 text-xs text-muted-foreground">{t("map.collapsedHint")}</div>}
      {layoutError && (
        <p role="alert" className="absolute bottom-2 right-2 rounded-md bg-background/90 px-2 py-1 text-xs text-destructive">
          {t("map.layoutFailed")}
        </p>
      )}
    </div>
  );
}
