import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { type Core, type EventObject } from "cytoscape";
import { Maximize, Minus, Plus, Workflow } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { AreaOverlay, type OverlayArea, type Rect, type Viewport } from "./AreaOverlay";
import { buildElkGraph, devicePositions, layoutMoves, runLayout } from "./layout";
import { PositionSaver, type PositionItem } from "./positions";
import { buildModel, deviceEid, isCollapsed, OPEN_ZOOM, type Topology } from "./semanticZoom";
import { buildStylesheet } from "./style";
import { syncElements } from "./sync";
import type { EventSeverity } from "@/features/problems/api";

/* above this many devices the renderer drops edges and uses a texture while panning, and edges are straight */
const LARGE = 1500;

export type AreaEditor = {
  tool: "select" | "draw";
  selectedId?: number;
  onSelect: (id: number | undefined) => void;
  onDraw: (r: Rect) => void;
  onChange: (id: number, r: Rect) => void;
};

type Props = {
  topology: Topology;
  severity: ReadonlyMap<number, EventSeverity>;
  /** Background image of the view (same-origin URL); drawn as an <img> layer under the canvas. */
  backgroundUrl?: string;
  /** Persists dragged positions into this view (map.manage and a view chosen). */
  save?: (items: PositionItem[]) => Promise<void>;
  onSaved?: (items: PositionItem[]) => void;
  onSaveError?: (err: unknown) => void;
  onOpenDevice: (id: number) => void;
  editor?: AreaEditor;
  /** Widget mode (mini map): no autolayout button, no wheel zoom (the page keeps scrolling), no hint strip; same data and interactions otherwise. */
  compact?: boolean;
};

type Tip = { x: number; y: number; lines: string[] };

function useDark(): boolean {
  const [dark, setDark] = useState(() => document.documentElement.classList.contains("dark"));
  useEffect(() => {
    const mo = new MutationObserver(() => setDark(document.documentElement.classList.contains("dark")));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => mo.disconnect();
  }, []);
  return dark;
}

/**
 * The interactive map: devices and links on a Cytoscape canvas (areas as compound nodes, collapsed into one node each
 * at low zoom), ELK autolayout in a Web Worker, drag = pin with batched saving. All text comes from safeText'd data and is
 * only ever drawn on the canvas or set as text content.
 */
export function NetworkMap({ topology, severity, backgroundUrl, save, onSaved, onSaveError, onOpenDevice, editor, compact = false }: Props) {
  const { t } = useTranslation();
  const dark = useDark();
  const host = useRef<HTMLDivElement>(null);
  const img = useRef<HTMLImageElement>(null);
  const cyRef = useRef<Core | undefined>(undefined);
  const [collapsed, setCollapsed] = useState(false);
  const collapsedRef = useRef(false);
  const [tip, setTip] = useState<Tip | undefined>();
  const [viewport, setViewport] = useState<Viewport>({ zoom: 1, pan: { x: 0, y: 0 } });
  const [layoutError, setLayoutError] = useState(false);
  const large = useRef(topology.nodes.length > LARGE);
  const compactRef = useRef(compact);

  /* client-side state not on the server yet */
  const [posOv, setPosOv] = useState<ReadonlyMap<number, { x: number; y: number }>>(new Map());
  const [pinOv, setPinOv] = useState<ReadonlySet<number>>(new Set());
  const pinOvRef = useRef(pinOv);
  const tried = useRef(new Set<string>());
  const fitted = useRef(false);
  const saver = useRef<PositionSaver | undefined>(undefined);
  const live = useRef({ topology, onOpenDevice, editor, t });
  useEffect(() => {
    live.current = { topology, onOpenDevice, editor, t };
  });
  const canDrag = save !== undefined;

  useEffect(() => {
    pinOvRef.current = pinOv;
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
    return () => {
      saver.current = undefined;
      s.dispose();
      void s.flush();
    };
  }, [save, onSaved, onSaveError]);

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
      hideEdgesOnViewport: large.current,
      textureOnViewport: large.current,
      pixelRatio: 1,
    });
    cyRef.current = cy;

    let raf = 0;
    const onViewport = () => {
      const z = cy.zoom();
      const p = cy.pan();
      if (img.current) {
        img.current.style.transformOrigin = "0 0";
        img.current.style.transform = `translate(${p.x}px, ${p.y}px) scale(${z})`;
      }
      if (live.current.editor && !raf) {
        raf = requestAnimationFrame(() => {
          raf = 0;
          setViewport({ zoom: cy.zoom(), pan: { ...cy.pan() } });
        });
      }
      if (live.current.topology.areas.length > 0) {
        const next = isCollapsed(collapsedRef.current, z);
        if (next !== collapsedRef.current) {
          collapsedRef.current = next;
          setCollapsed(next);
        }
      }
    };
    cy.on("viewport", onViewport);

    cy.on("tap", (e: EventObject) => {
      if (e.target === cy) return live.current.editor?.onSelect(undefined);
      const n = e.target;
      if (!n.isNode()) return;
      const kind = n.data("kind") as string;
      if (kind === "device") live.current.onOpenDevice(Number(String(n.id()).slice(1)));
      else if (kind === "group") cy.animate({ zoom: { level: OPEN_ZOOM, position: n.position() }, duration: 250 });
    });

    cy.on("dragfree", "node[kind = 'device']", (e: EventObject) => {
      const id = Number(String(e.target.id()).slice(1));
      const p = e.target.position();
      setPosOv((m) => new Map(m).set(id, { x: p.x, y: p.y }));
      setPinOv((s) => new Set(s).add(id));
      e.target.data("pinned", true);
      saver.current?.queue({ device_id: id, x: p.x, y: p.y, pinned: true });
    });

    cy.on("cxttap", "node[kind = 'device'][?pinned]", (e: EventObject) => {
      if (!saver.current) return;
      const id = Number(String(e.target.id()).slice(1));
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
      if (host.current) host.current.style.cursor = el.isNode() && el.data("kind") !== "area" ? "pointer" : "default";
      const d = el.data();
      let lines: string[];
      if (el.isEdge()) lines = d.aggregate ? [live.current.t("map.tip.links", { count: d.aggregate })] : [`${d.nameA} ${d.portA}`, `${d.nameB} ${d.portB}`];
      else lines = [d.label];
      setTip({ x: e.renderedPosition.x, y: e.renderedPosition.y, lines: lines.map((l) => String(l).trim()).filter(Boolean) });
    });
    cy.on("mouseout", "node, edge", (e: EventObject) => {
      e.target.removeClass("hover");
      if (host.current) host.current.style.cursor = "default";
      setTip(undefined);
    });
    cy.on("grab", () => setTip(undefined));

    return () => {
      cancelAnimationFrame(raf);
      cy.destroy();
      cyRef.current = undefined;
    };
  }, []);

  useEffect(() => {
    cyRef.current?.style(buildStylesheet({ dark, large: large.current }));
  }, [dark]);

  const model = useMemo(() => buildModel(topology, collapsed, severity, { pos: posOv, pinned: pinOv }), [topology, collapsed, severity, posOv, pinOv]);

  const applyLayout = useCallback(
    async (scope: ReadonlySet<string> | undefined, persist: boolean) => {
      const topo = live.current.topology;
      try {
        const laid = devicePositions(await runLayout(buildElkGraph(topo)));
        const pinned = new Set(topo.nodes.filter((n) => n.pinned).map((n) => deviceEid(n.device_id)));
        for (const id of pinOvRef.current) pinned.add(deviceEid(id));
        const moves = layoutMoves(laid, pinned, scope);
        const items: PositionItem[] = [...moves].map(([eid, p]) => ({ device_id: Number(eid.slice(1)), x: p.x, y: p.y, pinned: false }));
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
    },
    [],
  );

  /* model -> canvas; devices without a position are laid out once */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const need = syncElements(cy, model, { canDrag });
    const fresh = need.filter((id) => !tried.current.has(id));
    if (fresh.length > 0) {
      for (const id of fresh) tried.current.add(id);
      void applyLayout(new Set(fresh), false);
    } else if (!fitted.current && model.nodes.length > 0 && need.length === 0) {
      fitted.current = true;
      cy.fit(undefined, 40);
    }
  }, [model, canDrag, applyLayout]);

  const fit = () => cyRef.current?.fit(undefined, 40);
  const zoomBy = (f: number) => {
    const cy = cyRef.current;
    if (cy) cy.zoom({ level: cy.zoom() * f, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  const overlayAreas: OverlayArea[] = useMemo(() => topology.areas.map((a) => ({ id: a.id, name: a.name, x: a.x, y: a.y, w: a.w, h: a.h })), [topology.areas]);

  return (
    <div className={`relative h-full w-full overflow-hidden rounded-md border bg-card ${compact ? "min-h-0" : "min-h-96"}`} data-testid="network-map">
      {backgroundUrl && <img ref={img} src={backgroundUrl} alt="" draggable={false} className="pointer-events-none absolute left-0 top-0 max-w-none select-none" />}
      <div ref={host} className="absolute inset-0" data-testid="map-canvas" />
      {editor && <AreaOverlay areas={overlayAreas} viewport={viewport} tool={editor.tool} selectedId={editor.selectedId} onSelect={editor.onSelect} onDraw={editor.onDraw} onChange={editor.onChange} />}
      <div className="absolute right-2 top-2 flex flex-col gap-1">
        <Button size="icon" variant="outline" aria-label={t("map.zoomIn")} onClick={() => zoomBy(1.4)}>
          <Plus />
        </Button>
        <Button size="icon" variant="outline" aria-label={t("map.zoomOut")} onClick={() => zoomBy(1 / 1.4)}>
          <Minus />
        </Button>
        <Button size="icon" variant="outline" aria-label={t("map.fit")} onClick={fit}>
          <Maximize />
        </Button>
        {!compact && (
          <Button size="icon" variant="outline" aria-label={t("map.layout")} title={t("map.layoutHint")} onClick={() => void applyLayout(undefined, canDrag)}>
            <Workflow />
          </Button>
        )}
      </div>
      {tip && tip.lines.length > 0 && (
        <div role="tooltip" className="pointer-events-none absolute z-10 max-w-64 rounded-md border bg-popover px-2 py-1 text-xs text-popover-foreground shadow" style={{ left: tip.x + 12, top: tip.y + 12 }}>
          {tip.lines.map((l, i) => (
            <div key={i} className="truncate">
              {l}
            </div>
          ))}
        </div>
      )}
      {collapsed && !compact && <div className="pointer-events-none absolute bottom-2 left-2 rounded-md bg-background/80 px-2 py-1 text-xs text-muted-foreground">{t("map.collapsedHint")}</div>}
      {layoutError && (
        <p role="alert" className="absolute bottom-2 right-2 rounded-md bg-background/90 px-2 py-1 text-xs text-destructive">
          {t("map.layoutFailed")}
        </p>
      )}
    </div>
  );
}
