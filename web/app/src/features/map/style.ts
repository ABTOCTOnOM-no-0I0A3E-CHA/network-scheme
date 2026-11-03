import type { StylesheetJson } from "cytoscape";
import type { components } from "@/api/schema";

type S = components["schemas"];
export type NodeState = S["TopologyNode"]["state"];
export type TopologyLink = S["TopologyLink"];

export const STATE_COLOR: Record<NodeState, string> = { up: "#16a34a", partial: "#d97706", down: "#dc2626", unknown: "#6b7280" };

const ORDER: NodeState[] = ["up", "unknown", "partial", "down"];

/** The worse of two availability states (down > partial > unknown > up), the order the server uses for areas. */
export function worseState(a: NodeState, b: NodeState): NodeState {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b;
}

/** Link width in pixels by speed in bit/s: thicker for faster links; unknown speed is the thinnest-but-visible default. */
export function linkWidth(speedBps: number | null): number {
  if (speedBps === null || speedBps <= 0) return 1.5;
  if (speedBps < 100e6) return 1;
  if (speedBps < 1e9) return 2;
  if (speedBps < 10e9) return 3;
  if (speedBps < 40e9) return 4.5;
  return 6;
}

type Pos = { x: number; y: number };
type EdgeEnds = { source(): { position(): Pos }; target(): { position(): Pos } };

/**
 * How far along a link its port name sits from one end: past the device's label chip when the link leaves downwards
 * (through the chip), close to the device otherwise, so the two names of a short link never meet.
 */
export function portLabelOffset(from: Pos, to: Pos): number {
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  return dy > Math.abs(dx) * 0.5 ? 46 : 20;
}

export const LINK_COLOR = { ok: "#64748b", partial: "#d97706", down: "#dc2626", manual: "#7c3aed" } as const;
/** Links below this confidence are drawn dashed: only one side (or a MAC table) vouches for them. */
export const CONFIDENCE_SOLID = 0.8;

export type LinkStyle = { width: number; color: string; dashed: boolean };

/** Visual style of a link: width by speed, color by the worse end state, violet when drawn by hand, dashed when not well corroborated. */
export function linkStyle(l: Pick<TopologyLink, "speed_bps" | "confidence" | "manual">, a: NodeState, b: NodeState): LinkStyle {
  const worst = worseState(a, b);
  const color = l.manual ? LINK_COLOR.manual : worst === "down" ? LINK_COLOR.down : worst === "partial" ? LINK_COLOR.partial : LINK_COLOR.ok;
  return { width: linkWidth(l.speed_bps), color, dashed: !l.manual && l.confidence < CONFIDENCE_SOLID };
}

/* device node box (model units): the pictogram fills it; the name and address go below it */
export const NODE_W = 60;
export const NODE_H = 52;
/* room the label below a device takes (model units), kept free by the layout */
export const LABEL_W = 132;
export const LABEL_H = 38;

/**
 * Cytoscape stylesheet. A device is a transparent box holding four image layers, drawn in order: the problem halo (spilling
 * over the box, unclipped), the role pictogram, the status lamp (top right) and the pin (top left); a layer that is off is a
 * transparent placeholder. `large` swaps
 * curved edges for haystack ones and draws the names on the canvas (the label layer is off then); `dark` flips text colors.
 */
export function buildStylesheet(opts: { dark: boolean; large: boolean }): StylesheetJson {
  const text = opts.dark ? "#e5e7eb" : "#1f2937";
  const chip = opts.dark ? "#111827" : "#ffffff";
  return [
    {
      selector: "node",
      style: {
        label: "data(label)",
        color: text,
        "font-size": 11,
        "font-family": "Inter Variable, Inter, system-ui, sans-serif",
        "text-valign": "bottom",
        "text-margin-y": 5,
        "text-wrap": "ellipsis",
        "text-max-width": `${LABEL_W - 12}px`,
        "text-background-color": chip,
        "text-background-opacity": 0.85,
        "text-background-padding": "2px",
        "text-background-shape": "round-rectangle",
        "min-zoomed-font-size": 7,
      },
    },
    {
      selector: "node[kind = 'device']",
      style: {
        shape: "round-rectangle",
        width: NODE_W,
        height: NODE_H,
        "background-opacity": 0,
        "border-width": 0,
        label: opts.large ? "data(label)" : "",
        "background-image": "data(images)",
        "background-width": ["170%", "100%", "15px", "15px"],
        "background-height": ["175%", "100%", "15px", "15px"],
        "background-position-x": ["50%", "50%", "100%", "0%"],
        "background-position-y": ["55%", "50%", "10%", "6%"],
        /* the halo, lamp and pin are not clipped to the box (containment stays "inside": "over" images are drawn last, above the pictogram) */
        "background-clip": ["none", "node", "none", "none"],
        "background-image-smoothing": "yes",
        "bounds-expansion": 24,
      },
    },
    { selector: "node[kind = 'device'].hover", style: { "underlay-color": "#0ea5e9", "underlay-opacity": 0.12, "underlay-padding": 6, "underlay-shape": "round-rectangle", "underlay-corner-radius": 10 } },
    {
      selector: "node[kind = 'group']",
      style: {
        shape: "round-rectangle",
        width: "data(w)",
        height: "data(h)",
        "background-color": "data(color)",
        "background-opacity": 0.12,
        "border-width": 2,
        "border-color": "data(color)",
        "background-image": "data(icon)",
        "background-fit": "contain",
        "background-width": "60%",
        "background-height": "60%",
        "text-valign": "bottom",
        "font-weight": "bold",
      },
    },
    { selector: "node[kind = 'group'].hover", style: { "overlay-opacity": 0.08, "overlay-color": text } },
    {
      selector: "edge",
      style: {
        width: "data(width)",
        "line-color": "data(color)",
        "line-style": "solid",
        "line-cap": "round",
        "curve-style": opts.large ? "haystack" : "bezier",
        "control-point-step-size": 26,
        opacity: 0.9,
        "font-size": 10,
        color: text,
        "text-background-color": chip,
        "text-background-opacity": 0.92,
        "text-background-padding": "2px",
        "text-background-shape": "round-rectangle",
        "text-border-color": opts.dark ? "#374151" : "#cbd5e1",
        "text-border-width": 1,
        "text-border-opacity": 1,
        /* evaluated when the names show (hover), so they follow the current positions */
        "source-text-offset": ((e: EdgeEnds) => portLabelOffset(e.source().position(), e.target().position())) as unknown as number,
        "target-text-offset": ((e: EdgeEnds) => portLabelOffset(e.target().position(), e.source().position())) as unknown as number,
      },
    },
    { selector: "edge[?dashed]", style: { "line-style": "dashed" } },
    { selector: "edge.hover, edge.ports", style: { opacity: 1, "source-label": "data(portA)", "target-label": "data(portB)" } },
    { selector: "edge.hover", style: { "underlay-color": "#0ea5e9", "underlay-opacity": 0.25, "underlay-padding": 3 } },
  ] as StylesheetJson;
}
