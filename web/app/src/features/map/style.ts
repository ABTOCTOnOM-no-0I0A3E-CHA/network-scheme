import type { StylesheetJson } from "cytoscape";
import type { components } from "@/api/schema";
import type { EventSeverity } from "@/features/problems/api";

type S = components["schemas"];
export type NodeState = S["TopologyNode"]["state"];
export type TopologyLink = S["TopologyLink"];

export const STATE_COLOR: Record<NodeState, string> = { up: "#16a34a", partial: "#d97706", down: "#dc2626", unknown: "#6b7280" };

/** Ring color of a device with open problems, by its worst severity. */
export const SEVERITY_COLOR: Record<EventSeverity, string> = {
  info: "#0ea5e9",
  warning: "#eab308",
  average: "#f97316",
  high: "#ef4444",
  disaster: "#7f1d1d",
};

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

const svg = (body: string) =>
  `data:image/svg+xml;utf8,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`)}`;

const ICONS = {
  switch: svg('<rect x="2" y="8" width="20" height="8" rx="1"/><path d="M6 12h.01M10 12h.01M14 12h.01M18 12h.01"/>'),
  router: svg('<rect x="3" y="14" width="18" height="6" rx="1"/><path d="M7 17h.01M11 17h.01M8 10l4-4 4 4M12 6v6"/>'),
  device: svg('<rect x="3" y="4" width="18" height="12" rx="1"/><path d="M8 20h8M12 16v4"/>'),
  area: svg('<path d="M3 21h18M5 21V7l7-4 7 4v14M9 21v-6h6v6"/>'),
} as const;
export type IconKey = keyof typeof ICONS;

/** Icon kind by driver name (the topology carries no model): Eltex MES are switches, ESR are routers. */
export function iconKey(driver: string): IconKey {
  if (driver === "eltex-mes") return "switch";
  if (driver === "eltex-esr") return "router";
  return "device";
}

export const iconUri = (k: IconKey): string => ICONS[k];

/** Cytoscape stylesheet. `large` swaps expensive curved edges for haystack ones; `dark` flips label colors for the dark theme. */
export function buildStylesheet(opts: { dark: boolean; large: boolean }): StylesheetJson {
  const text = opts.dark ? "#e5e7eb" : "#1f2937";
  return [
    {
      selector: "node",
      style: {
        width: 34,
        height: 34,
        "background-color": "data(color)",
        "background-image": "data(icon)",
        "background-fit": "contain",
        "background-width": "62%",
        "background-height": "62%",
        "border-width": "data(ring)",
        "border-color": "data(ringColor)",
        label: "data(label)",
        color: text,
        "font-size": 11,
        "text-valign": "bottom",
        "text-margin-y": 4,
        "text-wrap": "ellipsis",
        "text-max-width": "110px",
        "min-zoomed-font-size": 8,
      },
    },
    { selector: "node[?pinned]", style: { "outline-width": 2, "outline-color": "#0ea5e9", "outline-offset": 1 } },
    {
      selector: "node:parent",
      style: {
        shape: "round-rectangle",
        "background-opacity": 0.05,
        "background-image": "none",
        "border-width": 1.5,
        "border-style": "dashed",
        "border-color": "data(color)",
        padding: "24px",
        "text-valign": "top",
        "text-margin-y": -4,
        "font-weight": "bold",
        "text-max-width": "300px",
      },
    },
    {
      selector: "node[kind = 'area'], node[kind = 'group']",
      style: { shape: "round-rectangle", width: "data(w)", height: "data(h)", "background-opacity": 0.08, "border-width": 2, "border-color": "data(color)", "text-valign": "center", "text-margin-y": 0, "background-width": "30%", "background-height": "30%" },
    },
    {
      selector: "edge",
      style: {
        width: "data(width)",
        "line-color": "data(color)",
        "line-style": "solid",
        "curve-style": opts.large ? "haystack" : "bezier",
        opacity: 0.85,
      },
    },
    { selector: "edge[?dashed]", style: { "line-style": "dashed" } },
    { selector: "edge:selected, edge.hover", style: { opacity: 1, "overlay-opacity": 0.12, "overlay-color": text } },
    { selector: "node.hover", style: { "overlay-opacity": 0.1, "overlay-color": text } },
  ] as StylesheetJson;
}
