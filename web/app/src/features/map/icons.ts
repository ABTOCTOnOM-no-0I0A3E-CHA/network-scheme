import type { components } from "@/api/schema";
import type { EventSeverity } from "@/features/problems/api";

/*
 * Device pictograms in the spirit of Packet Tracer's logical workspace: small oblique 3D bodies (front, lit top, shaded
 * side) in one palette, drawn from constant markup into data: URIs once at module load (CSP: img-src 'self' data:). They
 * hold no device data. Viewbox 64x56; readable from ~40 px up.
 */

export type DeviceRole = components["schemas"]["DeviceRole"];
type Pt = [number, number];

const W = 64;
const H = 56;
const LINE = "#12324f";

const uri = (w: number, h: number, body: string) =>
  `data:image/svg+xml;utf8,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w * 2}" height="${h * 2}">${body}</svg>`)}`;

const pts = (p: Pt[]) => p.map(([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`).join(" ");
const poly = (p: Pt[], fill: string, extra = "") => `<polygon points="${pts(p)}" fill="${fill}" ${extra}/>`;

type Palette = { top: string; front: [string, string]; side: string; edge: string };
const BLUE: Palette = { top: "#9fd0f5", front: ["#4b93d6", "#2a69ad"], side: "#1f528c", edge: LINE };
const STEEL: Palette = { top: "#d7e3f0", front: ["#9fb5cf", "#7590b3"], side: "#56708f", edge: "#2b3d55" };
const BRICK: Palette = { top: "#ffb48e", front: ["#e2643a", "#b9431f"], side: "#8c3316", edge: "#5a1f0c" };
const PALE: Palette = { top: "#f4f7fb", front: ["#dbe4ee", "#c3d0de"], side: "#a3b3c6", edge: "#4a5d75" };

const grad = (id: string, [a, b]: [string, string]) => `<linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${a}"/><stop offset="1" stop-color="${b}"/></linearGradient>`;

/** A box seen from the front-right: front rectangle, top parallelogram going back by `d` (up-right), right side. */
function slab(x: number, y: number, w: number, h: number, d: number, c: Palette, id = "f") {
  const dy = d / 2;
  const top: Pt[] = [
    [x, y],
    [x + d, y - dy],
    [x + w + d, y - dy],
    [x + w, y],
  ];
  const side: Pt[] = [
    [x + w, y],
    [x + w + d, y - dy],
    [x + w + d, y + h - dy],
    [x + w, y + h],
  ];
  const stroke = `stroke="${c.edge}" stroke-width="1" stroke-linejoin="round"`;
  const svg = `<defs>${grad(id, c.front)}</defs>${poly(side, c.side, stroke)}${poly(top, c.top, stroke)}<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="url(#${id})" ${stroke}/>`;
  /* maps (u, v) in [0,1]² of the top face to the picture: u along the front edge, v towards the back */
  const onTop = ([u, v]: Pt): Pt => [x + u * w + v * d, y - v * dy];
  return { svg, onTop };
}

/** A flat arrow from `a` to `b` in some plane coordinates, as polygon points of that plane. */
function arrow(a: Pt, b: Pt, t = 0.06, head = 0.16, hw = 0.13): Pt[] {
  const len = Math.hypot(b[0] - a[0], b[1] - a[1]);
  const ux = (b[0] - a[0]) / len;
  const uy = (b[1] - a[1]) / len;
  const at = (s: number, n: number): Pt => [a[0] + ux * s - uy * n, a[1] + uy * s + ux * n];
  const s = len - head;
  return [at(0, -t), at(s, -t), at(s, -hw), at(len, 0), at(s, hw), at(s, t), at(0, t)];
}

const ARROW = `stroke="#14406d" stroke-width="0.6" stroke-linejoin="round"`;

function ports(x: number, y: number, n: number, gap: number, size = 3.2) {
  let s = "";
  for (let i = 0; i < n; i++) s += `<rect x="${(x + i * gap).toFixed(2)}" y="${y}" width="${size}" height="${size * 0.8}" rx="0.4" fill="#0c2742"/>`;
  return s;
}
const led = (x: number, y: number, c = "#7dff9b") => `<circle cx="${x}" cy="${y}" r="1.1" fill="${c}"/>`;

function switchIcon(): string {
  const b = slab(4, 30, 38, 13, 20, BLUE);
  const right = arrow([0.16, 0.66], [0.84, 0.66], 0.07, 0.17, 0.17).map(b.onTop);
  const left = arrow([0.84, 0.3], [0.16, 0.3], 0.07, 0.17, 0.17).map(b.onTop);
  return b.svg + poly(right, "#fff", ARROW) + poly(left, "#fff", ARROW) + ports(8, 35.5, 7, 4.4) + led(8.5, 40.6) + led(12, 40.6);
}

function l3switchIcon(): string {
  const b = slab(4, 28, 38, 15, 20, BLUE);
  const c: Pt = [0.5, 0.5];
  const out = (to: Pt) => poly(arrow([c[0] + (to[0] - c[0]) * 0.25, c[1] + (to[1] - c[1]) * 0.25], to, 0.06, 0.16, 0.14).map(b.onTop), "#fff", ARROW);
  const inn = (from: Pt) => poly(arrow(from, [c[0] + (from[0] - c[0]) * 0.25, c[1] + (from[1] - c[1]) * 0.25], 0.06, 0.16, 0.14).map(b.onTop), "#fff", ARROW);
  return b.svg + out([0.93, 0.5]) + out([0.07, 0.5]) + inn([0.5, 1.02]) + inn([0.5, -0.02]) + ports(8, 33.5, 7, 4.4) + ports(8, 38, 7, 4.4) + led(38, 31.5);
}

function routerIcon(): string {
  const cx = 30;
  const cy = 24;
  const rx = 25;
  const ry = 9.5;
  const hgt = 15;
  const plane = ([u, v]: Pt): Pt => [cx + u * rx * 0.86, cy + v * ry * 0.86];
  const a = (from: Pt, to: Pt) => poly(arrow(from, to, 0.08, 0.26, 0.2).map(plane), "#fff", ARROW);
  return (
    `<defs>${grad("rb", ["#3f87cc", "#225d9d"])}<radialGradient id="rt" cx="0.4" cy="0.35" r="0.8"><stop offset="0" stop-color="#c4e4fb"/><stop offset="1" stop-color="#7dbbe9"/></radialGradient></defs>` +
    `<path d="M${cx - rx},${cy} v${hgt} a${rx},${ry} 0 0 0 ${2 * rx},0 v${-hgt} z" fill="url(#rb)" stroke="${LINE}" stroke-width="1" stroke-linejoin="round"/>` +
    `<ellipse cx="${cx}" cy="${cy}" rx="${rx}" ry="${ry}" fill="url(#rt)" stroke="${LINE}" stroke-width="1"/>` +
    /* two arrows in, two out: the classic router mark */
    a([-0.95, -0.02], [-0.18, -0.02]) +
    a([0.95, 0.02], [0.18, 0.02]) +
    a([-0.06, -0.12], [-0.06, -0.98]) +
    a([0.06, 0.12], [0.06, 0.98]) +
    `<path d="M${cx - rx + 5},${cy + hgt + 3.5} h${2 * rx - 10}" stroke="#163f69" stroke-width="0.8" opacity="0.5"/>` +
    led(cx - 14, cy + 12.5) +
    led(cx - 10, cy + 13.2)
  );
}

function firewallIcon(): string {
  const x = 6;
  const y = 18;
  const w = 36;
  const h = 28;
  const b = slab(x, y, w, h, 16, BRICK);
  let bricks = "";
  const rows = 4;
  for (let r = 1; r < rows; r++) bricks += `<path d="M${x},${y + (r * h) / rows} h${w}" stroke="#7a2a10" stroke-width="0.9"/>`;
  for (let r = 0; r < rows; r++) {
    const off = r % 2 === 0 ? w / 4 : w / 8;
    for (let bx = x + off; bx < x + w - 1; bx += w / 4) bricks += `<path d="M${bx.toFixed(2)},${y + (r * h) / rows} v${h / rows}" stroke="#7a2a10" stroke-width="0.9"/>`;
  }
  /* courses continue along the side */
  for (let r = 1; r < rows; r++) bricks += `<path d="M${x + w},${y + (r * h) / rows} l16,-8" stroke="#5e220d" stroke-width="0.8"/>`;
  const top = [b.onTop([0.1, 0.5]), b.onTop([0.9, 0.5])];
  return b.svg + bricks + `<path d="M${pts(top).replace(" ", " L")}" stroke="#a8401d" stroke-width="0.8"/>`;
}

function serverIcon(): string {
  const x = 18;
  const y = 12;
  const w = 22;
  const h = 38;
  const b = slab(x, y, w, h, 12, STEEL);
  let bays = "";
  for (let i = 0; i < 3; i++) bays += `<rect x="${x + 3}" y="${y + 4 + i * 7}" width="${w - 6}" height="4.6" rx="0.8" fill="#2c3f58"/><rect x="${x + 4.5}" y="${y + 5.6 + i * 7}" width="${w - 13}" height="1.4" fill="#5d7593"/>` + led(x + w - 5, y + 6.3 + i * 7);
  let grill = "";
  for (let i = 0; i < 4; i++) grill += `<path d="M${x + 4},${y + 29 + i * 2.2} h${w - 8}" stroke="#4d6585" stroke-width="0.8"/>`;
  return b.svg + bays + grill;
}

function apIcon(): string {
  const b = slab(10, 38, 36, 7, 14, PALE);
  const ant = (u: number) => {
    const [ax, ay] = b.onTop([u, 0.8]);
    return `<path d="M${ax},${ay} v-16" stroke="#3b4d63" stroke-width="2.2" stroke-linecap="round"/>`;
  };
  const [wx, wy] = b.onTop([0.5, 0.5]);
  const arcs = [7, 12, 17].map((r) => `<path d="M${wx - r * 0.75},${wy - 6 - r * 0.6} A${r},${r} 0 0 1 ${wx + r * 0.75},${wy - 6 - r * 0.6}" fill="none" stroke="#2a7fd0" stroke-width="2" stroke-linecap="round"/>`).join("");
  return ant(0.12) + ant(0.9) + b.svg + arcs + led(14, 41.5, "#22c55e") + led(18, 41.5, "#3b9cf0");
}

function pcIcon(): string {
  const m = slab(10, 10, 34, 25, 6, STEEL, "m");
  const screen = `<defs>${grad("s", ["#bfe6ff", "#5aa8e6"])}</defs><rect x="13" y="13" width="28" height="19" rx="0.8" fill="url(#s)" stroke="#2b3d55" stroke-width="0.6"/><path d="M15,16 l8,0 M15,19 l12,0" stroke="#ffffff" stroke-width="1" opacity="0.6"/>`;
  const stand = `<path d="M24,35 h6 l2,5 h-10 z" fill="#6f87a7" stroke="#2b3d55" stroke-width="0.8" stroke-linejoin="round"/>`;
  const kb = slab(10, 46, 30, 3.5, 10, PALE, "k");
  let keys = "";
  for (let r = 0; r < 2; r++) for (let i = 0; i < 6; i++) keys += poly(arrow([0.08 + i * 0.15, 0.3 + r * 0.38], [0.18 + i * 0.15, 0.3 + r * 0.38], 0.1, 0.0001, 0.1).map(kb.onTop), "#8fa2b8");
  return m.svg + screen + stand + kb.svg + keys;
}

function printerIcon(): string {
  const b = slab(8, 26, 40, 16, 14, PALE);
  const paper = poly([b.onTop([0.2, 0.75]), b.onTop([0.8, 0.75]), [b.onTop([0.8, 0.75])[0] + 2, b.onTop([0.8, 0.75])[1] - 12], [b.onTop([0.2, 0.75])[0] + 2, b.onTop([0.2, 0.75])[1] - 12]], "#ffffff", `stroke="#4a5d75" stroke-width="0.8" stroke-linejoin="round"`);
  const lines = `<path d="M${b.onTop([0.3, 0.75])[0] + 1},${b.onTop([0.3, 0.75])[1] - 8} h14 M${b.onTop([0.3, 0.75])[0] + 1.4},${b.onTop([0.3, 0.75])[1] - 5} h10" stroke="#9fb0c4" stroke-width="0.9"/>`;
  const tray = `<rect x="14" y="34" width="28" height="3.4" rx="0.8" fill="#2c3f58"/><path d="M12,42 h32 l-3,4 h-26 z" fill="#c3d0de" stroke="#4a5d75" stroke-width="0.8" stroke-linejoin="round"/>`;
  return paper + lines + b.svg + tray + led(12, 30, "#22c55e") + `<rect x="36" y="28.5" width="8" height="3" rx="0.5" fill="#5aa8e6"/>`;
}

function phoneIcon(): string {
  const b = slab(10, 34, 36, 10, 18, { top: "#8ea3bd", front: ["#61789a", "#475d7d"], side: "#364963", edge: "#1c2a3d" });
  const scr = poly([b.onTop([0.42, 0.55]), b.onTop([0.92, 0.55]), b.onTop([0.92, 0.92]), b.onTop([0.42, 0.92])], "#9ed3ff", `stroke="#0f1724" stroke-width="0.5"`);
  let keys = "";
  for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++) keys += poly(arrow([0.47 + c * 0.15, 0.12 + r * 0.14], [0.55 + c * 0.15, 0.12 + r * 0.14], 0.05, 0.0001, 0.05).map(b.onTop), "#d6dee8");
  const [hx, hy] = b.onTop([0.04, 0.5]);
  const handset = `<path d="M${hx + 1},${hy + 1} l3,-10 q1.5,-3 4.5,-1.6 l2.4,1.2 l-1.6,3.4 l-2,-0.8 l-2.6,8 l2.2,1 l-1.6,3.4 l-2.6,-1.2 q-3,-1.4 -1.7,-3.4 z" fill="#2b394d" stroke="#0f1724" stroke-width="0.8" stroke-linejoin="round"/>`;
  return b.svg + scr + keys + handset + led(14, 39, "#22c55e");
}

function cloudIcon(): string {
  return (
    `<defs><linearGradient id="c" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f3f8fd"/><stop offset="1" stop-color="#b9cde3"/></linearGradient></defs>` +
    `<path d="M15,44 C6,44 4,34 11,31 C9,23 18,18 24,22 C27,13 41,12 44,22 C52,19 59,26 55,33 C61,35 59,44 51,44 Z" fill="url(#c)" stroke="#47607e" stroke-width="1.4" stroke-linejoin="round"/>` +
    `<path d="M14,40 C24,42 40,42 52,40" stroke="#ffffff" stroke-width="1.4" fill="none" opacity="0.8"/>`
  );
}

function otherIcon(): string {
  const b = slab(10, 22, 30, 24, 16, STEEL);
  return b.svg + `<text x="25" y="40.5" text-anchor="middle" font-family="Arial, Helvetica, sans-serif" font-weight="700" font-size="17" fill="#ffffff" stroke="#2b3d55" stroke-width="0.6">?</text>`;
}

function areaIcon(): string {
  const b = slab(14, 14, 24, 34, 14, { top: "#e9e3f8", front: ["#a996d9", "#8269c2"], side: "#5f4a9c", edge: "#2f2257" });
  let win = "";
  for (let r = 0; r < 4; r++) for (let c = 0; c < 3; c++) win += `<rect x="${17 + c * 7}" y="${18 + r * 7}" width="4" height="4" fill="#f5f0ff" opacity="0.9"/>`;
  return b.svg + win;
}

export const ROLES: DeviceRole[] = ["switch", "l3switch", "router", "firewall", "server", "ap", "pc", "printer", "phone", "cloud", "other"];

const DRAW: Record<DeviceRole, () => string> = {
  switch: switchIcon,
  l3switch: l3switchIcon,
  router: routerIcon,
  firewall: firewallIcon,
  server: serverIcon,
  ap: apIcon,
  pc: pcIcon,
  printer: printerIcon,
  phone: phoneIcon,
  cloud: cloudIcon,
  other: otherIcon,
};

const ROLE_ICONS = Object.fromEntries(ROLES.map((r) => [r, uri(W, H, DRAW[r]())])) as Record<DeviceRole, string>;

/** The pictogram of a device role; an unknown or missing role gets the generic one. */
export function roleIcon(role: DeviceRole | null | undefined): string {
  return (role && ROLE_ICONS[role]) || ROLE_ICONS.other;
}

/** Pictogram of a collapsed area (a building). */
export const AREA_ICON = uri(W, H, areaIcon());

export type Lamp = "up" | "partial" | "down" | "unknown";
export const LAMP_COLOR: Record<Lamp, string> = { up: "#22c55e", partial: "#f59e0b", down: "#ef4444", unknown: "#9ca3af" };

/* the white rim keeps the lamp visible on light and dark ground alike */
const LAMPS = Object.fromEntries(
  (Object.keys(LAMP_COLOR) as Lamp[]).map((s) => [
    s,
    uri(16, 16, `<defs><radialGradient id="l" cx="0.35" cy="0.35" r="0.75"><stop offset="0" stop-color="#ffffff" stop-opacity="0.85"/><stop offset="0.45" stop-color="${LAMP_COLOR[s]}"/><stop offset="1" stop-color="${LAMP_COLOR[s]}"/></radialGradient></defs><circle cx="8" cy="8" r="6.2" fill="url(#l)" stroke="#ffffff" stroke-width="1.8"/><circle cx="8" cy="8" r="7.3" fill="none" stroke="#000000" stroke-opacity="0.25" stroke-width="0.6"/>`),
  ]),
) as Record<Lamp, string>;

/** Status lamp image for a device state. */
export const lampIcon = (s: Lamp): string => LAMPS[s];

/** Pushpin of a pinned device. */
export const PIN_ICON = uri(
  16,
  16,
  `<path d="M8,15 L8,9" stroke="#334155" stroke-width="1.6" stroke-linecap="round"/><circle cx="8" cy="6" r="4.6" fill="#0ea5e9" stroke="#ffffff" stroke-width="1.6"/><circle cx="6.6" cy="4.6" r="1.4" fill="#ffffff" opacity="0.7"/>`,
);

/** A transparent placeholder for an image layer that is off (cytoscape needs the same layer count on every node). */
export const BLANK = uri(1, 1, "");

export const HALO_COLOR: Record<EventSeverity, string> = { info: "#38bdf8", warning: "#facc15", average: "#fb923c", high: "#ef4444", disaster: "#b91c1c" };

const HALOS = Object.fromEntries(
  (Object.keys(HALO_COLOR) as EventSeverity[]).map((s) => [
    s,
    uri(
      100,
      100,
      `<defs><radialGradient id="h"><stop offset="0" stop-color="${HALO_COLOR[s]}" stop-opacity="0.7"/><stop offset="0.55" stop-color="${HALO_COLOR[s]}" stop-opacity="0.35"/><stop offset="1" stop-color="${HALO_COLOR[s]}" stop-opacity="0"/></radialGradient></defs><ellipse cx="50" cy="50" rx="50" ry="50" fill="url(#h)"/>`,
    ),
  ]),
) as Record<EventSeverity, string>;

/** Soft glow behind a device with open problems, in the colour of the worst severity. */
export const haloIcon = (s: EventSeverity): string => HALOS[s];
