import { useId, useRef, useState, type KeyboardEvent } from "react";
import { useTranslation } from "react-i18next";
import type { DeviceState } from "@/features/common/StateBadge";
import { safeText } from "@/lib/text";
import type { TableRows } from "./api";

type Iface = TableRows["interfaces"];

/*
 * Geometry of the faceplate in SVG units. Ports run in columns of two, odd numbers on top and even below as on a real
 * switch; RJ-45 columns come in blocks of six (twelve ports), the SFP cages form their own block at the right.
 */
const EAR = 22;
const INFO = 124;
const H = 104;
const RJ = { w: 20, h: 16, pitch: 24, block: 6, gap: 10 };
const SFP = { w: 26, h: 13, pitch: 30 };
const ROW_Y = [32, 56];
const GROUP_GAP = 18;
const PAD_R = 18;
const MIN_W = 440;
/* the panel never grows past this many pixels per unit, so a four-port router does not fill a wide window */
const MAX_SCALE = 1.6;

/* LED and metal colours of the drawing: the faceplate looks the same in both themes, like the real device */
const C = {
  ledGreen: "#34d399",
  ledAmber: "#fbbf24",
  ledRed: "#f87171",
  ledOff: "#3b4148",
  hole: "#090b0e",
  pin: "#c59b3a",
  label: "#9aa5b1",
  text: "#e7ecf1",
  select: "#facc15",
};

type PortPos = { port: Iface; kind: "rj45" | "sfp"; x: number; y: number; row: 0 | 1; label: string };

/* the number printed by a port: the last number of its name, else its if_index */
function portLabel(r: Iface): string {
  return /(\d+)\s*$/.exec(r.name)?.[1] ?? String(r.if_index);
}

/** Positions of the ports on a faceplate and its width; pure, so the layout is testable without a DOM. */
export function layoutPanel(rj45: Iface[], sfp: Iface[]): { width: number; ports: PortPos[]; rjEnd: number; sfpStart: number } {
  const ports: PortPos[] = [];
  let x = EAR + INFO;
  rj45.forEach((port, i) => {
    const col = Math.floor(i / 2);
    const px = x + col * RJ.pitch + Math.floor(col / RJ.block) * RJ.gap;
    ports.push({ port, kind: "rj45", x: px, y: ROW_Y[i % 2], row: (i % 2) as 0 | 1, label: portLabel(port) });
  });
  const rjCols = Math.ceil(rj45.length / 2);
  const rjEnd = rjCols ? x + rjCols * RJ.pitch - (RJ.pitch - RJ.w) + Math.floor((rjCols - 1) / RJ.block) * RJ.gap : x;
  const sfpStart = rjCols ? rjEnd + GROUP_GAP : x;
  x = sfpStart;
  sfp.forEach((port, i) => {
    ports.push({ port, kind: "sfp", x: x + Math.floor(i / 2) * SFP.pitch, y: ROW_Y[i % 2] + (RJ.h - SFP.h) / 2, row: (i % 2) as 0 | 1, label: portLabel(port) });
  });
  const sfpCols = Math.ceil(sfp.length / 2);
  const end = sfpCols ? sfpStart + sfpCols * SFP.pitch - (SFP.pitch - SFP.w) : rjEnd;
  return { width: Math.max(MIN_W, end + PAD_R + EAR), ports, rjEnd, sfpStart };
}

/* link/activity LED: green with a link; the speed LED is amber below a gigabit, as on Eltex switches */
const linkLed = (p: Iface) => (p.oper_up ? C.ledGreen : C.ledOff);
const speedLed = (p: Iface) => (p.oper_up && p.speed_bps > 0 && p.speed_bps < 1e9 ? C.ledAmber : C.ledOff);

/* an RJ-45 socket: metal frame, dark opening with the latch notch (up on the top row, down on the bottom one), eight pins */
function Rj45({ x, y, flip, frame, port }: { x: number; y: number; flip: boolean; frame: string; port?: Iface }) {
  const { w, h } = RJ;
  /* opening outline drawn for the top row; the bottom row mirrors it vertically */
  const yy = (v: number) => (flip ? y + h - v : y + v);
  const hole = [
    [2, 4],
    [7, 4],
    [7, 2],
    [13, 2],
    [13, 4],
    [18, 4],
    [18, 14.5],
    [2, 14.5],
  ]
    .map(([px, py]) => `${x + px},${yy(py)}`)
    .join(" ");
  const ledY = flip ? y + h - 3 : y + 0.8;
  return (
    <>
      <rect x={x} y={y} width={w} height={h} rx={1.5} fill={frame} />
      <polygon points={hole} fill={C.hole} />
      {Array.from({ length: 8 }, (_, i) => (
        <rect key={i} x={x + 3.6 + i * 1.65} y={flip ? y + 2.2 : y + 11.6} width={0.8} height={2.2} fill={C.pin} />
      ))}
      {port && (
        <>
          <rect x={x + 1} y={ledY} width={5} height={2.2} rx={0.5} fill={linkLed(port)} />
          <rect x={x + w - 6} y={ledY} width={5} height={2.2} rx={0.5} fill={speedLed(port)} />
        </>
      )}
    </>
  );
}

/* an SFP cage: metal frame and slot; with a link it shows a seated module and its pull tab */
function SfpCage({ x, y, port, gid }: { x: number; y: number; port: Iface; gid: string }) {
  const { w, h } = SFP;
  return (
    <>
      <rect x={x} y={y} width={w} height={h} rx={1} fill={`url(#${gid}metal)`} />
      <rect x={x + 1.6} y={y + 1.6} width={w - 3.2} height={h - 3.2} rx={0.6} fill={C.hole} />
      {port.oper_up && (
        <>
          <rect x={x + 2.4} y={y + 2.6} width={w - 4.8} height={h - 5.2} rx={0.5} fill="#8e98a3" />
          <rect x={x + 4} y={y + h / 2 - 1.2} width={w - 8} height={2.4} rx={1.2} fill="#1d4ed8" />
        </>
      )}
      <rect x={x + w - 6} y={y - 3.4} width={5} height={2} rx={0.4} fill={linkLed(port)} />
    </>
  );
}

type Props = {
  rj45: Iface[];
  sfp: Iface[];
  model: string;
  /** Brand text printed on the faceplate (no logo image). */
  brand?: string;
  state?: DeviceState;
  hover?: number;
  selected?: number;
  onHover: (ifIndex: number | undefined) => void;
  onSelect: (ifIndex: number) => void;
};

/** Front panel of a device drawn as inline SVG from its port inventory; every port is a keyboard-reachable button. */
export function FrontPanel({ rj45, sfp, model, brand, state = "unknown", hover, selected, onHover, onSelect }: Props) {
  const { t } = useTranslation();
  const gid = useId().replace(/[^a-zA-Z0-9_-]/g, "");
  const { width: W, ports, rjEnd, sfpStart } = layoutPanel(rj45, sfp);
  const x0 = EAR + 10;
  const sys = state === "up" ? C.ledGreen : state === "partial" ? C.ledAmber : state === "down" ? C.ledRed : C.ledOff;
  const pwr = state === "unknown" ? C.ledOff : C.ledGreen;
  const modelText = safeText(model).slice(0, 24);
  /* one tab stop for the whole panel (roving tabindex): arrows move between ports, Enter or Space opens the port card */
  const svg = useRef<SVGSVGElement>(null);
  const [stop, setStop] = useState<number | undefined>();
  const [focused, setFocused] = useState<number | undefined>();
  const stopIdx = Math.max(
    0,
    ports.findIndex((p) => p.port.if_index === (stop ?? selected)),
  );
  const key = (e: KeyboardEvent, i: number) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      onSelect(ports[i].port.if_index);
      return;
    }
    const step: Record<string, number> = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1, Home: -ports.length, End: ports.length };
    if (!(e.key in step)) return;
    e.preventDefault();
    const next = Math.min(ports.length - 1, Math.max(0, i + step[e.key]));
    setStop(ports[next].port.if_index);
    svg.current?.querySelector<SVGGElement>(`[data-port-idx="${next}"]`)?.focus();
  };
  const tenGig = sfp.some((p) => p.speed_bps >= 1e10);

  return (
    <svg
      ref={svg}
      viewBox={`0 0 ${W} ${H}`}
      width={Math.round(W * MAX_SCALE)}
      height={Math.round(H * MAX_SCALE)}
      className="h-auto max-w-full select-none"
      role="group"
      aria-label={t("phys.panel", { model: modelText || t("phys.device") })}
      data-slot="faceplate"
    >
      <defs>
        <linearGradient id={`${gid}body`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#434b55" />
          <stop offset="0.12" stopColor="#2c3239" />
          <stop offset="0.85" stopColor="#1f2429" />
          <stop offset="1" stopColor="#15181c" />
        </linearGradient>
        <linearGradient id={`${gid}ear`} x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#5a636e" />
          <stop offset="1" stopColor="#3a4149" />
        </linearGradient>
        <linearGradient id={`${gid}metal`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#dfe4ea" />
          <stop offset="1" stopColor="#9aa4af" />
        </linearGradient>
        <filter id={`${gid}shadow`} x="-5%" y="-10%" width="110%" height="130%">
          <feDropShadow dx="0" dy="2" stdDeviation="2" floodColor="#000" floodOpacity="0.35" />
        </filter>
      </defs>

      {/* mounting ears with their slots, then the chassis with a top highlight and a bottom shadow */}
      <g filter={`url(#${gid}shadow)`}>
        {[0, W - EAR - 4].map((ex) => (
          <g key={ex}>
            <rect x={ex} y={6} width={EAR + 4} height={H - 14} rx={3} fill={`url(#${gid}ear)`} />
            {[20, H - 34].map((sy) => (
              <rect key={sy} x={ex + (EAR + 4) / 2 - 4.5} y={sy} width={9} height={6} rx={3} fill={C.hole} />
            ))}
          </g>
        ))}
        <rect x={EAR} y={4} width={W - 2 * EAR} height={H - 10} rx={4} fill={`url(#${gid}body)`} />
      </g>
      <rect x={EAR + 3} y={5} width={W - 2 * EAR - 6} height={1.2} rx={0.6} fill="#ffffff" opacity={0.14} />
      <rect x={EAR + 3} y={H - 9} width={W - 2 * EAR - 6} height={1.5} rx={0.75} fill="#000000" opacity={0.4} />

      {/* brand and model, system LEDs and the console port; the silkscreen text (PWR, SYS, CONSOLE, port types) is printed on the device, not UI text */}
      {brand && (
        <text x={x0} y={30} fill={C.text} fontSize={15} fontWeight={800} letterSpacing={1.6} fontFamily="ui-sans-serif, system-ui, sans-serif">
          {brand}
        </text>
      )}
      <text x={x0} y={brand ? 44 : 34} fill={brand ? C.label : C.text} fontSize={brand ? 9 : 12} fontWeight={600} fontFamily="ui-sans-serif, system-ui, sans-serif" data-slot="faceplate-model">
        {modelText}
      </text>
      {[
        ["PWR", pwr],
        ["SYS", sys],
      ].map(([label, fill], i) => (
        <g key={label}>
          <circle cx={x0 + 4 + i * 20} cy={64} r={2.8} fill={fill} />
          <text x={x0 + 4 + i * 20} y={76} fill={C.label} fontSize={5.5} textAnchor="middle" fontFamily="ui-sans-serif, system-ui, sans-serif">
            {label}
          </text>
        </g>
      ))}
      <g data-slot="console">
        <Rj45 x={x0 + 60} y={56} flip={false} frame="#6f9fe0" />
        <text x={x0 + 70} y={83} fill={C.label} fontSize={5.5} textAnchor="middle" fontFamily="ui-sans-serif, system-ui, sans-serif">
          CONSOLE
        </text>
      </g>
      <line x1={EAR + INFO - 8} y1={14} x2={EAR + INFO - 8} y2={H - 16} stroke="#000" strokeOpacity={0.35} />
      <line x1={EAR + INFO - 7} y1={14} x2={EAR + INFO - 7} y2={H - 16} stroke="#fff" strokeOpacity={0.06} />

      {/* block captions under the ports */}
      {rj45.length > 0 && (
        <text x={(EAR + INFO + rjEnd) / 2} y={H - 13} fill={C.label} fontSize={5.5} textAnchor="middle" fontFamily="ui-sans-serif, system-ui, sans-serif">
          10/100/1000BASE-T
        </text>
      )}
      {sfp.length > 0 && (
        <text
          x={sfpStart + (Math.ceil(sfp.length / 2) * SFP.pitch - (SFP.pitch - SFP.w)) / 2}
          y={H - 13}
          fill={C.label}
          fontSize={5.5}
          textAnchor="middle"
          fontFamily="ui-sans-serif, system-ui, sans-serif"
        >
          {tenGig ? "10G SFP+" : "SFP"}
        </text>
      )}

      {ports.map(({ port, kind, x, y, row, label }, idx) => {
        const w = kind === "sfp" ? SFP.w : RJ.w;
        const h = kind === "sfp" ? SFP.h : RJ.h;
        const lit = hover === port.if_index || focused === port.if_index || selected === port.if_index;
        const name = safeText(port.name);
        return (
          <g
            key={port.if_index}
            role="button"
            tabIndex={idx === stopIdx ? 0 : -1}
            data-port-idx={idx}
            data-if-index={port.if_index}
            data-port-kind={kind}
            data-oper={port.oper_up ? "up" : "down"}
            aria-label={t("phys.port", { name, state: t(port.oper_up ? "card.up" : "card.down") })}
            aria-pressed={selected === port.if_index}
            className="cursor-pointer outline-none"
            onMouseEnter={() => onHover(port.if_index)}
            onMouseLeave={() => onHover(undefined)}
            onFocus={() => {
              setFocused(port.if_index);
              onHover(port.if_index);
            }}
            onBlur={() => {
              setFocused(undefined);
              onHover(undefined);
            }}
            onClick={() => {
              setStop(port.if_index);
              onSelect(port.if_index);
            }}
            onKeyDown={(e) => key(e, idx)}
          >
            {/* a transparent hit area slightly larger than the port */}
            <rect x={x - 2} y={y - 4} width={w + 4} height={h + 6} fill="transparent" />
            {kind === "rj45" ? <Rj45 x={x} y={y} flip={row === 1} frame={`url(#${gid}metal)`} port={port} /> : <SfpCage x={x} y={y} port={port} gid={gid} />}
            <text x={x + w / 2} y={row === 0 ? y - 3 : y + h + 7.5} fill={C.label} fontSize={6} textAnchor="middle" fontFamily="ui-monospace, monospace">
              {safeText(label)}
            </text>
            {lit && <rect x={x - 1.8} y={y - 1.8} width={w + 3.6} height={h + 3.6} rx={2} fill="none" stroke={C.select} strokeWidth={1.4} />}
          </g>
        );
      })}
    </svg>
  );
}
