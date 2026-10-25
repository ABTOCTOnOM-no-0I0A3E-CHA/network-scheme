
/* The API answers 400 too_many_points above this many buckets; aim lower to leave headroom. */
export const MAX_POINTS = 5000;
const TARGET_POINTS = 4000;
/* Resolution of the sources the server reads (0: raw at the poll interval, floor 10 s). */
const RAW_FLOOR_S = 10;
const RAW_MAX_WIDTH_S = 48 * 3600;
const RAW_MAX_AGE_S = 14 * 86400;
const M5_MAX_WIDTH_S = 60 * 86400;
const M5_MAX_AGE_S = 90 * 86400;

const NICE_STEPS = [10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 21600, 43200, 86400, 172800, 604800];

export type Preset = "1h" | "6h" | "24h" | "7d" | "30d" | "custom";
export const PRESETS: Exclude<Preset, "custom">[] = ["1h", "6h", "24h", "7d", "30d"];
const PRESET_SECONDS: Record<Exclude<Preset, "custom">, number> = { "1h": 3600, "6h": 6 * 3600, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400 };

/** Range ending at `now` for a preset. */
export function presetRange(p: Exclude<Preset, "custom">, now: Date): { from: Date; to: Date } {
  return { from: new Date(now.getTime() - PRESET_SECONDS[p] * 1000), to: now };
}

/* Resolution (seconds) of the source the server picks for the range: raw 0 -> poll floor. */
function sourceResolutionS(widthS: number, ageS: number): number {
  if (widthS <= RAW_MAX_WIDTH_S && ageS <= RAW_MAX_AGE_S) return RAW_FLOOR_S;
  if (widthS <= M5_MAX_WIDTH_S && ageS <= M5_MAX_AGE_S) return 300;
  return 3600;
}

/**
 * Step (seconds) that keeps the range within MAX_POINTS buckets: the smallest
 * round value that is at least the source resolution and width / 4000.
 */
export function pickStep(from: Date, to: Date, now: Date = new Date()): number {
  const widthS = Math.max(1, (to.getTime() - from.getTime()) / 1000);
  const ageS = Math.max(0, (now.getTime() - from.getTime()) / 1000);
  const need = Math.max(sourceResolutionS(widthS, ageS), Math.ceil(widthS / TARGET_POINTS));
  return NICE_STEPS.find((s) => s >= need) ?? Math.ceil(need);
}

/** Next, coarser step after `too_many_points`. */
export function coarserStep(step: number): number {
  return step * 2;
}

/* uPlot AlignedData: seconds, then series; null leaves a gap. */
export type Columns = (number | null)[][];

/** Series order of the traffic chart. */
export const TRAFFIC_KEYS = ["in_bps", "out_bps"] as const;
/** Series order of the errors chart. */
export const ERROR_KEYS = ["in_err_ps", "out_err_ps", "in_disc_ps", "out_disc_ps"] as const;

/* lower quartile of the spacing: holes (few, long deltas) do not raise it the way they would a median of a short series */
function typicalDelta(ts: number[]): number {
  const d = ts.slice(1).map((v, i) => v - ts[i]).sort((a, b) => a - b);
  return d.length ? d[Math.floor((d.length - 1) / 4)] : 0;
}

/**
 * Shapes API points into uPlot columns. Timestamps are epoch seconds. A NULL
 * value (not read from the device) stays null, never 0; a hole longer than two
 * buckets gets a null point so the line breaks instead of bridging it.
 */
export function shapeData<P extends { ts: string }>(points: P[], keys: readonly (keyof P)[], stepS: number): Columns {
  const ts = points.map((p) => Math.floor(Date.parse(p.ts) / 1000));
  /* the server only returns buckets with data: with a poll interval above the step the normal spacing is the typical delta */
  const unit = Math.max(stepS, typicalDelta(ts));
  const cols: Columns = [[], ...keys.map(() => [])];
  points.forEach((p, i) => {
    if (i > 0 && unit > 0 && ts[i] - ts[i - 1] > 2 * unit) {
      cols[0].push(ts[i - 1] + unit);
      for (let k = 0; k < keys.length; k++) cols[k + 1].push(null);
    }
    cols[0].push(ts[i]);
    keys.forEach((key, k) => {
      const v = p[key];
      cols[k + 1].push(typeof v === "number" && Number.isFinite(v) ? v : null);
    });
  });
  return cols;
}

/** True when no series has a single non-null value. */
export function isEmpty(cols: Columns): boolean {
  return cols.slice(1).every((c) => c.every((v) => v === null));
}

/**
 * Formats a rate with decimal bit prefixes. `units` are the labels for
 * bit/s, kbit/s, Mbit/s, Gbit/s, Tbit/s (localised by the caller).
 */
export function formatBps(v: number, units: readonly string[], locale?: string): string {
  let n = v;
  let i = 0;
  while (Math.abs(n) >= 1000 && i < units.length - 1) {
    n /= 1000;
    i++;
  }
  return `${n.toLocaleString(locale, { maximumFractionDigits: 2 })} ${units[i]}`;
}

/** Plain count per second (errors, discards). */
export function formatPs(v: number, unit: string, locale?: string): string {
  return `${v.toLocaleString(locale, { maximumFractionDigits: 3 })} ${unit}`;
}
