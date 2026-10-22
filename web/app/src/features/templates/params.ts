import type { EventSeverity } from "@/features/problems/api";

/*
 * Client-side mirror of internal/triggers/types.go: the closed set of kinds and the bounds of their
 * parameters. The API validates again and stays the authority.
 */
export const KINDS = ["availability", "if_oper_down", "metric_threshold", "trap", "syslog"] as const;
export type Kind = (typeof KINDS)[number];

export const MAX_DURATION_S = 86400;
export const MAX_IF_INDEX = 2147483647;
export const MAX_TRAP_NAME_BYTES = 1024;
export const MAX_CONTAINS_CHARS = 128;
export const MAX_NAME_CHARS = 200;
export const MIN_INTERVAL_S = 10;
export const MAX_INTERVAL_S = 86400;

export const METRICS = ["cpu", "mem", "temp", "if_util_in", "if_util_out", "if_errors"] as const;
export type Metric = (typeof METRICS)[number];
export const METRIC_BOUNDS: Record<Metric, { min: number; max: number; iface: boolean }> = {
  cpu: { min: 0, max: 100, iface: false },
  mem: { min: 0, max: 100, iface: false },
  temp: { min: -50, max: 150, iface: false },
  if_util_in: { min: 0, max: 100, iface: true },
  if_util_out: { min: 0, max: 100, iface: true },
  if_errors: { min: 0, max: 1e9, iface: true },
};
export const OPS = ["gt", "lt"] as const;
export const AVAIL_STATES = ["down", "partial"] as const;
export const SYSLOG_SEVERITIES = [0, 1, 2, 3, 4, 5, 6, 7] as const;

/** All parameter inputs as typed by the user; only the fields of the chosen kind are used. */
export type ParamsForm = {
  states: Record<(typeof AVAIL_STATES)[number], boolean>;
  ifIndex: string;
  metric: Metric;
  op: (typeof OPS)[number];
  value: string;
  trapName: string;
  syslogSeverity: string;
  contains: string;
};

export const EMPTY_PARAMS: ParamsForm = {
  states: { down: true, partial: false },
  ifIndex: "",
  metric: "cpu",
  op: "gt",
  value: "",
  trapName: "",
  syslogSeverity: "4",
  contains: "",
};

/** Result of validation: the value to send, or the key suffix of `templates.err.*`. */
export type Built<T> = { ok: T } | { err: string };

const CONTROL = /[\p{Cc}\p{Cf}]/u;

function parseIfIndex(s: string): Built<number | undefined> {
  if (s.trim() === "") return { ok: undefined };
  const n = Number(s);
  return Number.isInteger(n) && n >= 1 && n <= MAX_IF_INDEX ? { ok: n } : { err: "ifIndex" };
}

/** Builds the params object of `kind` from the form, exactly as the server expects it (no other keys). */
export function buildParams(kind: Kind, f: ParamsForm): Built<Record<string, unknown>> {
  switch (kind) {
    case "availability": {
      const states = AVAIL_STATES.filter((s) => f.states[s]);
      return states.length ? { ok: { states } } : { err: "states" };
    }
    case "if_oper_down": {
      const i = parseIfIndex(f.ifIndex);
      if ("err" in i) return i;
      return { ok: i.ok === undefined ? {} : { if_index: i.ok } };
    }
    case "metric_threshold": {
      const b = METRIC_BOUNDS[f.metric];
      if (!b || !OPS.includes(f.op)) return { err: "metric" };
      const v = f.value.trim() === "" ? NaN : Number(f.value);
      if (!Number.isFinite(v) || v < b.min || v > b.max) return { err: "value" };
      const i = parseIfIndex(f.ifIndex);
      if ("err" in i) return i;
      if (i.ok !== undefined && !b.iface) return { err: "ifScope" };
      return { ok: { metric: f.metric, op: f.op, value: v, ...(i.ok === undefined ? {} : { if_index: i.ok }) } };
    }
    case "trap": {
      const n = f.trapName;
      if (n === "" || new TextEncoder().encode(n).length > MAX_TRAP_NAME_BYTES || CONTROL.test(n)) return { err: "trapName" };
      return { ok: { name: n } };
    }
    case "syslog": {
      const sev = Number(f.syslogSeverity);
      if (f.syslogSeverity === "" || !Number.isInteger(sev) || sev < 0 || sev > 7) return { err: "syslogSeverity" };
      const c = f.contains;
      if (c === "") return { ok: { severity_min: sev } };
      if ([...c].length > MAX_CONTAINS_CHARS || CONTROL.test(c)) return { err: "contains" };
      return { ok: { severity_min: sev, contains: c } };
    }
  }
}

/** Fills the form from stored params (unknown shape: anything unexpected falls back to the defaults). */
export function formFromParams(kind: Kind, raw: Record<string, unknown>): ParamsForm {
  const f: ParamsForm = { ...EMPTY_PARAMS, states: { ...EMPTY_PARAMS.states } };
  const num = (v: unknown) => (typeof v === "number" ? String(v) : "");
  switch (kind) {
    case "availability": {
      const s = Array.isArray(raw.states) ? raw.states : [];
      f.states = { down: s.includes("down"), partial: s.includes("partial") };
      break;
    }
    case "if_oper_down":
      f.ifIndex = num(raw.if_index);
      break;
    case "metric_threshold":
      f.metric = METRICS.includes(raw.metric as Metric) ? (raw.metric as Metric) : f.metric;
      f.op = OPS.includes(raw.op as (typeof OPS)[number]) ? (raw.op as (typeof OPS)[number]) : f.op;
      f.value = num(raw.value);
      f.ifIndex = num(raw.if_index);
      break;
    case "trap":
      f.trapName = typeof raw.name === "string" ? raw.name : "";
      break;
    case "syslog":
      f.syslogSeverity = num(raw.severity_min) || f.syslogSeverity;
      f.contains = typeof raw.contains === "string" ? raw.contains : "";
      break;
  }
  return f;
}

/** Display name: 1..200 characters, no control characters, no leading or trailing spaces. */
export function validName(s: string): boolean {
  return s.length > 0 && [...s].length <= MAX_NAME_CHARS && s === s.trim() && !CONTROL.test(s);
}

/** Condition duration in whole seconds, 0..86400; null if invalid. */
export function parseDuration(s: string): number | null {
  if (s.trim() === "") return null;
  const n = Number(s);
  return Number.isInteger(n) && n >= 0 && n <= MAX_DURATION_S ? n : null;
}

/** Polling interval override: empty = inherit (null), otherwise 10..86400; undefined if invalid. */
export function parseInterval(s: string): number | null | undefined {
  if (s.trim() === "") return null;
  const n = Number(s);
  return Number.isInteger(n) && n >= MIN_INTERVAL_S && n <= MAX_INTERVAL_S ? n : undefined;
}

/** Driver name pattern of the API. */
export const DRIVER_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export type TriggerDraft = { name: string; kind: Kind; params: Record<string, unknown>; duration_s: number; severity: EventSeverity; enabled: boolean };
