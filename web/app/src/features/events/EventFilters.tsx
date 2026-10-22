import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Input } from "@/components/ui/input";
import { useDevices } from "@/features/devices/api";
import { safeText } from "@/lib/text";
import type { EventQuery, EventSeverity } from "./api";

export const SEVERITIES: EventSeverity[] = ["info", "warning", "average", "high", "disaster"];
export const PRESETS = ["1h", "24h", "7d", "30d", "custom"] as const;
export type Preset = (typeof PRESETS)[number];

const PRESET_MS: Record<Exclude<Preset, "custom">, number> = { "1h": 3_600_000, "24h": 86_400_000, "7d": 7 * 86_400_000, "30d": 30 * 86_400_000 };
/** The API rejects windows wider than 31 days. */
export const MAX_WINDOW_MS = 31 * 86_400_000;
const DEBOUNCE_MS = 300;
const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

/** Filter controls as typed by the user (`custom*` are datetime-local values). */
export type FilterState = {
  kind: "" | "syslog" | "trap";
  deviceId: string;
  severityMin: "" | EventSeverity;
  preset: Preset;
  customFrom: string;
  customTo: string;
  q: string;
};

export const INITIAL_FILTERS: FilterState = { kind: "", deviceId: "", severityMin: "", preset: "24h", customFrom: "", customTo: "", q: "" };

export type WindowError = "required" | "order" | "tooWide";

/** Converts the period of the filters to ISO bounds relative to `now`; reports why a custom period is unusable. */
export function resolveWindow(f: Pick<FilterState, "preset" | "customFrom" | "customTo">, now: number): { from: string; to?: string } | { error: WindowError } {
  if (f.preset !== "custom") return { from: new Date(now - PRESET_MS[f.preset]).toISOString() };
  const from = Date.parse(f.customFrom);
  const to = f.customTo ? Date.parse(f.customTo) : now;
  if (Number.isNaN(from) || Number.isNaN(to)) return { error: "required" };
  if (from >= to) return { error: "order" };
  if (to - from > MAX_WINDOW_MS) return { error: "tooWide" };
  return { from: new Date(from).toISOString(), to: f.customTo ? new Date(to).toISOString() : undefined };
}

/** Builds the API query from the filters, or the reason the period is invalid. */
export function buildQuery(f: FilterState, now: number, fixedDeviceId?: number): { query: EventQuery } | { error: WindowError } {
  const w = resolveWindow(f, now);
  if ("error" in w) return w;
  const deviceId = fixedDeviceId ?? (f.deviceId ? Number(f.deviceId) : undefined);
  return { query: { kind: f.kind || undefined, deviceId, severityMin: f.severityMin || undefined, from: w.from, to: w.to, q: f.q.trim() || undefined } };
}

type Props = {
  value: FilterState;
  onChange: (patch: Partial<FilterState>) => void;
  /** Hides the device filter (the journal tab of a device). */
  hideDevice?: boolean;
  error?: WindowError;
};

/** Filters of the event feed: kind, device, minimal severity, period and debounced text search. */
export function EventFilters({ value, onChange, hideDevice, error }: Props) {
  const { t } = useTranslation();
  const [text, setText] = useState(value.q);
  const devices = useDevices();

  useEffect(() => {
    if (text === value.q) return;
    const h = setTimeout(() => onChange({ q: text }), DEBOUNCE_MS);
    return () => clearTimeout(h);
  }, [text, value.q, onChange]);

  return (
    <div className="grid gap-2">
      <div className="flex flex-wrap gap-2">
        <Input className="max-w-xs" type="search" aria-label={t("events.filter.search")} placeholder={t("events.filter.search")} value={text} maxLength={200} onChange={(e) => setText(e.target.value)} />
        <select aria-label={t("events.filter.kind")} className={SELECT_CLASS} value={value.kind} onChange={(e) => onChange({ kind: e.target.value as FilterState["kind"] })}>
          <option value="">{t("events.filter.allKinds")}</option>
          <option value="syslog">{t("events.kind.syslog")}</option>
          <option value="trap">{t("events.kind.trap")}</option>
        </select>
        {!hideDevice && (
          <select aria-label={t("events.filter.device")} className={SELECT_CLASS} value={value.deviceId} onChange={(e) => onChange({ deviceId: e.target.value })}>
            <option value="">{t("events.filter.allDevices")}</option>
            {devices.data?.map((d) => (
              <option key={d.id} value={d.id}>
                {safeText(d.name)}
              </option>
            ))}
          </select>
        )}
        <select aria-label={t("events.filter.severity")} className={SELECT_CLASS} value={value.severityMin} onChange={(e) => onChange({ severityMin: e.target.value as FilterState["severityMin"] })}>
          <option value="">{t("events.filter.anySeverity")}</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {t("events.filter.atLeast", { severity: t(`events.severity.${s}`) })}
            </option>
          ))}
        </select>
        <select aria-label={t("events.filter.period")} className={SELECT_CLASS} value={value.preset} onChange={(e) => onChange({ preset: e.target.value as Preset })}>
          {PRESETS.map((p) => (
            <option key={p} value={p}>
              {t(`events.period.${p}`)}
            </option>
          ))}
        </select>
      </div>
      {value.preset === "custom" && (
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <label className="flex items-center gap-2">
            {t("events.period.from")}
            <Input className="w-auto" type="datetime-local" aria-label={t("events.period.from")} value={value.customFrom} onChange={(e) => onChange({ customFrom: e.target.value })} />
          </label>
          <label className="flex items-center gap-2">
            {t("events.period.to")}
            <Input className="w-auto" type="datetime-local" aria-label={t("events.period.to")} value={value.customTo} onChange={(e) => onChange({ customTo: e.target.value })} />
          </label>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {t(`events.periodError.${error}`)}
        </p>
      )}
    </div>
  );
}
