import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import uPlot from "uplot";
import "uplot/dist/uPlot.min.css";
import { errorKey } from "@/features/auth/errors";
import { ApiError } from "@/features/common/stepup";
import { useIfMetrics, type MetricsRange } from "@/features/devices/api";
import { ERROR_KEYS, TRAFFIC_KEYS, formatBps, formatPs, isEmpty, shapeData, type Columns } from "./series";

const COLORS = ["#2563eb", "#16a34a", "#dc2626", "#d97706"];
const FALLBACK_AXIS = "#888";
const FALLBACK_GRID = "rgba(136,136,136,0.2)";
const HEIGHT = 220;

export type Spec = { label: string; fmt: (v: number) => string };

type Theme = { axis: string; grid: string };

/* Axis and grid colors follow the active theme through the app's CSS custom properties. */
function readTheme(): Theme {
  const css = getComputedStyle(document.documentElement);
  return { axis: css.getPropertyValue("--muted-foreground").trim() || FALLBACK_AXIS, grid: css.getPropertyValue("--border").trim() || FALLBACK_GRID };
}

/* Bumps when the theme class of <html> changes, so plots are rebuilt with the new colors. */
function useThemeVersion(): number {
  const [version, setVersion] = useState(0);
  useEffect(() => {
    const mo = new MutationObserver(() => setVersion((v) => v + 1));
    mo.observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
    return () => mo.disconnect();
  }, []);
  return version;
}

/**
 * uPlot options: local-time x axis, formatted y axis, gaps for null values
 * (spanGaps off). Exported for tests.
 */
export function buildOptions(width: number, series: Spec[], fmtAxis: (v: number) => string, theme: Theme = { axis: FALLBACK_AXIS, grid: FALLBACK_GRID }): uPlot.Options {
  return {
    width,
    height: HEIGHT,
    tzDate: (ts) => new Date(ts * 1000),
    cursor: { drag: { x: true, y: false } },
    scales: { x: { time: true }, y: { range: (_u, _min, max) => [0, max > 0 ? max * 1.1 : 1] } },
    axes: [
      { stroke: theme.axis, grid: { stroke: theme.grid } },
      { stroke: theme.axis, grid: { stroke: theme.grid }, size: 80, values: (_u, splits) => splits.map((v) => fmtAxis(v)) },
    ],
    series: [
      {},
      ...series.map((s, i) => ({
        label: s.label,
        stroke: COLORS[i % COLORS.length],
        width: 1.5,
        spanGaps: false,
        value: (_u: uPlot, v: number | null) => (v == null ? "-" : s.fmt(v)),
      })),
    ],
  };
}

/** Canvas plot of the columns; rebuilt when the data or formatting changes. */
export function Plot({ data, series, fmtAxis, label }: { data: Columns; series: Spec[]; fmtAxis: (v: number) => string; label: string }) {
  const host = useRef<HTMLDivElement>(null);
  const themeVersion = useThemeVersion();

  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const u = new uPlot(buildOptions(el.clientWidth || 640, series, fmtAxis, readTheme()), data as uPlot.AlignedData, el);
    const ro = typeof ResizeObserver === "undefined" ? undefined : new ResizeObserver(() => u.setSize({ width: el.clientWidth || 640, height: HEIGHT }));
    ro?.observe(el);
    return () => {
      ro?.disconnect();
      u.destroy();
    };
  }, [data, series, fmtAxis, themeVersion]);

  return <div ref={host} role="img" aria-label={label} className="w-full overflow-hidden" />;
}

type Props = { deviceId: number; ifIndex: number; range: MetricsRange };

/** Traffic (in/out bit/s) and error/discard charts of one interface. */
export function IfChart({ deviceId, ifIndex, range }: Props) {
  const { t, i18n } = useTranslation();
  const q = useIfMetrics(deviceId, ifIndex, range);
  const locale = i18n.language;

  const units = useMemo(() => ["bps", "kbps", "mbps", "gbps", "tbps"].map((k) => t(`chart.unit.${k}`)), [t]);
  const fmtBps = useMemo(() => (v: number) => formatBps(v, units, locale), [units, locale]);
  const perSec = t("chart.unit.perSec");
  const fmtPs = useMemo(() => (v: number) => formatPs(v, perSec, locale), [perSec, locale]);
  const traffic = useMemo<Spec[]>(() => [{ label: t("chart.in"), fmt: fmtBps }, { label: t("chart.out"), fmt: fmtBps }], [t, fmtBps]);
  const errors = useMemo<Spec[]>(
    () => [
      { label: t("chart.inErr"), fmt: fmtPs },
      { label: t("chart.outErr"), fmt: fmtPs },
      { label: t("chart.inDisc"), fmt: fmtPs },
      { label: t("chart.outDisc"), fmt: fmtPs },
    ],
    [t, fmtPs],
  );

  const points = q.data?.points;
  const stepS = q.data?.step_s ?? 0;
  const trafficData = useMemo(() => (points ? shapeData(points, TRAFFIC_KEYS, stepS) : undefined), [points, stepS]);
  const errorData = useMemo(() => (points ? shapeData(points, ERROR_KEYS, stepS) : undefined), [points, stepS]);

  if (q.isPending) return <p className="text-sm text-muted-foreground">{t("chart.loading")}</p>;
  if (q.error) {
    const key = q.error instanceof ApiError ? errorKey({ error: { code: q.error.code } }) : "errors.unknown";
    return (
      <p role="alert" className="text-sm text-destructive">
        {t(key)}
      </p>
    );
  }
  if (!points?.length || !trafficData || !errorData) return <p className="text-sm text-muted-foreground">{t("chart.empty")}</p>;

  return (
    <div className="grid gap-4" data-slot="if-chart">
      <section className="grid gap-1">
        <h3 className="text-sm font-medium">{t("chart.traffic")}</h3>
        <Plot data={trafficData} series={traffic} fmtAxis={fmtBps} label={t("chart.traffic")} />
      </section>
      <section className="grid gap-1">
        <h3 className="text-sm font-medium">{t("chart.errors")}</h3>
        {isEmpty(errorData) ? (
          <p className="text-sm text-muted-foreground">{t("chart.noErrors")}</p>
        ) : (
          <Plot data={errorData} series={errors} fmtAxis={fmtPs} label={t("chart.errors")} />
        )}
      </section>
    </div>
  );
}
