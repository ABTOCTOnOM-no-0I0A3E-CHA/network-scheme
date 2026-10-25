import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { Plot, type Spec } from "@/features/charts/IfChart";
import { formatBps, isEmpty, presetRange, shapeData, TRAFFIC_KEYS } from "@/features/charts/series";
import { errText } from "@/features/common/errText";
import { useIfMetrics, useSysMetrics, type MetricsRange } from "@/features/devices/api";
import { Empty } from "./parts";
import { titleField, type WidgetDef } from "./registry";
import { id, title } from "./schema";

const RANGES = ["1h", "6h", "24h", "7d"] as const;
const SYS = { cpu: "cpu_pct", mem: "mem_used_pct", temp: "temp_c" } as const;

const schema = z
  .strictObject({
    title,
    device_id: id,
    metric: z.enum(["cpu", "mem", "temp", "traffic"]),
    if_index: z.number().int().min(1).max(2147483647).optional(),
    range: z.enum(RANGES).optional(),
  })
  .refine((c) => (c.metric === "traffic") === (c.if_index !== undefined));
type Config = z.infer<typeof schema>;

/* the range slides forward while the widget is shown */
const SLIDE_MS = 60_000;

/** A range ending now that slides every minute; the caller remounts on a new preset (key). */
function useSlidingRange(preset: (typeof RANGES)[number]): MetricsRange {
  const [range, setRange] = useState(() => presetRange(preset, new Date()));
  useEffect(() => {
    const id = setInterval(() => setRange(presetRange(preset, new Date())), SLIDE_MS);
    return () => clearInterval(id);
  }, [preset]);
  return range;
}

function SysMetric({ deviceId, metric, range }: { deviceId: number; metric: keyof typeof SYS; range: MetricsRange }) {
  const { t, i18n } = useTranslation();
  const q = useSysMetrics(deviceId, range);
  const unit = metric === "temp" ? "°C" : "%";
  const fmt = useMemo(() => (v: number) => `${v.toLocaleString(i18n.language, { maximumFractionDigits: 1 })} ${unit}`, [i18n.language, unit]);
  const series = useMemo<Spec[]>(() => [{ label: t(`chart.${metric}`), fmt }], [t, metric, fmt]);
  const points = q.data?.points;
  const stepS = q.data?.step_s ?? 0;
  const data = useMemo(() => (points ? shapeData(points, [SYS[metric]], stepS) : undefined), [points, metric, stepS]);
  if (q.error) return <p role="alert" className="text-sm text-destructive">{errText(t, q.error)}</p>;
  if (!data) return <Empty>{t("chart.loading")}</Empty>;
  if (isEmpty(data)) return <Empty>{t("chart.empty")}</Empty>;
  return <Plot data={data} series={series} fmtAxis={fmt} label={t(`chart.${metric}`)} />;
}

function Traffic({ deviceId, ifIndex, range }: { deviceId: number; ifIndex: number; range: MetricsRange }) {
  const { t, i18n } = useTranslation();
  const q = useIfMetrics(deviceId, ifIndex, range);
  const units = useMemo(() => ["bps", "kbps", "mbps", "gbps", "tbps"].map((k) => t(`chart.unit.${k}`)), [t]);
  const fmt = useMemo(() => (v: number) => formatBps(v, units, i18n.language), [units, i18n.language]);
  const series = useMemo<Spec[]>(() => [{ label: t("chart.in"), fmt }, { label: t("chart.out"), fmt }], [t, fmt]);
  const points = q.data?.points;
  const stepS = q.data?.step_s ?? 0;
  const data = useMemo(() => (points ? shapeData(points, TRAFFIC_KEYS, stepS) : undefined), [points, stepS]);
  if (q.error) return <p role="alert" className="text-sm text-destructive">{errText(t, q.error)}</p>;
  if (!data) return <Empty>{t("chart.loading")}</Empty>;
  if (isEmpty(data)) return <Empty>{t("chart.empty")}</Empty>;
  return <Plot data={data} series={series} fmtAxis={fmt} label={t("chart.traffic")} />;
}

function MetricChart({ c }: { c: Config }) {
  const range = useSlidingRange(c.range ?? "24h");
  return c.metric === "traffic" ? (
    <Traffic deviceId={c.device_id} ifIndex={c.if_index ?? 1} range={range} />
  ) : (
    <SysMetric deviceId={c.device_id} metric={c.metric} range={range} />
  );
}

/** One metric of one device over a sliding range (uPlot, as on the device charts tab); a device outside the user's groups shows "not found". */
export const metricChartWidget: WidgetDef<Config> = {
  type: "metric_chart",
  title: "widgets.metricChart.title",
  description: "widgets.metricChart.description",
  configSchema: schema,
  /* no device: the user picks one in the settings before the dashboard can be saved (the server requires device_id) */
  defaultConfig: { metric: "cpu", range: "24h" },
  size: { w: 6, h: 6, minW: 3, minH: 4 },
  fields: [
    titleField(),
    { key: "device_id", kind: "device", label: "widgets.field.device" },
    {
      key: "metric",
      kind: "select",
      label: "widgets.field.metric",
      options: (["cpu", "mem", "temp", "traffic"] as const).map((m) => ({ value: m, label: `widgets.metricChart.metric.${m}` })),
    },
    { key: "if_index", kind: "number", label: "widgets.field.ifIndex", min: 1, max: 2147483647 },
    { key: "range", kind: "select", label: "widgets.field.range", options: RANGES.map((r) => ({ value: r, label: `chart.preset.${r}` })) },
  ],
  render: (_data, c) => <MetricChart key={c.range ?? "24h"} c={c} />,
};
