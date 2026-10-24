import { useMemo } from "react";
import { useTranslation } from "react-i18next";
import { useSysMetrics, type MetricsRange } from "@/features/devices/api";
import { Plot, type Spec } from "./IfChart";
import { isEmpty, shapeData } from "./series";

const LOAD_KEYS = ["cpu_pct", "mem_used_pct"] as const;
const TEMP_KEYS = ["temp_c"] as const;

/** Device resources over the range: CPU and memory load (%) and temperature (°C); a series the device does not report is left out. */
export function SysChart({ deviceId, range }: { deviceId: number; range: MetricsRange }) {
  const { t, i18n } = useTranslation();
  const q = useSysMetrics(deviceId, range);
  const locale = i18n.language;
  const fmtPct = useMemo(() => (v: number) => `${v.toLocaleString(locale, { maximumFractionDigits: 1 })} %`, [locale]);
  const fmtC = useMemo(() => (v: number) => `${v.toLocaleString(locale, { maximumFractionDigits: 1 })} °C`, [locale]);
  const load = useMemo<Spec[]>(() => [{ label: t("chart.cpu"), fmt: fmtPct }, { label: t("chart.mem"), fmt: fmtPct }], [t, fmtPct]);
  const temp = useMemo<Spec[]>(() => [{ label: t("chart.temp"), fmt: fmtC }], [t, fmtC]);

  const points = q.data?.points;
  const stepS = q.data?.step_s ?? 0;
  const loadData = useMemo(() => (points ? shapeData(points, LOAD_KEYS, stepS) : undefined), [points, stepS]);
  const tempData = useMemo(() => (points ? shapeData(points, TEMP_KEYS, stepS) : undefined), [points, stepS]);

  /* an error or missing data only hides the block: the interface charts above stay the main content */
  if (!loadData || !tempData || (isEmpty(loadData) && isEmpty(tempData))) return null;
  return (
    <div className="grid gap-4" data-slot="sys-chart">
      {!isEmpty(loadData) && (
        <section className="grid gap-1">
          <h3 className="text-sm font-medium">{t("chart.load")}</h3>
          <Plot data={loadData} series={load} fmtAxis={fmtPct} label={t("chart.load")} />
        </section>
      )}
      {!isEmpty(tempData) && (
        <section className="grid gap-1">
          <h3 className="text-sm font-medium">{t("chart.temp")}</h3>
          <Plot data={tempData} series={temp} fmtAxis={fmtC} label={t("chart.temp")} />
        </section>
      )}
    </div>
  );
}
