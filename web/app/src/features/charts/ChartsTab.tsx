import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { useDeviceTable, type MetricsRange } from "@/features/devices/api";
import { safeText } from "@/lib/text";
import { IfChart } from "./IfChart";
import { RangePicker } from "./RangePicker";
import { SysChart } from "./SysChart";
import { presetRange, type Preset } from "./series";

type Props = { deviceId: number; ifIndex: number | undefined; onIfIndex: (i: number) => void };

type Sel = { preset: Preset; range: MetricsRange };
const initial = (): Sel => ({ preset: "1h", range: presetRange("1h", new Date()) });

/** "Графики" tab: interface picker, range picker and the charts of the chosen interface. */
export function ChartsTab({ deviceId, ifIndex, onIfIndex }: Props) {
  const { t } = useTranslation();
  const [sel, setSel] = useState<Sel>(initial);
  const ifaces = useDeviceTable(deviceId, "interfaces", { limit: 1000 });

  return (
    <div data-slot="device-charts" className="grid gap-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="grid gap-1 text-xs text-muted-foreground">
          {t("chart.interface")}
          <select
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm text-foreground dark:bg-input/30"
            value={ifIndex ?? ""}
            onChange={(e) => onIfIndex(Number(e.target.value))}
          >
            {ifIndex === undefined && <option value="">{t("chart.pick")}</option>}
            {ifIndex !== undefined && !ifaces.data?.items.some((i) => i.if_index === ifIndex) && <option value={ifIndex}>{ifIndex}</option>}
            {ifaces.data?.items.map((i) => (
              <option key={i.if_index} value={i.if_index}>
                {i.if_index} {safeText(i.name)}
              </option>
            ))}
          </select>
        </label>
        <RangePicker
          preset={sel.preset}
          onPreset={(p) => setSel({ preset: p, range: presetRange(p, new Date()) })}
          onCustom={(from, to) => setSel({ preset: "custom", range: { from, to } })}
        />
        {sel.preset !== "custom" && (
          <Button type="button" size="sm" variant="outline" onClick={() => setSel({ preset: sel.preset, range: presetRange(sel.preset as Exclude<Preset, "custom">, new Date()) })}>
            {t("chart.refresh")}
          </Button>
        )}
      </div>
      {ifIndex === undefined ? <p className="text-sm text-muted-foreground">{t("chart.pick")}</p> : <IfChart key={ifIndex} deviceId={deviceId} ifIndex={ifIndex} range={sel.range} />}
      <SysChart deviceId={deviceId} range={sel.range} />
    </div>
  );
}
