import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { PRESETS, type Preset } from "./series";

const INPUT_CLASS = "h-9 rounded-md border border-input bg-transparent px-2 text-sm dark:bg-input/30";
/* the server caps a range at 730 days */
const MAX_RANGE_MS = 730 * 86400 * 1000;

type Props = {
  preset: Preset;
  onPreset: (p: Exclude<Preset, "custom">) => void;
  onCustom: (from: Date, to: Date) => void;
};

/* datetime-local value (local time, no zone) -> Date */
const parseLocal = (v: string) => (v ? new Date(v) : undefined);

/** Range presets plus a custom from/to pair in local time. */
export function RangePicker({ preset, onPreset, onCustom }: Props) {
  const { t } = useTranslation();
  const [custom, setCustom] = useState(false);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const f = parseLocal(from);
  const u = parseLocal(to);
  const ordered = !!f && !!u && !Number.isNaN(f.getTime()) && !Number.isNaN(u.getTime()) && u > f;
  const tooWide = ordered && u.getTime() - f.getTime() > MAX_RANGE_MS;
  const valid = ordered && !tooWide;

  return (
    <div className="flex flex-wrap items-end gap-2" role="group" aria-label={t("chart.range")}>
      {PRESETS.map((p) => (
        <Button
          key={p}
          type="button"
          size="sm"
          variant={preset === p ? "default" : "outline"}
          aria-pressed={preset === p}
          onClick={() => {
            setCustom(false);
            onPreset(p);
          }}
        >
          {t(`chart.preset.${p}`)}
        </Button>
      ))}
      <Button type="button" size="sm" variant={preset === "custom" ? "default" : "outline"} aria-pressed={preset === "custom"} onClick={() => setCustom(true)}>
        {t("chart.preset.custom")}
      </Button>
      {custom && (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (valid) onCustom(f, u);
          }}
        >
          <label className="grid gap-1 text-xs text-muted-foreground">
            {t("chart.from")}
            <input type="datetime-local" className={INPUT_CLASS} value={from} onChange={(e) => setFrom(e.target.value)} />
          </label>
          <label className="grid gap-1 text-xs text-muted-foreground">
            {t("chart.to")}
            <input type="datetime-local" className={INPUT_CLASS} value={to} onChange={(e) => setTo(e.target.value)} />
          </label>
          <Button type="submit" size="sm" disabled={!valid}>
            {t("chart.apply")}
          </Button>
          {from && to && !ordered && <span className="text-xs text-destructive">{t("chart.badRange")}</span>}
          {tooWide && <span className="text-xs text-destructive">{t("chart.tooWide")}</span>}
        </form>
      )}
    </div>
  );
}
