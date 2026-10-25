import { useTranslation } from "react-i18next";
import { z } from "zod";
import { unwrap } from "@/features/common/stepup";
import { StateBadge, type DeviceState } from "@/features/common/StateBadge";
import { api } from "@/lib/api";
import { titleField, type WidgetDef } from "./registry";
import { title } from "./schema";

const schema = z.strictObject({ title });
type Config = z.infer<typeof schema>;
type Counts = { total: number; up: number; partial: number; down: number; unknown: number };

const STATES: DeviceState[] = ["up", "partial", "down", "unknown"];

function DeviceCounts({ data }: { data: Counts }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-2">
      <p className="text-2xl font-semibold tabular-nums" data-testid="device-total">
        {data.total} <span className="text-sm font-normal text-muted-foreground">{t("widgets.deviceStatus.total")}</span>
      </p>
      <dl className="grid grid-cols-2 gap-2 text-sm">
        {STATES.map((s) => (
          <div key={s} className="flex items-center justify-between gap-2 rounded-md border px-2 py-1">
            <dt>
              <StateBadge state={s} />
            </dt>
            <dd className="font-medium tabular-nums" data-testid={`device-count-${s}`}>
              {data[s]}
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}

/** Device counts by availability state (visible devices only). */
export const deviceStatusWidget: WidgetDef<Config, Counts> = {
  type: "device_status",
  title: "widgets.deviceStatus.title",
  description: "widgets.deviceStatus.description",
  configSchema: schema,
  defaultConfig: {},
  size: { w: 3, h: 4, minW: 2, minH: 3 },
  fields: [titleField()],
  dataQuery: () => ({
    queryKey: ["widgets", "device-states"],
    queryFn: async () => unwrap(await api.GET("/api/stats/device-states")),
    refetchInterval: 30_000,
  }),
  render: (data) => <DeviceCounts data={data} />,
};
