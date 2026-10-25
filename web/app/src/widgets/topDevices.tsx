import type { TFunction } from "i18next";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { unwrap } from "@/features/common/stepup";
import { api } from "@/lib/api";
import { DeviceName, Empty, Rows } from "./parts";
import { titleField, type WidgetDef } from "./registry";
import { limit, title } from "./schema";

const METRICS = ["cpu", "mem", "uptime"] as const;
const schema = z.strictObject({ title, metric: z.enum(METRICS), limit: limit(50) });
type Config = z.infer<typeof schema>;
type Item = { device_id: number; device_name: string; value: number; at: string };

/** Seconds as the two largest units ("3 д 4 ч", "5 ч 12 мин", "40 мин"). */
export function formatUptime(t: TFunction, seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return t("widgets.uptime.dh", { d, h });
  if (h > 0) return t("widgets.uptime.hm", { h, m });
  return t("widgets.uptime.m", { m });
}

function TopRows({ items, metric }: { items: Item[]; metric: Config["metric"] }) {
  const { t, i18n } = useTranslation();
  if (items.length === 0) return <Empty />;
  return (
    <Rows>
      {items.map((it) => (
        <tr key={it.device_id}>
          <td className="truncate">
            <DeviceName id={it.device_id} name={it.device_name} />
          </td>
          <td>{metric === "uptime" ? formatUptime(t, it.value) : `${it.value.toLocaleString(i18n.language, { maximumFractionDigits: 1 })} %`}</td>
        </tr>
      ))}
    </Rows>
  );
}

/** Visible devices with the highest CPU or memory load, or the longest uptime. */
export const topDevicesWidget: WidgetDef<Config, Item[]> = {
  type: "top_devices",
  title: "widgets.topDevices.title",
  description: "widgets.topDevices.description",
  configSchema: schema,
  defaultConfig: { metric: "cpu", limit: 10 },
  size: { w: 3, h: 6, minW: 2, minH: 3 },
  fields: [
    titleField(),
    { key: "metric", kind: "select", label: "widgets.field.metric", options: METRICS.map((m) => ({ value: m, label: `widgets.topDevices.metric.${m}` })) },
    { key: "limit", kind: "number", label: "widgets.field.limit", min: 1, max: 50 },
  ],
  dataQuery: (c) => ({
    queryKey: ["widgets", "top-devices", c.metric, c.limit ?? 10],
    queryFn: async () => unwrap(await api.GET("/api/stats/top-devices", { params: { query: { metric: c.metric, limit: c.limit ?? 10 } } })).items,
    refetchInterval: 60_000,
  }),
  render: (items, c) => <TopRows items={items} metric={c.metric} />,
};
