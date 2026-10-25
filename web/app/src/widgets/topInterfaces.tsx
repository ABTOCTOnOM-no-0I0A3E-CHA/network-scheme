import { useTranslation } from "react-i18next";
import { z } from "zod";
import { unwrap } from "@/features/common/stepup";
import type { paths } from "@/api/schema";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";
import { DeviceName, Empty, Rows } from "./parts";
import { titleField, type WidgetDef } from "./registry";
import { limit, title } from "./schema";

const schema = z.strictObject({ title, limit: limit(50) });
type Config = z.infer<typeof schema>;
type Item = paths["/api/stats/top-interfaces"]["get"]["responses"]["200"]["content"]["application/json"]["items"][number];

function IfRows({ items }: { items: Item[] }) {
  const { i18n } = useTranslation();
  if (items.length === 0) return <Empty />;
  return (
    <Rows>
      {items.map((it) => (
        <tr key={`${it.device_id}-${it.if_index}`}>
          <td className="truncate">
            <DeviceName id={it.device_id} name={it.device_name} /> <span className="text-muted-foreground">{safeText(it.port_name) || `#${it.if_index}`}</span>
          </td>
          <td>{`${it.util_pct.toLocaleString(i18n.language, { maximumFractionDigits: 1 })} %`}</td>
        </tr>
      ))}
    </Rows>
  );
}

/** Interfaces of visible devices with the highest load over the last 10 minutes (the busier direction against the speed). */
export const topInterfacesWidget: WidgetDef<Config, Item[]> = {
  type: "top_interfaces",
  title: "widgets.topInterfaces.title",
  description: "widgets.topInterfaces.description",
  configSchema: schema,
  defaultConfig: { limit: 10 },
  size: { w: 4, h: 6, minW: 3, minH: 3 },
  fields: [titleField(), { key: "limit", kind: "number", label: "widgets.field.limit", min: 1, max: 50 }],
  dataQuery: (c) => ({
    queryKey: ["widgets", "top-interfaces", c.limit ?? 10],
    queryFn: async () => unwrap(await api.GET("/api/stats/top-interfaces", { params: { query: { limit: c.limit ?? 10 } } })).items,
    refetchInterval: 60_000,
  }),
  render: (items) => <IfRows items={items} />,
};
