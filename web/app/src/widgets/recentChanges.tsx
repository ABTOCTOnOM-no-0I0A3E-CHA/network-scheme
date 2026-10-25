import { useTranslation } from "react-i18next";
import { z } from "zod";
import type { components } from "@/api/schema";
import { unwrap } from "@/features/common/stepup";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";
import { DeviceName, Empty } from "./parts";
import { titleField, type WidgetDef } from "./registry";
import { limit, title } from "./schema";

const schema = z.strictObject({ title, limit: limit(50) });
type Config = z.infer<typeof schema>;
type LinkChange = components["schemas"]["LinkChange"];

/** One change: a configuration drift version or a link that appeared or disappeared. */
export type Change =
  | { kind: "drift"; at: string; key: string; deviceId: number; deviceName: string }
  | { kind: "link"; at: string; key: string; change: LinkChange };

/** Merges both sources newest first and keeps n. */
export function mergeChanges(drift: { version_id: number; device_id: number; device_name: string; taken_at: string }[], links: LinkChange[], n: number): Change[] {
  const all: Change[] = [
    ...drift.map((d): Change => ({ kind: "drift", at: d.taken_at, key: `d${d.version_id}`, deviceId: d.device_id, deviceName: d.device_name })),
    ...links.map((c): Change => ({ kind: "link", at: c.at, key: `l${c.id}`, change: c })),
  ];
  return all.sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, n);
}

function ChangeRows({ items }: { items: Change[] }) {
  const { t, i18n } = useTranslation();
  if (items.length === 0) return <Empty />;
  return (
    <ul className="grid gap-1 text-sm">
      {items.map((c) => (
        <li key={c.key} className="grid grid-cols-[auto_1fr] gap-2">
          <time className="text-xs text-muted-foreground tabular-nums">{new Date(c.at).toLocaleString(i18n.language)}</time>
          {c.kind === "drift" ? (
            <span className="min-w-0 truncate">
              {t("widgets.recentChanges.drift")} <DeviceName id={c.deviceId} name={c.deviceName} />
            </span>
          ) : (
            <span className="min-w-0 truncate">
              {t(`widgets.recentChanges.link.${c.change.change}`)} <DeviceName id={c.change.a_device_id} name={c.change.a_device_name} /> {safeText(c.change.a_port_name)} —{" "}
              <DeviceName id={c.change.b_device_id} name={c.change.b_device_name} /> {safeText(c.change.b_port_name)}
            </span>
          )}
        </li>
      ))}
    </ul>
  );
}

/** Recent changes: configuration drift (backups changed outside the panel) and topology changes of visible devices. */
export const recentChangesWidget: WidgetDef<Config, Change[]> = {
  type: "recent_changes",
  title: "widgets.recentChanges.title",
  description: "widgets.recentChanges.description",
  configSchema: schema,
  defaultConfig: { limit: 10 },
  size: { w: 4, h: 6, minW: 3, minH: 3 },
  fields: [titleField(), { key: "limit", kind: "number", label: "widgets.field.limit", min: 1, max: 50 }],
  dataQuery: (c) => ({
    queryKey: ["widgets", "recent-changes", c.limit ?? 10],
    queryFn: async () => {
      const n = c.limit ?? 10;
      const [drift, links] = await Promise.all([
        api.GET("/api/stats/config-drift", { params: { query: { limit: n } } }).then(unwrap),
        api.GET("/api/topology/changes", { params: { query: { limit: n } } }).then(unwrap),
      ]);
      return mergeChanges(drift.items, links.items, n);
    },
    refetchInterval: 60_000,
  }),
  render: (items) => <ChangeRows items={items} />,
};
