import { useTranslation } from "react-i18next";
import { z } from "zod";
import { unwrap } from "@/features/common/stepup";
import { SeverityBadge } from "@/features/events/EventFeed";
import type { NmsEvent } from "@/features/events/api";
import { SEVERITIES } from "@/features/problems/api";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";
import { DeviceName, Empty } from "./parts";
import { titleField, type WidgetDef } from "./registry";
import { limit, severityMin, title } from "./schema";

const schema = z.strictObject({ title, kind: z.enum(["syslog", "trap"]).optional(), severity_min: severityMin, limit: limit(100) });
type Config = z.infer<typeof schema>;

/* the feed of the last day, as the logs screen opens with */
const WINDOW_MS = 24 * 3600_000;

/** Event text as plain text: the syslog app or trap name, then the message. */
function eventText(e: NmsEvent): string {
  const head = e.kind === "syslog" ? e.app : e.name;
  return safeText(head ? `${head}: ${e.text}` : e.text);
}

function EventRows({ items }: { items: NmsEvent[] }) {
  const { i18n } = useTranslation();
  if (items.length === 0) return <Empty />;
  return (
    <ul className="grid gap-1 font-mono text-xs" data-testid="log-stream">
      {items.map((e, i) => (
        <li key={`${e.ts}-${e.device_id}-${i}`} className="grid grid-cols-[auto_auto_1fr] items-start gap-2">
          <time className="text-muted-foreground tabular-nums">{new Date(e.ts).toLocaleTimeString(i18n.language)}</time>
          <SeverityBadge severity={e.severity} />
          <span className="min-w-0">
            <DeviceName id={e.device_id} name={e.device_name} /> <span className="break-words">{eventText(e)}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}

/** The newest syslog messages and traps of visible devices (the log feed of the last 24 hours). */
export const logStreamWidget: WidgetDef<Config, NmsEvent[]> = {
  type: "log_stream",
  title: "widgets.logStream.title",
  description: "widgets.logStream.description",
  configSchema: schema,
  defaultConfig: { limit: 20 },
  size: { w: 6, h: 6, minW: 3, minH: 3 },
  fields: [
    titleField(),
    {
      key: "kind",
      kind: "select",
      label: "widgets.field.kind",
      options: [
        { value: "syslog", label: "events.kind.syslog" },
        { value: "trap", label: "events.kind.trap" },
      ],
    },
    { key: "severity_min", kind: "select", label: "widgets.field.severityMin", options: SEVERITIES.map((s) => ({ value: s, label: `events.severity.${s}` })) },
    { key: "limit", kind: "number", label: "widgets.field.limit", min: 1, max: 100 },
  ],
  dataQuery: (c) => ({
    queryKey: ["widgets", "events", c.kind ?? null, c.severity_min ?? null, c.limit ?? 20],
    queryFn: async () =>
      unwrap(
        await api.GET("/api/events", {
          params: { query: { kind: c.kind, severity_min: c.severity_min, from: new Date(Date.now() - WINDOW_MS).toISOString(), limit: c.limit ?? 20 } },
        }),
      ).items,
    refetchInterval: 15_000,
  }),
  render: (items) => <EventRows items={items} />,
};
