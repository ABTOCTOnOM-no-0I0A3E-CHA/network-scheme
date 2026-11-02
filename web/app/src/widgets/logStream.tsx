import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { unwrap } from "@/features/common/stepup";
import type { EventSeverity, NmsEvent } from "@/features/events/api";
import { SEVERITIES } from "@/features/problems/api";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { DeviceChip, Empty } from "./parts";
import { titleField, type WidgetDef } from "./registry";
import { limit, severityMin, title } from "./schema";

const schema = z.strictObject({ title, kind: z.enum(["syslog", "trap"]).optional(), severity_min: severityMin, limit: limit(100) });
type Config = z.infer<typeof schema>;

/* the feed of the last day, as the logs screen opens with */
const WINDOW_MS = 24 * 3600_000;

/* severity marker (the bar at the row start), row tint from warning up and the severity word: one hue per level */
const MARK: Record<EventSeverity | "none", string> = {
  none: "bg-muted-foreground/30",
  info: "bg-sky-500/70",
  warning: "bg-yellow-400",
  average: "bg-orange-500",
  high: "bg-red-500",
  disaster: "bg-red-800 dark:bg-red-600",
};
const TINT: Partial<Record<EventSeverity, string>> = {
  warning: "bg-yellow-400/10 dark:bg-yellow-400/8",
  average: "bg-orange-500/10 dark:bg-orange-500/12",
  high: "bg-red-500/10 dark:bg-red-500/14",
  disaster: "bg-red-700/15 dark:bg-red-600/22",
};
const LABEL: Record<EventSeverity, string> = {
  info: "text-sky-700 dark:text-sky-400",
  warning: "text-yellow-700 dark:text-yellow-300",
  average: "text-orange-700 dark:text-orange-400",
  high: "text-red-600 dark:text-red-400",
  disaster: "text-red-800 dark:text-red-300",
};

/** Events of the feed with the same device, kind, severity, source and text folded into one row (newest first). */
export type LogRow = { e: NmsEvent; count: number; first: string };

/** Folds repeats of a newest-first feed: each row keeps the newest event, the number of repeats and the oldest time. */
export function groupRepeats(items: NmsEvent[]): LogRow[] {
  const rows = new Map<string, LogRow>();
  for (const e of items) {
    const key = JSON.stringify([e.device_id, e.kind, e.severity, e.app ?? e.name ?? "", e.text]);
    const row = rows.get(key);
    if (row) {
      row.count += e.count ?? 1;
      row.first = e.ts;
    } else rows.set(key, { e, count: e.count ?? 1, first: e.ts });
  }
  return [...rows.values()];
}

/* the current time, refreshed every 30 s so relative times stay true */
function useNow(): number {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(id);
  }, []);
  return now;
}

/** "только что", "5 мин. назад", "3 ч. назад", "2 дн. назад". */
export function relativeTime(iso: string, now: number, lang: string, justNow: string): string {
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (s < 45) return justNow;
  const f = new Intl.RelativeTimeFormat(lang, { numeric: "auto", style: "short" });
  if (s < 3600) return f.format(-Math.round(s / 60), "minute");
  if (s < 86400) return f.format(-Math.round(s / 3600), "hour");
  return f.format(-Math.round(s / 86400), "day");
}

function EventRows({ items }: { items: NmsEvent[] }) {
  const { t, i18n } = useTranslation();
  const now = useNow();
  if (items.length === 0) return <Empty />;
  const exact = (iso: string) => new Date(iso).toLocaleString(i18n.language);
  return (
    <ul className="grid gap-1" data-testid="log-stream">
      {groupRepeats(items).map(({ e, count, first }) => {
        const sev = e.severity ?? "none";
        /* a named trap reads by its name (linkDown), with the OID as a muted detail; syslog by its message */
        const named = e.kind === "trap" && !!e.name;
        const source = named ? t("events.kind.trap") : safeText(e.kind === "syslog" ? e.app : e.name);
        const text = safeText(named ? e.name : e.text);
        const detail = named ? safeText(e.text) : "";
        return (
          <li key={`${e.ts}-${e.device_id}-${e.kind}-${text}`} data-severity={sev} className={cn("flex gap-2.5 rounded-md py-1.5 pr-2 pl-1.5", e.severity ? TINT[e.severity] : undefined)}>
            <span aria-hidden="true" className={cn("w-1 shrink-0 self-stretch rounded-full", MARK[sev])} />
            <div className="grid min-w-0 flex-1 gap-0.5">
              <div className="flex min-w-0 items-center gap-2 text-xs">
                <DeviceChip id={e.device_id} name={e.device_name} />
                {e.severity && <span className={cn("shrink-0 font-semibold", LABEL[e.severity])}>{t(`events.severity.${e.severity}`)}</span>}
                {source && (
                  <span className="min-w-0 truncate text-muted-foreground" title={source}>
                    {source}
                  </span>
                )}
                <time dateTime={e.ts} title={count > 1 ? t("widgets.logStream.repeatSpan", { first: exact(first), last: exact(e.ts) }) : exact(e.ts)} className="ml-auto shrink-0 text-muted-foreground tabular-nums">
                  {relativeTime(e.ts, now, i18n.language, t("widgets.logStream.justNow"))}
                </time>
              </div>
              <p className="flex min-w-0 items-start gap-2 text-sm">
                <span className="line-clamp-2 min-w-0 flex-1 font-medium break-words text-foreground" title={detail || text}>
                  {text}
                  {detail && <span className="ml-2 font-mono text-xs font-normal text-muted-foreground">{detail}</span>}
                </span>
                {count > 1 && (
                  <span className="shrink-0 rounded-full bg-foreground/10 px-1.5 text-xs font-semibold tabular-nums" title={t("widgets.logStream.repeats", { count })}>
                    ×{count}
                  </span>
                )}
              </p>
            </div>
          </li>
        );
      })}
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
