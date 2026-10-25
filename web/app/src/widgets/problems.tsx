import { useTranslation } from "react-i18next";
import { z } from "zod";
import { unwrap } from "@/features/common/stepup";
import { SeverityBadge } from "@/features/events/EventFeed";
import { problemTitle, SEVERITIES, type Problem } from "@/features/problems/api";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";
import { DeviceName, Empty } from "./parts";
import { titleField, type WidgetDef } from "./registry";
import { limit, severityMin, title } from "./schema";

const schema = z.strictObject({ title, severity_min: severityMin, limit: limit(50) });
type Config = z.infer<typeof schema>;

function ProblemRows({ items }: { items: Problem[] }) {
  const { t, i18n } = useTranslation();
  if (items.length === 0) return <Empty>{t("widgets.problems.none")}</Empty>;
  return (
    <ul className="grid gap-1 text-sm">
      {items.map((p) => (
        <li key={p.id} className="grid grid-cols-[auto_1fr] items-start gap-2">
          <SeverityBadge severity={p.severity} />
          <div className="min-w-0">
            <p className="truncate">{safeText(problemTitle(t, p))}</p>
            <p className="flex gap-2 truncate text-xs text-muted-foreground">
              {p.device_id != null && <DeviceName id={p.device_id} name={p.device_name} />}
              <span>{new Date(p.opened_at).toLocaleString(i18n.language)}</span>
            </p>
          </div>
        </li>
      ))}
    </ul>
  );
}

/** Active (not acknowledged, not suppressed) problems of visible devices, newest first. */
export const problemsWidget: WidgetDef<Config, Problem[]> = {
  type: "problems",
  title: "widgets.problems.title",
  description: "widgets.problems.description",
  configSchema: schema,
  defaultConfig: { limit: 10 },
  size: { w: 4, h: 6, minW: 3, minH: 3 },
  fields: [
    titleField(),
    { key: "severity_min", kind: "select", label: "widgets.field.severityMin", options: SEVERITIES.map((s) => ({ value: s, label: `events.severity.${s}` })) },
    { key: "limit", kind: "number", label: "widgets.field.limit", min: 1, max: 50 },
  ],
  dataQuery: (c) => ({
    queryKey: ["widgets", "problems", c.severity_min ?? null, c.limit ?? 10],
    queryFn: async () =>
      unwrap(await api.GET("/api/problems", { params: { query: { state: "problem", suppressed: "false", severity_min: c.severity_min, limit: c.limit ?? 10 } } })).items,
    refetchInterval: 30_000,
  }),
  render: (items) => <ProblemRows items={items} />,
};
