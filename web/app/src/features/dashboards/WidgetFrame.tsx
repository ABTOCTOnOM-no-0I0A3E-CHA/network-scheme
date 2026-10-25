import { useQuery } from "@tanstack/react-query";
import { GripVertical, Settings, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { errText } from "@/features/common/errText";
import { safeText } from "@/lib/text";
import { getWidget } from "@/widgets/registry";

export type GridItem = { key: string; id?: number; type: string; x: number; y: number; w: number; h: number; config: Record<string, unknown> };

/** CSS class of the drag handle: only the handle moves a widget, so its content stays usable in edit mode. */
export const DRAG_HANDLE = "widget-drag";

const NONE = { queryKey: ["widgets", "none"] as const, queryFn: async () => null };

/**
 * One cell of a dashboard: looks the widget up in the registry, checks the stored config with the widget's schema, runs
 * its data query and renders it. In edit mode a toolbar offers the drag handle, settings and removal.
 */
export function WidgetFrame({ item, editing, onSettings, onRemove }: { item: GridItem; editing: boolean; onSettings: () => void; onRemove: () => void }) {
  const { t } = useTranslation();
  const def = getWidget(item.type);
  const parsed = def?.configSchema.safeParse(item.config);
  const config = parsed?.success ? parsed.data : undefined;
  const dq = def?.dataQuery && config ? def.dataQuery(config) : undefined;
  const q = useQuery({ ...(dq ?? NONE), enabled: dq !== undefined, retry: false });
  const custom = typeof item.config.title === "string" ? item.config.title : "";
  const heading = custom ? safeText(custom) : def ? t(def.title) : t("widgets.unknown.title");

  let body;
  if (!def) body = <p className="text-sm text-muted-foreground">{t("widgets.unknown.body", { type: safeText(item.type) })}</p>;
  else if (!config) body = <p role="alert" className="text-sm text-destructive">{t("widgets.invalidConfig")}</p>;
  else if (!dq) body = def.render(undefined, config);
  else if (q.error) body = <p role="alert" className="text-sm text-destructive">{errText(t, q.error)}</p>;
  else if (q.isPending) body = <Skeleton className="h-full w-full" />;
  else body = def.render(q.data, config);

  const frameless = def?.frameless && !!config;
  return (
    <section aria-label={heading} data-widget={item.type} className="flex h-full flex-col gap-2 overflow-hidden rounded-lg border bg-card p-3 text-card-foreground">
      {(editing || !frameless) && (
        <header className="flex items-center gap-1">
          {editing && (
            <span className={`${DRAG_HANDLE} cursor-move text-muted-foreground`} title={t("dashboards.drag")}>
              <GripVertical className="size-4" />
            </span>
          )}
          <h2 className="min-w-0 flex-1 truncate text-sm font-medium">{heading}</h2>
          {editing && (
            <>
              {def?.fields && (
                <Button size="icon" variant="ghost" className="size-7" aria-label={t("dashboards.settings", { name: heading })} onClick={onSettings}>
                  <Settings />
                </Button>
              )}
              <Button size="icon" variant="ghost" className="size-7" aria-label={t("dashboards.remove", { name: heading })} onClick={onRemove}>
                <X />
              </Button>
            </>
          )}
        </header>
      )}
      <div className="min-h-0 flex-1 overflow-auto">{body}</div>
    </section>
  );
}
