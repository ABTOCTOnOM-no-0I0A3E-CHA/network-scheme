import { useQuery } from "@tanstack/react-query";
import { GripVertical, Settings, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { errText } from "@/features/common/errText";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { getWidget } from "@/widgets/registry";

export type GridItem = { key: string; id?: number; type: string; x: number; y: number; w: number; h: number; config: Record<string, unknown> };

/** CSS class of the drag handle: only the handle moves a widget, so its content stays usable in edit mode. */
export const DRAG_HANDLE = "widget-drag";

/**
 * Where a bubble widget grows from: the grid side it touches (so it never grows off the dashboard sideways), and its top
 * edge in the first row, else its middle (so a widget low on the screen does not grow past the bottom of the window).
 */
export type BubbleOrigin = `${"top" | "middle"}-${"left" | "center" | "right"}`;

/*
 * Bubble (FR-MAP-7): after a short hover, or while focus is inside, the whole widget grows a fifth over its neighbours with
 * a deep shadow; the grid cell raises its z-index (DashboardGrid). Only with motion allowed: prefers-reduced-motion keeps it still.
 */
const BUBBLE =
  "motion-safe:transition-[scale,box-shadow] motion-safe:duration-300 motion-safe:ease-out motion-safe:hover:delay-150 motion-safe:hover:scale-[1.2] motion-safe:hover:shadow-2xl motion-safe:focus-within:scale-[1.2] motion-safe:focus-within:shadow-2xl";
const ORIGIN: Record<BubbleOrigin, string> = {
  "top-left": "origin-top-left",
  "top-center": "origin-top",
  "top-right": "origin-top-right",
  "middle-left": "origin-left",
  "middle-center": "origin-center",
  "middle-right": "origin-right",
};

const NONE = { queryKey: ["widgets", "none"] as const, queryFn: async () => null };

/**
 * One cell of a dashboard: looks the widget up in the registry, checks the stored config with the widget's schema, runs
 * its data query and renders it. In edit mode a toolbar offers the drag handle, settings and removal.
 */
export function WidgetFrame({
  item,
  editing,
  bubble,
  onSettings,
  onRemove,
}: {
  item: GridItem;
  editing: boolean;
  /** Set for a widget that grows over its neighbours on hover (never while editing). */
  bubble?: BubbleOrigin;
  onSettings: () => void;
  onRemove: () => void;
}) {
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
  else if (!config && editing) body = <p className="text-sm text-muted-foreground">{t("widgets.configure")}</p>;
  else if (!config) body = <p role="alert" className="text-sm text-destructive">{t("widgets.invalidConfig")}</p>;
  else if (!dq) body = def.render(undefined, config);
  else if (q.error) body = <p role="alert" className="text-sm text-destructive">{errText(t, q.error)}</p>;
  else if (q.isPending) body = <Skeleton className="h-full w-full" />;
  else body = def.render(q.data, config);

  const frameless = def?.frameless && !!config;
  return (
    <section
      aria-label={heading}
      data-widget={item.type}
      data-bubble={bubble}
      className={cn("flex h-full flex-col gap-2 overflow-hidden rounded-lg border bg-card p-3 text-card-foreground shadow-xs", bubble && [BUBBLE, ORIGIN[bubble]])}
    >
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
