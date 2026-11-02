import { useNavigate } from "@tanstack/react-router";
import { ExternalLink } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { errText } from "@/features/common/errText";
import { useDeviceWindows } from "@/features/devices/DeviceWindows";
import { NetworkMap } from "@/features/map/NetworkMap";
import { useOpenProblems, useTopology, useViews } from "@/features/map/useTopology";

/**
 * Compact network map, the mini-map widget of dashboards. Self-contained: loads the view (viewId or
 * the first one), the topology and the problem severities itself. The "Open" button sits in a strip above the map box, so it
 * never covers map content, and leads to /map with the same view. `fill` stretches the map box to the parent's height
 * (a dashboard cell) instead of the fixed 20rem. The bubble effect enlarges the whole widget (the dashboard frame does it).
 */
export function MiniMap({ viewId, className = "", fill = false }: { viewId?: number; className?: string; fill?: boolean }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const windows = useDeviceWindows();
  const views = useViews();
  const id = viewId ?? views.data?.[0]?.id;
  const view = views.data?.find((v) => v.id === id);
  const topo = useTopology(id, views.isSuccess);
  const problems = useOpenProblems(false);
  const err = views.error ?? topo.error;

  return (
    <section aria-label={t("map.mini.title")} className={`flex flex-col gap-2 ${className}`}>
      <div className="flex items-center justify-between gap-2" data-testid="mini-map-header">
        <h2 className="text-sm font-medium">{t("map.mini.title")}</h2>
        <Button size="sm" variant="outline" title={t("map.mini.openHint")} onClick={() => void navigate({ to: "/map", search: id === undefined ? {} : { view: id } })}>
          <ExternalLink />
          {t("map.mini.open")}
        </Button>
      </div>
      <div className={`${fill ? "min-h-0 flex-1" : "h-80"} rounded-md`} data-testid="mini-map-box">
        {err ? (
          <p role="alert" className="text-sm text-destructive">
            {errText(t, err)}
          </p>
        ) : !topo.data ? (
          <Skeleton className="h-full w-full" />
        ) : topo.data.nodes.length === 0 ? (
          <p className="flex h-full items-center justify-center rounded-md border text-sm text-muted-foreground">{t("map.mini.empty")}</p>
        ) : (
          <NetworkMap
            compact
            key={id ?? 0}
            topology={topo.data}
            severity={problems.severity}
            problems={problems.counts}
            backgroundUrl={view?.background_id != null ? `/api/map/backgrounds/${view.background_id}` : undefined}
            onOpenDevice={(d, name) => (windows ? windows.open(d, name) : void navigate({ to: "/devices/$id", params: { id: String(d) } }))}
          />
        )}
      </div>
    </section>
  );
}
