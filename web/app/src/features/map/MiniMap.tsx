import { useEffect, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { ExternalLink } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { errText } from "@/features/common/errText";
import { NetworkMap } from "./NetworkMap";
import { useOpenProblemSeverity, useTopology, useViews } from "./useTopology";

const QUERY = "(prefers-reduced-motion: reduce)";

function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(() => window.matchMedia?.(QUERY).matches ?? false);
  useEffect(() => {
    const mq = window.matchMedia?.(QUERY);
    if (!mq) return;
    const on = () => setReduced(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return reduced;
}

/* bubble effect: the map box grows from its top edge (never towards the header strip with the button) and gains a shadow */
const BUBBLE = "origin-top transition-[scale,box-shadow] duration-200 ease-out hover:z-10 hover:scale-[1.04] hover:shadow-lg focus-within:z-10 focus-within:scale-[1.04] focus-within:shadow-lg";

/**
 * Compact network map for the home page (Phase 3 dashboards embed it as a widget). Self-contained: loads the view (viewId or
 * the first one), the topology and the problem severities itself. The "Open" button sits in a strip above the map box, so it
 * never covers map content, and leads to /map with the same view.
 */
export function MiniMap({ viewId, className = "" }: { viewId?: number; className?: string }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const reduced = useReducedMotion();
  const views = useViews();
  const id = viewId ?? views.data?.[0]?.id;
  const view = views.data?.find((v) => v.id === id);
  const topo = useTopology(id, views.isSuccess);
  const severity = useOpenProblemSeverity(false);
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
      <div className={`h-80 rounded-md ${reduced ? "" : BUBBLE}`} data-testid="mini-map-box">
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
            severity={severity}
            backgroundUrl={view?.background_id != null ? `/api/map/backgrounds/${view.background_id}` : undefined}
            onOpenDevice={(d) => void navigate({ to: "/devices/$id", params: { id: String(d) } })}
          />
        )}
      </div>
    </section>
  );
}
