import { useCallback, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Settings2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { errText } from "@/features/common/errText";
import { safeText } from "@/lib/text";
import type { Rect } from "./AreaOverlay";
import { MapAdmin } from "./MapAdmin";
import { NetworkMap, type AreaEditor } from "./NetworkMap";
import { topologyKeys, useOpenProblemSeverity, usePatchArea, useSavePositions, useTopology, useViews } from "./useTopology";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
/* the select value for "no view": all visible devices, laid out automatically */
const NONE = "0";

/** The map screen: view selector, the interactive map and, with map.manage, the editors for views, areas and backgrounds. */
export function MapPage({ canManage }: { canManage: boolean }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const views = useViews();
  const [chosen, setChosen] = useState<number | undefined>();
  const [adminOpen, setAdminOpen] = useState(false);
  const [tool, setTool] = useState<"select" | "draw">("select");
  const [selectedId, setSelectedId] = useState<number | undefined>();
  const [draft, setDraft] = useState<Rect | undefined>();
  const [saveError, setSaveError] = useState<unknown>();

  /* the first view is the default; 0 = deliberately none */
  const list = views.data ?? [];
  const viewId = chosen === undefined ? list[0]?.id : chosen === 0 ? undefined : chosen;
  const view = list.find((v) => v.id === viewId);
  const topo = useTopology(viewId, views.isSuccess);
  const severity = useOpenProblemSeverity();
  const savePositions = useSavePositions(viewId);
  const patchArea = usePatchArea(viewId ?? 0);
  const editing = canManage && adminOpen && viewId !== undefined;

  const onSaved = useCallback(() => setSaveError(undefined), []);
  const open = useCallback((id: number) => void navigate({ to: "/devices/$id", params: { id: String(id) } }), [navigate]);
  const refresh = () => void qc.invalidateQueries({ queryKey: topologyKeys.all });
  const editor: AreaEditor | undefined = editing
    ? {
        tool,
        selectedId,
        onSelect: (id) => {
          setSelectedId(id);
          setDraft(undefined);
        },
        onDraw: (r) => {
          setSelectedId(undefined);
          setDraft(r);
          setTool("select");
        },
        onChange: (id, r) => void patchArea.mutateAsync({ id, body: r }).catch(() => undefined),
      }
    : undefined;

  const chooseView = (id: number | undefined) => {
    setChosen(id === undefined ? 0 : id);
    setSelectedId(undefined);
    setDraft(undefined);
    setTool("select");
  };

  return (
    <section className="flex h-[calc(100svh-7rem)] min-h-[28rem] flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-auto text-xl font-semibold">{t("nav.map")}</h1>
        {views.isSuccess && (
          <select aria-label={t("map.view")} className={SELECT_CLASS} value={viewId ?? NONE} onChange={(e) => chooseView(Number(e.target.value) || undefined)}>
            <option value={NONE}>{t("map.allDevices")}</option>
            {list.map((v) => (
              <option key={v.id} value={v.id}>
                {safeText(v.name)}
              </option>
            ))}
          </select>
        )}
        <Button variant="outline" size="sm" onClick={refresh}>
          {t("map.refresh")}
        </Button>
        {canManage && (
          <Button variant={adminOpen ? "default" : "outline"} size="sm" aria-pressed={adminOpen} onClick={() => setAdminOpen((o) => !o)}>
            <Settings2 />
            {t("map.admin.title")}
          </Button>
        )}
      </div>
      {(views.error || topo.error || saveError !== undefined) && (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, views.error ?? topo.error ?? saveError)}
        </p>
      )}
      <div className={`grid min-h-0 flex-1 gap-3 ${canManage && adminOpen ? "lg:grid-cols-[1fr_20rem]" : ""}`}>
        {topo.data ? (
          <NetworkMap
            key={viewId ?? 0}
            topology={topo.data}
            severity={severity}
            backgroundUrl={view?.background_id != null ? `/api/map/backgrounds/${view.background_id}` : undefined}
            save={canManage && viewId !== undefined ? savePositions : undefined}
            onSaved={onSaved}
            onSaveError={setSaveError}
            onOpenDevice={open}
            editor={editor}
          />
        ) : (
          <Skeleton className="h-full min-h-96 w-full" />
        )}
        {canManage && adminOpen && (
          <MapAdmin
            views={list}
            view={view}
            areas={topo.data?.areas ?? []}
            tool={tool}
            setTool={setTool}
            selectedId={selectedId}
            setSelectedId={setSelectedId}
            draft={draft}
            setDraft={setDraft}
            onViewChosen={chooseView}
          />
        )}
      </div>
    </section>
  );
}
