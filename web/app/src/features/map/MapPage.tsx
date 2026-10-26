import { useCallback, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { MousePointer2, Pencil, RefreshCw, Settings2, SquareDashed } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useDeviceWindows } from "@/features/devices/DeviceWindows";
import { errText } from "@/features/common/errText";
import { StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import type { AreaEditing } from "./AreaOverlay";
import { containerOf, descendants } from "./areas";
import { MapAdmin } from "./MapAdmin";
import { NetworkMap } from "./NetworkMap";
import { topologyKeys, useCreateArea, useCreateViewId, useDeleteArea, useOpenProblems, usePatchArea, useSavePositions, useTopology, useViews } from "./useTopology";

const SELECT_CLASS = "h-8 rounded-md border border-input bg-transparent px-2 text-sm dark:bg-input/30";
/* the select value for "no view": all visible devices, laid out automatically */
const NONE = "0";

/**
 * The map screen (initialViewId: the view from ?view=): view selector and the interactive map. With map.manage the
 * "Правка" mode makes devices draggable and adds the zone tools; "all devices" then switches to a default view (created
 * on first use) so that positions persist. Views and backgrounds are managed in a side panel.
 */
export function MapPage({ canManage, initialViewId }: { canManage: boolean; initialViewId?: number }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const windows = useDeviceWindows();
  const qc = useQueryClient();
  const views = useViews();
  const [chosen, setChosen] = useState<number | undefined>(initialViewId);
  const [adminOpen, setAdminOpen] = useState(false);
  const [editMode, setEditMode] = useState(false);
  const [tool, setTool] = useState<"select" | "draw">("select");
  const [selectedId, setSelectedId] = useState<number | undefined>();
  const [error, setError] = useState<unknown>();

  /* the first view is the default; 0 = deliberately none */
  const list = views.data ?? [];
  const viewId = chosen === undefined ? list[0]?.id : chosen === 0 ? undefined : chosen;
  const view = list.find((v) => v.id === viewId);
  const topo = useTopology(viewId, views.isSuccess);
  const problems = useOpenProblems();
  const savePositions = useSavePositions(viewId);
  const createView = useCreateViewId();
  const createArea = useCreateArea(viewId ?? 0);
  const patchArea = usePatchArea(viewId ?? 0);
  const deleteArea = useDeleteArea(viewId ?? 0);
  const editing = canManage && editMode && viewId !== undefined;

  const report = useCallback((e: unknown) => {
    if (!(e instanceof StepUpCancelled)) setError(e);
  }, []);
  const onSaved = useCallback(() => setError(undefined), []);
  const open = useCallback(
    (id: number, name: string) => (windows ? windows.open(id, name) : void navigate({ to: "/devices/$id", params: { id: String(id) } })),
    [windows, navigate],
  );
  const refresh = () => void qc.invalidateQueries({ queryKey: topologyKeys.all });

  const chooseView = (id: number | undefined) => {
    setChosen(id === undefined ? 0 : id);
    /* "all devices" keeps no positions: nothing to edit there */
    if (id === undefined) setEditMode(false);
    setSelectedId(undefined);
    setTool("select");
  };

  /* "all devices" keeps no positions: editing it moves to the default view, made on first use */
  const toggleEdit = async () => {
    setError(undefined);
    if (editMode) {
      setEditMode(false);
      setSelectedId(undefined);
      setTool("select");
      return;
    }
    if (viewId === undefined) {
      try {
        const name = t("map.defaultView");
        const id = list.find((v) => v.kind === "logical" && v.name === name)?.id ?? (await createView({ name, kind: "logical" }));
        chooseView(id);
      } catch (e) {
        return report(e);
      }
    }
    setEditMode(true);
  };

  const areas = topo.data?.areas ?? [];
  const editor: AreaEditing | undefined = editing
    ? {
        tool,
        selectedId,
        onSelect: setSelectedId,
        onDrawn: () => setTool("select"),
        onCreate: async (r, name, kind) => {
          await createArea.mutateAsync({ name, kind, parent_id: containerOf(areas, r), ...r });
        },
        onUpdate: async (id, name, kind) => {
          await patchArea.mutateAsync({ id, body: { name, kind } });
        },
        onDelete: async (id) => {
          await deleteArea.mutateAsync(id);
          setSelectedId(undefined);
        },
        onMove: async (id, r, dx, dy) => {
          const below = descendants(areas, id);
          const parent = containerOf(areas, r, new Set([id, ...below]));
          try {
            await Promise.all([
              patchArea.mutateAsync({ id, body: { x: r.x, y: r.y, parent_id: parent } }),
              ...areas.filter((a) => below.has(a.id)).map((a) => patchArea.mutateAsync({ id: a.id, body: { x: a.x + dx, y: a.y + dy } })),
            ]);
          } catch (e) {
            report(e);
            throw e;
          }
        },
        /* a resized zone is re-nested by what holds it now */
        onResize: async (id, r) => {
          try {
            await patchArea.mutateAsync({ id, body: { ...r, parent_id: containerOf(areas, r, new Set([id, ...descendants(areas, id)])) } });
          } catch (e) {
            report(e);
            throw e;
          }
        },
      }
    : undefined;

  return (
    <section className="flex h-[calc(100svh-7rem)] min-h-[28rem] flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-auto text-xl font-semibold">{t("nav.map")}</h1>
        {editing && (
          <div className="flex items-center gap-2">
            <span className="hidden text-xs text-muted-foreground 2xl:inline">{t(tool === "draw" ? "map.drawHint" : "map.editHint")}</span>
            <div role="group" aria-label={t("map.tools")} className="flex rounded-md border p-0.5">
              <Button size="xs" variant={tool === "select" ? "secondary" : "ghost"} aria-pressed={tool === "select"} onClick={() => setTool("select")}>
                <MousePointer2 />
                {t("map.tool.select")}
              </Button>
              <Button size="xs" variant={tool === "draw" ? "secondary" : "ghost"} aria-pressed={tool === "draw"} onClick={() => setTool("draw")}>
                <SquareDashed />
                {t("map.tool.area")}
              </Button>
            </div>
          </div>
        )}
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
          <RefreshCw />
          {t("map.refresh")}
        </Button>
        {canManage && (
          <>
            <Button variant={editMode ? "default" : "outline"} size="sm" aria-pressed={editMode} className={cn(editMode && "shadow-sm")} onClick={() => void toggleEdit()}>
              <Pencil />
              {t("map.edit")}
            </Button>
            <Button variant={adminOpen ? "secondary" : "ghost"} size="icon-sm" aria-pressed={adminOpen} aria-label={t("map.admin.title")} title={t("map.admin.title")} onClick={() => setAdminOpen((o) => !o)}>
              <Settings2 />
            </Button>
          </>
        )}
      </div>
      {(views.error || topo.error || error !== undefined) && (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, views.error ?? topo.error ?? error)}
        </p>
      )}
      <div className={`grid min-h-0 flex-1 gap-3 ${canManage && adminOpen ? "lg:grid-cols-[1fr_20rem]" : ""}`}>
        {topo.data ? (
          <NetworkMap
            key={viewId ?? 0}
            topology={topo.data}
            severity={problems.severity}
            problems={problems.counts}
            backgroundUrl={view?.background_id != null ? `/api/map/backgrounds/${view.background_id}` : undefined}
            save={editing ? savePositions : undefined}
            onSaved={onSaved}
            onSaveError={report}
            onOpenDevice={open}
            editor={editor}
          />
        ) : (
          <Skeleton className="h-full min-h-96 w-full" />
        )}
        {canManage && adminOpen && <MapAdmin view={view} onViewChosen={chooseView} />}
      </div>
    </section>
  );
}
