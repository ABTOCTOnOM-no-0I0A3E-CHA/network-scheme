import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errText } from "@/features/common/errText";
import { StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import type { Rect } from "./AreaOverlay";
import type { Topology } from "./semanticZoom";
import {
  useBackgrounds,
  useCreateArea,
  useCreateView,
  useDeleteArea,
  useDeleteBackground,
  useDeleteView,
  usePatchArea,
  usePatchView,
  useUploadBackground,
  type AreaBody,
  type MapAreaKind,
  type MapView,
} from "./useTopology";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
const KINDS: MapAreaKind[] = ["organization", "building", "floor", "room"];
const MAX_NAME = 100;

type Area = Topology["areas"][number];

/** Runs a mutation, reporting its error as text; a dismissed step-up prompt is not an error. */
function useGuarded() {
  const { t } = useTranslation();
  const [error, setError] = useState<string | undefined>();
  const run = async (fn: () => Promise<unknown>): Promise<boolean> => {
    setError(undefined);
    try {
      await fn();
      return true;
    } catch (e) {
      if (!(e instanceof StepUpCancelled)) setError(errText(t, e));
      return false;
    }
  };
  return { error, run };
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="grid gap-2">
      <h2 className="text-sm font-semibold">{title}</h2>
      {children}
    </section>
  );
}

/** Two-step delete button: the first click asks, the second one deletes. */
function ConfirmDelete({ label, onConfirm }: { label: string; onConfirm: () => void }) {
  const { t } = useTranslation();
  const [ask, setAsk] = useState(false);
  if (!ask)
    return (
      <Button type="button" variant="outline" size="sm" onClick={() => setAsk(true)}>
        {label}
      </Button>
    );
  return (
    <span className="flex gap-1">
      <Button type="button" variant="destructive" size="sm" onClick={onConfirm}>
        {t("map.admin.confirm")}
      </Button>
      <Button type="button" variant="outline" size="sm" onClick={() => setAsk(false)}>
        {t("map.admin.cancel")}
      </Button>
    </span>
  );
}

function ViewsEditor({ view, onChosen }: { view: MapView | undefined; onChosen: (id: number | undefined) => void }) {
  const { t } = useTranslation();
  const { error, run } = useGuarded();
  const create = useCreateView();
  const patch = usePatchView();
  const del = useDeleteView();
  const upload = useUploadBackground();
  const delBackground = useDeleteBackground();
  const [name, setName] = useState("");
  const [kind, setKind] = useState<MapView["kind"]>("logical");

  const createView = async (e: React.FormEvent) => {
    e.preventDefault();
    if (await run(() => create.mutateAsync({ name: name.trim(), kind }))) setName("");
  };

  return (
    <Section title={t("map.admin.views")}>
      <form className="grid gap-2" onSubmit={(e) => void createView(e)}>
        <Label htmlFor="mv-name">{t("map.admin.viewName")}</Label>
        <Input id="mv-name" value={name} maxLength={MAX_NAME} onChange={(e) => setName(e.target.value)} />
        <select aria-label={t("map.admin.viewKind")} className={SELECT_CLASS} value={kind} onChange={(e) => setKind(e.target.value as MapView["kind"])}>
          <option value="logical">{t("map.kind.logical")}</option>
          <option value="plan">{t("map.kind.plan")}</option>
        </select>
        <Button type="submit" size="sm" disabled={name.trim() === "" || create.isPending}>
          {t("map.admin.createView")}
        </Button>
      </form>
      {view && (
        <div className="grid gap-2 border-t pt-2">
          <p className="text-xs text-muted-foreground">{t("map.admin.current", { name: safeText(view.name) })}</p>
          <div className="flex flex-wrap gap-2">
            <Label className="inline-flex cursor-pointer items-center gap-2 rounded-md border px-3 py-1.5 text-sm">
              {t("map.admin.uploadBackground")}
              <input
                type="file"
                className="sr-only"
                accept="image/png,image/jpeg,image/webp,image/svg+xml"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (f) void run(async () => patch.mutateAsync({ id: view.id, body: { background_id: await upload.mutateAsync(f) } }));
                }}
              />
            </Label>
            {view.background_id !== null && (
              <Button type="button" variant="outline" size="sm" onClick={() => void run(() => patch.mutateAsync({ id: view.id, body: { background_id: null } }))}>
                {t("map.admin.removeBackground")}
              </Button>
            )}
            {view.background_id !== null && <ConfirmDelete label={t("map.admin.deleteBackground")} onConfirm={() => void run(() => delBackground.mutateAsync(view.background_id!))} />}
            <ConfirmDelete
              label={t("map.admin.deleteView")}
              onConfirm={() =>
                void run(async () => {
                  await del.mutateAsync(view.id);
                  onChosen(undefined);
                })
              }
            />
          </div>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </Section>
  );
}

/** Stored backgrounds: metadata and use count; only the ones no view uses can be deleted here. */
function BackgroundsEditor() {
  const { t, i18n } = useTranslation();
  const { error, run } = useGuarded();
  const list = useBackgrounds();
  const del = useDeleteBackground();
  const items = list.data ?? [];
  return (
    <Section title={t("map.admin.backgrounds")}>
      {list.isError && (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, list.error)}
        </p>
      )}
      {list.isSuccess && items.length === 0 && <p className="text-xs text-muted-foreground">{t("map.admin.backgroundsEmpty")}</p>}
      <ul className="grid max-h-60 gap-2 overflow-y-auto text-sm" aria-label={t("map.admin.backgrounds")}>
        {items.map((b) => (
          <li key={b.id} className="grid gap-1 rounded-md border p-2">
            <span>
              {t("map.admin.backgroundInfo", {
                id: b.id,
                mime: b.mime,
                width: b.width,
                height: b.height,
                kb: Math.max(1, Math.round(b.size / 1024)).toLocaleString(i18n.language),
              })}
            </span>
            <span className="text-xs text-muted-foreground">{new Date(b.uploaded_at).toLocaleString(i18n.language)}</span>
            {b.unused ? (
              <ConfirmDelete label={t("map.admin.deleteUnused", { id: b.id })} onConfirm={() => void run(() => del.mutateAsync(b.id))} />
            ) : (
              <span className="text-xs text-muted-foreground">{t("map.admin.backgroundViews", { n: b.views })}</span>
            )}
          </li>
        ))}
      </ul>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </Section>
  );
}

const num = (s: string) => (s.trim() === "" ? NaN : Number(s));

function AreaForm({ viewId, area, draft, areas, onDone }: { viewId: number; area?: Area; draft?: Rect; areas: Area[]; onDone: () => void }) {
  const { t } = useTranslation();
  const { error, run } = useGuarded();
  const create = useCreateArea(viewId);
  const patch = usePatchArea(viewId);
  const del = useDeleteArea(viewId);
  const src = area ?? draft ?? { x: 0, y: 0, w: 100, h: 100 };
  const [name, setName] = useState(area?.name ?? "");
  const [kind, setKind] = useState<MapAreaKind>(area?.kind ?? "building");
  const [parent, setParent] = useState<number | null>(area?.parent_id ?? null);
  const [x, setX] = useState(String(src.x));
  const [y, setY] = useState(String(src.y));
  const [w, setW] = useState(String(src.w));
  const [h, setH] = useState(String(src.h));
  const valid = name.trim() !== "" && [x, y, w, h].every((v) => Number.isFinite(num(v))) && num(w) > 0 && num(h) > 0;

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body: AreaBody = { name: name.trim(), kind, parent_id: parent, x: num(x), y: num(y), w: num(w), h: num(h) };
    if (await run(() => (area ? patch.mutateAsync({ id: area.id, body }) : create.mutateAsync(body)))) onDone();
  };

  return (
    <form className="grid gap-2 border-t pt-2" onSubmit={(e) => void submit(e)} aria-label={t("map.admin.areaForm")}>
      <Label htmlFor="ma-name">{t("map.admin.areaName")}</Label>
      <Input id="ma-name" value={name} maxLength={MAX_NAME} onChange={(e) => setName(e.target.value)} />
      <select aria-label={t("map.admin.areaKind")} className={SELECT_CLASS} value={kind} onChange={(e) => setKind(e.target.value as MapAreaKind)}>
        {KINDS.map((k) => (
          <option key={k} value={k}>
            {t(`map.areaKind.${k}`)}
          </option>
        ))}
      </select>
      <select aria-label={t("map.admin.areaParent")} className={SELECT_CLASS} value={parent ?? ""} onChange={(e) => setParent(e.target.value ? Number(e.target.value) : null)}>
        <option value="">{t("map.admin.noParent")}</option>
        {areas
          .filter((a) => a.id !== area?.id)
          .map((a) => (
            <option key={a.id} value={a.id}>
              {safeText(a.name)}
            </option>
          ))}
      </select>
      <div className="grid grid-cols-2 gap-2">
        {(
          [
            ["x", x, setX],
            ["y", y, setY],
            ["w", w, setW],
            ["h", h, setH],
          ] as const
        ).map(([k, v, set]) => (
          <label key={k} className="grid gap-1 text-xs">
            {t(`map.admin.geom.${k}`)}
            <Input type="number" value={v} onChange={(e) => set(e.target.value)} />
          </label>
        ))}
      </div>
      <div className="flex flex-wrap gap-2">
        <Button type="submit" size="sm" disabled={!valid}>
          {t("map.admin.save")}
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={onDone}>
          {t("map.admin.cancel")}
        </Button>
        {area && (
          <ConfirmDelete
            label={t("map.admin.deleteArea")}
            onConfirm={() =>
              void run(async () => {
                await del.mutateAsync(area.id);
                onDone();
              })
            }
          />
        )}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}

type Props = {
  views: MapView[];
  view: MapView | undefined;
  areas: Area[];
  tool: "select" | "draw";
  setTool: (t: "select" | "draw") => void;
  selectedId: number | undefined;
  setSelectedId: (id: number | undefined) => void;
  /** Rectangle just drawn on the map, waiting for a name. */
  draft: Rect | undefined;
  setDraft: (r: Rect | undefined) => void;
  onViewChosen: (id: number | undefined) => void;
};

/** map.manage tools: views, background upload, the list of backgrounds and area rectangles. */
export function MapAdmin({ view, areas, tool, setTool, selectedId, setSelectedId, draft, setDraft, onViewChosen }: Props) {
  const { t } = useTranslation();
  const selected = areas.find((a) => a.id === selectedId);
  return (
    <aside className="grid content-start gap-4 overflow-y-auto rounded-md border p-3" aria-label={t("map.admin.title")}>
      <ViewsEditor view={view} onChosen={onViewChosen} />
      <BackgroundsEditor />
      {view && (
        <Section title={t("map.admin.areas")}>
          <div className="flex gap-2">
            <Button type="button" size="sm" variant={tool === "select" ? "default" : "outline"} aria-pressed={tool === "select"} onClick={() => setTool("select")}>
              {t("map.admin.toolSelect")}
            </Button>
            <Button type="button" size="sm" variant={tool === "draw" ? "default" : "outline"} aria-pressed={tool === "draw"} onClick={() => setTool("draw")}>
              {t("map.admin.toolDraw")}
            </Button>
          </div>
          <ul className="max-h-40 overflow-y-auto text-sm">
            {areas.map((a) => (
              <li key={a.id}>
                <button type="button" className={`w-full truncate rounded px-2 py-1 text-left hover:bg-muted ${a.id === selectedId ? "bg-muted font-medium" : ""}`} onClick={() => setSelectedId(a.id)}>
                  {safeText(a.name)}
                </button>
              </li>
            ))}
          </ul>
          {(selected || draft) && (
            <AreaForm
              key={selected ? `a${selected.id}:${selected.x},${selected.y},${selected.w},${selected.h}` : `d${draft!.x},${draft!.y},${draft!.w},${draft!.h}`}
              viewId={view.id}
              area={selected}
              draft={selected ? undefined : draft}
              areas={areas}
              onDone={() => {
                setDraft(undefined);
                setSelectedId(undefined);
              }}
            />
          )}
        </Section>
      )}
    </aside>
  );
}
