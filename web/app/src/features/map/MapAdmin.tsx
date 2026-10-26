import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errText } from "@/features/common/errText";
import { StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { useBackgrounds, useCreateView, useDeleteBackground, useDeleteView, usePatchView, useUploadBackground, type MapView } from "./useTopology";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
const MAX_NAME = 100;

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

type Props = {
  view: MapView | undefined;
  onViewChosen: (id: number | undefined) => void;
};

/** map.manage tools for views and backgrounds (zones are edited on the map itself, in edit mode). */
export function MapAdmin({ view, onViewChosen }: Props) {
  const { t } = useTranslation();
  return (
    <aside className="grid content-start gap-4 overflow-y-auto rounded-md border p-3" aria-label={t("map.admin.title")}>
      <ViewsEditor view={view} onChosen={onViewChosen} />
      <BackgroundsEditor />
    </aside>
  );
}
