import { useState, type FormEvent } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Dialog } from "radix-ui";
import { Pencil, Plus } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useContainerWidth, type Layout } from "react-grid-layout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { canManageDashboards } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { errText } from "@/features/common/errText";
import "@/widgets/builtin";
import { getWidget, listWidgets } from "@/widgets/registry";
import { pickDashboard, useCreateDashboard, useDashboard, useDashboards, useDeleteDashboard, useSaveWidgets, useUpdateDashboard, type DashboardDetail, type Role } from "./api";
import { COLS, DashboardGrid, STACK_BELOW } from "./DashboardGrid";
import type { GridItem } from "./WidgetFrame";
import { WidgetSettings } from "./WidgetSettings";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
const ROLES: Role[] = ["viewer", "operator", "admin", "auditor"];

let seq = 0;
const newKey = () => `n${++seq}`;

/** The stored widgets as grid items keyed by id. */
function toItems(d: DashboardDetail): GridItem[] {
  return d.widgets.map((w) => ({ key: `w${w.id}`, id: w.id, type: w.type, x: w.x, y: w.y, w: w.w, h: w.h, config: w.config as Record<string, unknown> }));
}

/** Applies a grid layout to the items (positions and sizes by key, clamped to the 12-column grid). */
export function applyLayout(items: GridItem[], layout: Layout): GridItem[] {
  const byKey = new Map(layout.map((l) => [l.i, l]));
  return items.map((it) => {
    const l = byKey.get(it.key);
    if (!l) return it;
    const w = Math.min(Math.max(1, l.w), COLS);
    return { ...it, x: Math.min(Math.max(0, l.x), COLS - w), y: Math.max(0, l.y), w, h: Math.min(Math.max(1, l.h), 48) };
  });
}

/** Adds a widget of type with its default config and size below everything else. */
export function addItem(items: GridItem[], type: string): GridItem[] {
  const def = getWidget(type);
  if (!def) return items;
  const y = items.reduce((m, it) => Math.max(m, it.y + it.h), 0);
  return [...items, { key: newKey(), type, x: 0, y, w: Math.min(def.size.w, COLS), h: def.size.h, config: { ...(def.defaultConfig as Record<string, unknown>) } }];
}

function CreateDialog({ open, onOpenChange, canShare }: { open: boolean; onOpenChange: (o: boolean) => void; canShare: boolean }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const create = useCreateDashboard();
  const [error, setError] = useState<string>();

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const name = String(fd.get("name") ?? "").trim();
    if (!name) return setError(t("dashboards.create.required"));
    try {
      const id = await create.mutateAsync({ name, shared: fd.get("shared") === "on" });
      onOpenChange(false);
      void navigate({ to: "/", search: { d: id } });
    } catch (err) {
      setError(errText(t, err));
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 grid w-full max-w-md -translate-x-1/2 -translate-y-1/2 gap-4 rounded-lg border bg-background p-6 shadow-lg">
          <form onSubmit={(e) => void submit(e)} className="grid gap-4" noValidate>
            <Dialog.Title className="text-lg font-semibold">{t("dashboards.create.title")}</Dialog.Title>
            <Dialog.Description className="text-sm text-muted-foreground">{t("dashboards.create.description")}</Dialog.Description>
            <div className="grid gap-2">
              <Label htmlFor="dashboard-name">{t("dashboards.name")}</Label>
              <Input id="dashboard-name" name="name" maxLength={200} autoComplete="off" autoFocus />
            </div>
            {canShare && (
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" name="shared" /> {t("dashboards.create.shared")}
              </label>
            )}
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                {t("dashboards.cancel")}
              </Button>
              <Button type="submit" disabled={create.isPending}>
                {t("dashboards.create.submit")}
              </Button>
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** Edit mode of one dashboard: the widget catalog, the draft grid, settings, name, role default, save and delete. */
function Editor({ dashboard, canManage, onDone }: { dashboard: DashboardDetail; canManage: boolean; onDone: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const [items, setItems] = useState(() => toItems(dashboard));
  const [name, setName] = useState(dashboard.name);
  const [role, setRole] = useState<string>(dashboard.default_for_role ?? "");
  const [settings, setSettings] = useState<string>();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [error, setError] = useState<string>();
  const save = useSaveWidgets(dashboard.id);
  const update = useUpdateDashboard();
  const remove = useDeleteDashboard();
  const editing = items.find((it) => it.key === settings);
  const busy = save.isPending || update.isPending || remove.isPending;

  const onSave = async () => {
    setError(undefined);
    const trimmed = name.trim();
    if (!trimmed) return setError(t("dashboards.create.required"));
    if (items.some((it) => !getWidget(it.type)?.configSchema.safeParse(it.config).success)) return setError(t("dashboards.unconfigured"));
    try {
      const patch: { name?: string; default_for_role?: Role | null } = {};
      if (trimmed !== dashboard.name) patch.name = trimmed;
      if (dashboard.shared && canManage && role !== (dashboard.default_for_role ?? "")) patch.default_for_role = role ? (role as Role) : null;
      if (Object.keys(patch).length) await update.mutateAsync({ id: dashboard.id, ...patch });
      await save.mutateAsync(items.map(({ id, type, x, y, w, h, config }) => ({ id, type, x, y, w, h, config })));
      onDone();
    } catch (err) {
      setError(errText(t, err));
    }
  };

  const onDelete = async () => {
    try {
      await remove.mutateAsync(dashboard.id);
      void navigate({ to: "/", search: {} });
    } catch (err) {
      setError(errText(t, err));
    }
  };

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-end gap-3 rounded-lg border p-3">
        <div className="grid gap-1">
          <Label htmlFor="dashboard-rename">{t("dashboards.name")}</Label>
          <Input id="dashboard-rename" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} className="w-64" />
        </div>
        {dashboard.shared && canManage && (
          <div className="grid gap-1">
            <Label htmlFor="dashboard-role">{t("dashboards.defaultFor")}</Label>
            <select id="dashboard-role" className={SELECT_CLASS} value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="">{t("dashboards.noRole")}</option>
              {ROLES.map((r) => (
                <option key={r} value={r}>
                  {t(`dashboards.role.${r}`)}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="ml-auto flex flex-wrap gap-2">
          {confirmDelete ? (
            <>
              <Button variant="destructive" disabled={busy} onClick={() => void onDelete()}>
                {t("dashboards.deleteConfirm")}
              </Button>
              <Button variant="outline" onClick={() => setConfirmDelete(false)}>
                {t("dashboards.cancel")}
              </Button>
            </>
          ) : (
            <Button variant="outline" onClick={() => setConfirmDelete(true)}>
              {t("dashboards.delete")}
            </Button>
          )}
          <Button variant="outline" onClick={onDone}>
            {t("dashboards.cancel")}
          </Button>
          <Button disabled={busy} onClick={() => void onSave()}>
            {t("dashboards.save")}
          </Button>
        </div>
        {error && (
          <p role="alert" className="w-full text-sm text-destructive">
            {error}
          </p>
        )}
      </div>
      <section aria-label={t("dashboards.catalog")} className="grid gap-2">
        <h2 className="text-sm font-medium">{t("dashboards.catalog")}</h2>
        <ul className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {listWidgets().map((w) => (
            <li key={w.type} className="flex items-start justify-between gap-2 rounded-md border p-2">
              <div className="min-w-0">
                <p className="text-sm font-medium">{t(w.title)}</p>
                <p className="text-xs text-muted-foreground">{t(w.description)}</p>
              </div>
              <Button size="sm" variant="outline" aria-label={t("dashboards.add", { name: t(w.title) })} disabled={items.length >= 50} onClick={() => setItems((old) => addItem(old, w.type))}>
                <Plus />
              </Button>
            </li>
          ))}
        </ul>
      </section>
      <DashboardGrid
        items={items}
        editing
        onLayout={(l) => setItems((old) => applyLayout(old, l))}
        onSettings={setSettings}
        onRemove={(key) => setItems((old) => old.filter((it) => it.key !== key))}
      />
      <WidgetSettings
        def={editing ? getWidget(editing.type) : undefined}
        config={editing?.config ?? {}}
        onSave={(config) => setItems((old) => old.map((it) => (it.key === settings ? { ...it, config } : it)))}
        onClose={() => setSettings(undefined)}
      />
    </div>
  );
}

/** Home page: the requested dashboard (?d=) or the default one of the user's role, with a selector, creation and edit mode. */
export function DashboardPage({ requested }: { requested?: number }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const session = useSession().data;
  const canManage = canManageDashboards(session);
  const list = useDashboards();
  const current = list.data ? pickDashboard(list.data, session?.roles.map((r) => r.role) ?? [], requested) : undefined;
  const detail = useDashboard(current?.id);
  const [editing, setEditing] = useState<number>();
  const [creating, setCreating] = useState(false);
  /* the header row is as wide as the grid: when the grid stacks, the dashboard is not editable */
  const { width, containerRef } = useContainerWidth();
  const stacked = width > 0 && width < STACK_BELOW;

  const err = list.error ?? detail.error;
  return (
    <section className="grid gap-4" aria-label={t("nav.dashboards")}>
      <div ref={containerRef} className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-semibold">{t("nav.dashboards")}</h1>
        {list.data && list.data.length > 0 && (
          <select
            aria-label={t("dashboards.select")}
            className={SELECT_CLASS}
            value={current?.id ?? ""}
            onChange={(e) => {
              setEditing(undefined);
              void navigate({ to: "/", search: { d: Number(e.target.value) } });
            }}
          >
            {list.data.map((d) => (
              <option key={d.id} value={d.id}>
                {d.shared ? t("dashboards.sharedName", { name: d.name }) : d.name}
              </option>
            ))}
          </select>
        )}
        <div className="ml-auto flex gap-2">
          {detail.data?.editable && !stacked && editing !== detail.data.id && (
            <Button variant="outline" onClick={() => setEditing(detail.data?.id)}>
              <Pencil />
              {t("dashboards.edit")}
            </Button>
          )}
          <Button variant="outline" onClick={() => setCreating(true)}>
            <Plus />
            {t("dashboards.new")}
          </Button>
        </div>
      </div>
      {err ? (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, err)}
        </p>
      ) : !list.data || (current && !detail.data) ? (
        <Skeleton className="h-64 w-full" />
      ) : !current || !detail.data ? (
        <p className="text-muted-foreground">{t("dashboards.none")}</p>
      ) : editing === detail.data.id ? (
        <Editor key={detail.data.id} dashboard={detail.data} canManage={canManage} onDone={() => setEditing(undefined)} />
      ) : detail.data.widgets.length === 0 ? (
        <p className="text-muted-foreground">{t(detail.data.editable ? "dashboards.emptyEditable" : "dashboards.empty")}</p>
      ) : (
        <DashboardGrid items={toItems(detail.data)} editing={false} onLayout={() => {}} onSettings={() => {}} onRemove={() => {}} />
      )}
      <CreateDialog open={creating} onOpenChange={setCreating} canShare={canManage} />
    </section>
  );
}
