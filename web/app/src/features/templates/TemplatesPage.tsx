import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errText } from "@/features/common/errText";
import { GroupField } from "@/features/common/GroupField";
import { StepUpCancelled } from "@/features/common/stepup";
import { useGroups, type Group } from "@/features/devices/api";
import { SeverityBadge } from "@/features/events/EventFeed";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { useCreateTemplate, useDeleteTemplate, useDeleteTrigger, useTemplates, useTriggers, useUpdateTemplate, useUpdateTrigger, type Template, type Trigger } from "./api";
import { DRIVER_RE, MAX_INTERVAL_S, MAX_NAME_CHARS, MIN_INTERVAL_S, parseInterval, validName } from "./params";
import { TriggerForm } from "./TriggerForm";

const INTERVALS = ["interval_avail_s", "interval_metrics_s", "interval_inventory_s"] as const;
const INTERVAL_LABEL = { interval_avail_s: "card.edit.intervalAvail", interval_metrics_s: "card.edit.intervalMetrics", interval_inventory_s: "card.edit.intervalInventory" } as const;

type Props = {
  /** triggers.manage hint; the API decides. */
  canManage: boolean;
  /** Whether group names can be fetched (global admin). */
  canListGroups: boolean;
};

/** Monitoring templates: the list, the create form and the triggers of the selected template. Read-only without triggers.manage. */
export function TemplatesPage({ canManage, canListGroups }: Props) {
  const { t } = useTranslation();
  const templates = useTemplates();
  const groups = useGroups(canListGroups);
  const [selected, setSelected] = useState<number | undefined>();
  const [creating, setCreating] = useState(false);
  const current = templates.data?.find((x) => x.id === selected);
  const groupName = (id: number | null) => (id === null ? "" : (groups.data?.find((g) => g.id === id)?.name ?? `#${id}`));

  return (
    <section className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{t("nav.templates")}</h1>
        {canManage && !creating && (
          <Button type="button" onClick={() => setCreating(true)}>
            {t("templates.add")}
          </Button>
        )}
      </div>
      {creating && <TemplateForm groups={groups.data} onDone={() => setCreating(false)} />}
      {templates.error && (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, templates.error)}
        </p>
      )}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[32rem] text-sm" aria-label={t("templates.table")}>
          <thead className="bg-muted/50 text-left text-xs font-medium text-muted-foreground">
            <tr>
              <th className="px-3 py-2">{t("templates.col.name")}</th>
              <th className="px-3 py-2">{t("templates.col.binding")}</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {templates.data?.map((x) => (
              <tr key={x.id} className={cn("border-t", x.id === selected && "bg-muted/40")}>
                <td className="max-w-64 px-3 py-2">
                  <div className="truncate" title={safeText(x.name)}>
                    {safeText(x.name)}
                  </div>
                </td>
                <td className="px-3 py-2 text-xs">
                  {x.driver !== null ? t("templates.bindingDriver", { name: safeText(x.driver) }) : t("templates.bindingGroup", { name: safeText(groupName(x.group_id)) })}
                </td>
                <td className="px-3 py-2 text-right">
                  <Button type="button" variant="outline" size="sm" aria-label={t("templates.open", { name: safeText(x.name) })} onClick={() => setSelected(x.id === selected ? undefined : x.id)}>
                    {t(x.id === selected ? "templates.close" : "templates.openShort")}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {templates.isPending && <p className="p-4 text-sm text-muted-foreground">{t("events.loading")}</p>}
        {templates.data?.length === 0 && <p className="p-4 text-sm text-muted-foreground">{t("templates.empty")}</p>}
      </div>
      {current && <TemplateDetail key={current.id} template={current} canManage={canManage} groups={groups.data} onGone={() => setSelected(undefined)} />}
    </section>
  );
}

function TemplateDetail({ template, canManage, groups, onGone }: { template: Template; canManage: boolean; groups?: Group[]; onGone: () => void }) {
  const { t } = useTranslation();
  const triggers = useTriggers(template.id);
  const del = useDeleteTemplate();
  const [editingTemplate, setEditingTemplate] = useState(false);
  const [triggerForm, setTriggerForm] = useState<"new" | Trigger | undefined>();
  const [confirm, setConfirm] = useState(false);
  const [error, setError] = useState<string | undefined>();

  const remove = async () => {
    setError(undefined);
    try {
      await del.mutateAsync(template.id);
      onGone();
    } catch (err) {
      if (!(err instanceof StepUpCancelled)) setError(errText(t, err));
    }
  };

  return (
    <div className="grid gap-4 rounded-md border p-4" data-testid="template-detail">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="min-w-0 text-base font-semibold break-words">{safeText(template.name)}</h2>
        {canManage && (
          <div className="flex gap-2">
            {!editingTemplate && (
              <Button type="button" variant="outline" size="sm" onClick={() => setEditingTemplate(true)}>
                {t("templates.edit")}
              </Button>
            )}
            {confirm ? (
              <>
                <Button type="button" variant="destructive" size="sm" disabled={del.isPending} onClick={() => void remove()}>
                  {t("templates.deleteConfirm")}
                </Button>
                <Button type="button" variant="outline" size="sm" onClick={() => setConfirm(false)}>
                  {t("stepup.cancel")}
                </Button>
              </>
            ) : (
              <Button type="button" variant="outline" size="sm" onClick={() => setConfirm(true)}>
                {t("templates.delete")}
              </Button>
            )}
          </div>
        )}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {editingTemplate && <TemplateForm template={template} groups={groups} onDone={() => setEditingTemplate(false)} />}
      <dl className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
        {INTERVALS.map((k) => (
          <div key={k}>
            <dt className="text-xs text-muted-foreground">{t(INTERVAL_LABEL[k])}</dt>
            <dd>{template[k] === null ? t("card.inherit") : t("card.seconds", { n: template[k] })}</dd>
          </div>
        ))}
      </dl>
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-sm font-semibold">{t("templates.triggers")}</h3>
        {canManage && !triggerForm && (
          <Button type="button" size="sm" onClick={() => setTriggerForm("new")}>
            {t("templates.trigger.add")}
          </Button>
        )}
      </div>
      {triggerForm && <TriggerForm key={triggerForm === "new" ? "new" : triggerForm.id} templateId={template.id} trigger={triggerForm === "new" ? undefined : triggerForm} onDone={() => setTriggerForm(undefined)} />}
      {triggers.error && (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, triggers.error)}
        </p>
      )}
      {triggers.data?.length === 0 && <p className="text-sm text-muted-foreground">{t("templates.noTriggers")}</p>}
      <ul className="grid gap-2">
        {triggers.data?.map((g) => (
          <TriggerRow key={g.id} templateId={template.id} trigger={g} canManage={canManage} onEdit={() => setTriggerForm(g)} />
        ))}
      </ul>
    </div>
  );
}

function TriggerRow({ templateId, trigger: g, canManage, onEdit }: { templateId: number; trigger: Trigger; canManage: boolean; onEdit: () => void }) {
  const { t } = useTranslation();
  const upd = useUpdateTrigger();
  const del = useDeleteTrigger();
  const [error, setError] = useState<string | undefined>();
  const run = async (fn: () => Promise<unknown>) => {
    setError(undefined);
    try {
      await fn();
    } catch (err) {
      if (!(err instanceof StepUpCancelled)) setError(errText(t, err));
    }
  };
  return (
    <li className="grid gap-1 rounded-md border px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={g.severity} />
        <span className="min-w-0 flex-1 truncate" title={safeText(g.name)}>
          {safeText(g.name)}
        </span>
        <span className="text-xs text-muted-foreground">{t(`templates.kind.${g.kind}`)}</span>
        {!g.enabled && <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{t("templates.disabled")}</span>}
        {canManage && (
          <div className="flex gap-1">
            <Button type="button" variant="outline" size="sm" disabled={upd.isPending} onClick={() => void run(() => upd.mutateAsync({ templateId, id: g.id, body: { enabled: !g.enabled } }))}>
              {t(g.enabled ? "templates.disable" : "templates.enable")}
            </Button>
            <Button type="button" variant="outline" size="sm" aria-label={t("templates.trigger.editNamed", { name: safeText(g.name) })} onClick={onEdit}>
              {t("templates.edit")}
            </Button>
            <Button type="button" variant="outline" size="sm" disabled={del.isPending} aria-label={t("templates.trigger.deleteNamed", { name: safeText(g.name) })} onClick={() => void run(() => del.mutateAsync({ templateId, id: g.id }))}>
              {t("templates.delete")}
            </Button>
          </div>
        )}
      </div>
      <code className="text-xs break-all text-muted-foreground">{safeText(JSON.stringify(g.params))}</code>
      {error && (
        <p role="alert" className="text-xs text-destructive">
          {error}
        </p>
      )}
    </li>
  );
}

/** Create (name, binding, intervals) or edit (name, intervals; the binding is fixed) a template. */
function TemplateForm({ template, groups, onDone }: { template?: Template; groups?: Group[]; onDone: () => void }) {
  const { t } = useTranslation();
  const create = useCreateTemplate();
  const update = useUpdateTemplate();
  const [name, setName] = useState(template?.name ?? "");
  const [bind, setBind] = useState<"driver" | "group">("driver");
  const [driver, setDriver] = useState("");
  const [groupId, setGroupId] = useState("");
  const [iv, setIv] = useState<Record<(typeof INTERVALS)[number], string>>({
    interval_avail_s: String(template?.interval_avail_s ?? ""),
    interval_metrics_s: String(template?.interval_metrics_s ?? ""),
    interval_inventory_s: String(template?.interval_inventory_s ?? ""),
  });
  const [error, setError] = useState<string | undefined>();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    if (!validName(name)) return setError(t("templates.err.name", { max: MAX_NAME_CHARS }));
    const vals = {} as Record<(typeof INTERVALS)[number], number | null>;
    for (const k of INTERVALS) {
      const v = parseInterval(iv[k]);
      if (v === undefined) return setError(t("card.edit.badInterval", { min: MIN_INTERVAL_S, max: MAX_INTERVAL_S }));
      vals[k] = v;
    }
    try {
      if (template) {
        await update.mutateAsync({ id: template.id, body: { name, ...vals } });
      } else if (bind === "driver") {
        if (!DRIVER_RE.test(driver)) return setError(t("templates.err.driver"));
        await create.mutateAsync({ name, driver, ...vals });
      } else {
        const g = Number(groupId);
        if (!Number.isInteger(g) || g <= 0) return setError(t("templates.err.group"));
        await create.mutateAsync({ name, group_id: g, ...vals });
      }
      onDone();
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      setError(errText(t, err));
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} noValidate aria-label={t(template ? "templates.edit" : "templates.add")} className="grid gap-4 rounded-md border p-4">
      <h3 className="text-sm font-semibold">{t(template ? "templates.edit" : "templates.add")}</h3>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label htmlFor="tpl-name">{t("templates.col.name")}</Label>
          <Input id="tpl-name" value={name} maxLength={MAX_NAME_CHARS} autoComplete="off" onChange={(e) => setName(e.target.value)} />
        </div>
        {!template && (
          <>
            <div className="grid gap-1.5">
              <Label htmlFor="tpl-bind">{t("templates.col.binding")}</Label>
              <select id="tpl-bind" className="h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30" value={bind} onChange={(e) => setBind(e.target.value as "driver" | "group")}>
                <option value="driver">{t("templates.bind.driver")}</option>
                <option value="group">{t("templates.bind.group")}</option>
              </select>
            </div>
            {bind === "driver" ? (
              <div className="grid gap-1.5">
                <Label htmlFor="tpl-driver">{t("templates.bind.driver")}</Label>
                <Input id="tpl-driver" value={driver} maxLength={64} autoComplete="off" spellCheck={false} onChange={(e) => setDriver(e.target.value)} />
              </div>
            ) : (
              <GroupField id="tpl-group" label={t("templates.bind.group")} value={groupId} onChange={setGroupId} groups={groups} />
            )}
          </>
        )}
        {INTERVALS.map((k) => (
          <div key={k} className="grid gap-1.5">
            <Label htmlFor={`tpl-${k}`}>{t(INTERVAL_LABEL[k])}</Label>
            <Input id={`tpl-${k}`} type="number" placeholder={t("card.inherit")} value={iv[k]} onChange={(e) => setIv((v) => ({ ...v, [k]: e.target.value }))} />
          </div>
        ))}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onDone}>
          {t("stepup.cancel")}
        </Button>
        <Button type="submit" disabled={create.isPending || update.isPending}>
          {t("profile.save")}
        </Button>
      </div>
    </form>
  );
}
