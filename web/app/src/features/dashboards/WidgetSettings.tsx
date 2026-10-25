import { useState, type FormEvent } from "react";
import { Dialog } from "radix-ui";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useDevices } from "@/features/devices/api";
import { useViews } from "@/features/map/useTopology";
import { safeText } from "@/lib/text";
import type { AnyWidget, WidgetField } from "@/widgets/registry";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

type Values = Record<string, string>;

/** The form values of a config: every field as text, absent ones empty. */
function toValues(fields: WidgetField[], config: Record<string, unknown>): Values {
  return Object.fromEntries(fields.map((f) => [f.key, config[f.key] == null ? "" : String(config[f.key])]));
}

/** The config of the form values: empty fields are left out, numeric kinds become numbers; unknown keys of the old config are dropped. */
export function toConfig(fields: WidgetField[], v: Values): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const f of fields) {
    const s = (v[f.key] ?? "").trim();
    if (s === "") continue;
    out[f.key] = f.kind === "number" || f.kind === "device" || f.kind === "view" ? Number(s) : f.kind === "text" ? v[f.key] : s;
  }
  return out;
}

function DeviceSelect({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation();
  const devices = useDevices();
  return (
    <select id={id} className={SELECT_CLASS} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{t("common.choose")}</option>
      {value && !devices.data?.some((d) => String(d.id) === value) && <option value={value}>#{value}</option>}
      {devices.data?.map((d) => (
        <option key={d.id} value={d.id}>
          {safeText(d.name)}
        </option>
      ))}
    </select>
  );
}

function ViewSelect({ id, value, onChange }: { id: string; value: string; onChange: (v: string) => void }) {
  const { t } = useTranslation();
  const views = useViews();
  return (
    <select id={id} className={SELECT_CLASS} value={value} onChange={(e) => onChange(e.target.value)}>
      <option value="">{t("widgets.field.firstView")}</option>
      {views.data?.map((v) => (
        <option key={v.id} value={v.id}>
          {v.name}
        </option>
      ))}
    </select>
  );
}

function Fields({ def, config, onSave, onClose }: { def: AnyWidget; config: Record<string, unknown>; onSave: (c: Record<string, unknown>) => void; onClose: () => void }) {
  const { t } = useTranslation();
  const fields = def.fields ?? [];
  const [values, setValues] = useState(() => toValues(fields, config));
  const [invalid, setInvalid] = useState(false);
  const set = (k: string) => (v: string) => setValues((old) => ({ ...old, [k]: v }));

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const parsed = def.configSchema.safeParse(toConfig(fields, values));
    if (!parsed.success) return setInvalid(true);
    onSave(parsed.data);
    onClose();
  };

  return (
    <form onSubmit={submit} className="grid gap-4" noValidate>
      <Dialog.Title className="text-lg font-semibold">{t("widgets.settings.title", { name: t(def.title) })}</Dialog.Title>
      <Dialog.Description className="text-sm text-muted-foreground">{t(def.description)}</Dialog.Description>
      {fields.map((f) => {
        const id = `widget-field-${f.key}`;
        const value = values[f.key] ?? "";
        return (
          <div key={f.key} className="grid gap-2">
            <Label htmlFor={id}>{t(f.label)}</Label>
            {f.kind === "text" && <Input id={id} value={value} maxLength={f.maxLength} onChange={(e) => set(f.key)(e.target.value)} />}
            {f.kind === "number" && <Input id={id} type="number" min={f.min} max={f.max} value={value} onChange={(e) => set(f.key)(e.target.value)} />}
            {f.kind === "select" && (
              <select id={id} className={SELECT_CLASS} value={value} onChange={(e) => set(f.key)(e.target.value)}>
                <option value="">{t("widgets.field.any")}</option>
                {f.options.map((o) => (
                  <option key={o.value} value={o.value}>
                    {t(o.label)}
                  </option>
                ))}
              </select>
            )}
            {f.kind === "device" && <DeviceSelect id={id} value={value} onChange={set(f.key)} />}
            {f.kind === "view" && <ViewSelect id={id} value={value} onChange={set(f.key)} />}
          </div>
        );
      })}
      {invalid && (
        <p role="alert" className="text-sm text-destructive">
          {t("widgets.settings.invalid")}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onClose}>
          {t("dashboards.cancel")}
        </Button>
        <Button type="submit">{t("widgets.settings.apply")}</Button>
      </div>
    </form>
  );
}

/** Settings of one widget, built from its declared fields and checked with its schema before they are applied to the draft. */
export function WidgetSettings({ def, config, onSave, onClose }: { def: AnyWidget | undefined; config: Record<string, unknown>; onSave: (c: Record<string, unknown>) => void; onClose: () => void }) {
  return (
    <Dialog.Root open={def !== undefined} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 grid max-h-[90vh] w-full max-w-md -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-lg border bg-background p-6 shadow-lg">
          {def && <Fields def={def} config={config} onSave={onSave} onClose={onClose} />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
