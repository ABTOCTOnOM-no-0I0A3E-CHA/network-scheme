import { useState, type ComponentProps, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { useDevices, useUpdateDevice, type DeviceDetail, type DevicePatch, type Group } from "./api";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
/* client-side bounds; the API enforces its own as well */
const MAX_INTERVAL = 86400;
const INTERVALS = [
  { field: "interval_avail_s", min: 10, label: "card.edit.intervalAvail" },
  { field: "interval_metrics_s", min: 10, label: "card.edit.intervalMetrics" },
  { field: "interval_inventory_s", min: 60, label: "card.edit.intervalInventory" },
] as const;

type Props = { device: DeviceDetail; groups?: Group[]; onDone: () => void };

/** Edits name, address, SNMP port, group and polling intervals (an empty interval inherits from the group). */
export function DeviceEditForm({ device, groups, onDone }: Props) {
  const { t } = useTranslation();
  const update = useUpdateDevice(device.id);
  const devices = useDevices();
  const [error, setError] = useState<string | undefined>();
  /* controlled: the option list may still be loading, which must not read as "no parent" */
  const initialParent = String(device.parent_id ?? "");
  const [parent, setParent] = useState(initialParent);

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(undefined);
    const fd = new FormData(e.currentTarget);
    const f = (n: string) => String(fd.get(n) ?? "").trim();
    const patch: DevicePatch = {};
    if (!f("name") || !f("address")) return setError(t("card.edit.required"));
    if (f("name") !== device.name) patch.name = f("name");
    if (f("address") !== device.address) patch.address = f("address");
    const port = Number(f("port"));
    if (!Number.isInteger(port) || port < 1 || port > 65535) return setError(t("devices.addDialog.badPort"));
    if (port !== device.snmp_port) patch.snmp_port = port;
    const groupId = Number(f("group_id"));
    if (!Number.isInteger(groupId) || groupId <= 0) return setError(t("card.edit.required"));
    if (groupId !== device.group_id) patch.group_id = groupId;
    if (parent !== initialParent) patch.parent_id = parent === "" ? null : Number(parent);
    for (const { field, min } of INTERVALS) {
      const raw = f(field);
      const v = raw === "" ? null : Number(raw);
      if (v !== null && (!Number.isInteger(v) || v < min || v > MAX_INTERVAL)) return setError(t("card.edit.badInterval", { min, max: MAX_INTERVAL }));
      if (v !== device[field]) patch[field] = v;
    }
    if (Object.keys(patch).length === 0) return onDone();
    try {
      await update.mutateAsync(patch);
      onDone();
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      if (err instanceof ApiError) return setError(t(errorKey({ error: { code: err.code } })));
      setError(t(err instanceof TypeError ? thrownKey(err) : "errors.unknown"));
    }
  };

  const field = (id: string, label: string, props: ComponentProps<typeof Input>) => (
    <div className="grid gap-1.5">
      <Label htmlFor={`edit-${id}`}>{label}</Label>
      <Input id={`edit-${id}`} name={id} autoComplete="off" {...props} />
    </div>
  );

  return (
    <form onSubmit={(e) => void submit(e)} noValidate aria-label={t("card.edit.title")} className="grid gap-4 rounded-md border p-4">
      <h2 className="text-base font-semibold">{t("card.edit.title")}</h2>
      <div className="grid gap-4 sm:grid-cols-2">
        {field("name", t("devices.addDialog.name"), { defaultValue: device.name })}
        {field("address", t("devices.addDialog.address"), { defaultValue: device.address, spellCheck: false })}
        {field("port", t("devices.addDialog.port"), { type: "number", defaultValue: device.snmp_port })}
        {groups ? (
          <div className="grid gap-1.5">
            <Label htmlFor="edit-group_id">{t("devices.addDialog.group")}</Label>
            <select id="edit-group_id" name="group_id" className={SELECT_CLASS} defaultValue={device.group_id}>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </div>
        ) : (
          field("group_id", t("devices.addDialog.groupId"), { type: "number", defaultValue: device.group_id })
        )}
        <div className="grid gap-1.5">
          <Label htmlFor="edit-parent_id">{t("card.edit.parent")}</Label>
          <select id="edit-parent_id" name="parent_id" className={SELECT_CLASS} value={parent} onChange={(e) => setParent(e.target.value)}>
            <option value="">{t("card.edit.noParent")}</option>
            {device.parent_id != null && !devices.data?.some((d) => d.id === device.parent_id) && <option value={device.parent_id}>#{device.parent_id}</option>}
            {devices.data
              ?.filter((d) => d.id !== device.id)
              .map((d) => (
                <option key={d.id} value={d.id}>
                  {safeText(d.name)}
                </option>
              ))}
          </select>
        </div>
        {INTERVALS.map(({ field: name, label }) => field(name, t(label), { type: "number", placeholder: t("card.inherit"), defaultValue: device[name] ?? "" }))}
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
        <Button type="submit" disabled={update.isPending}>
          {t("profile.save")}
        </Button>
      </div>
    </form>
  );
}
