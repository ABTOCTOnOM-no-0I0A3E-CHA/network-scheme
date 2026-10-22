import { useState, type FormEvent } from "react";
import { Dialog } from "radix-ui";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import type { CredKind } from "@/lib/seal";
import { useCreateDevice, type Group } from "./api";
import { ProfileForm } from "./ProfileForm";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
const KINDS: CredKind[] = ["snmp2c", "snmp3", "ssh_read"];

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Groups to choose from; undefined when the caller may not list them (a numeric id is asked instead). */
  groups?: Group[];
};

/** Two-step add-device dialog: device fields, then the read credential. */
export function AddDeviceDialog({ open, onOpenChange, groups }: Props) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 grid max-h-[90vh] w-full max-w-md -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-lg border bg-background p-6 shadow-lg">
          {/* mounted only while open, so both steps start fresh every time */}
          <Steps groups={groups} onClose={() => onOpenChange(false)} />
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Steps({ groups, onClose }: { groups?: Group[]; onClose: () => void }) {
  const { t } = useTranslation();
  const create = useCreateDevice();
  const [deviceId, setDeviceId] = useState<number | undefined>();
  const [kind, setKind] = useState<CredKind>("snmp2c");
  const [error, setError] = useState<string | undefined>();

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(undefined);
    const fd = new FormData(e.currentTarget);
    const name = String(fd.get("name") ?? "").trim();
    const address = String(fd.get("address") ?? "").trim();
    const groupId = Number(fd.get("group_id"));
    const port = Number(fd.get("port") || 161);
    if (!Number.isInteger(port) || port < 1 || port > 65535) return setError(t("devices.addDialog.badPort"));
    if (!name || !address || !Number.isInteger(groupId) || groupId <= 0) return setError(t("devices.addDialog.required"));
    try {
      setDeviceId(await create.mutateAsync({ name, address, group_id: groupId, snmp_port: port }));
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      if (err instanceof ApiError) return setError(t(errorKey({ error: { code: err.code } })));
      setError(t(err instanceof TypeError ? thrownKey(err) : "errors.unknown"));
    }
  };

  if (deviceId !== undefined) {
    return (
      <>
        <Dialog.Title className="text-lg font-semibold">{t("devices.addDialog.credTitle")}</Dialog.Title>
        <Dialog.Description className="text-sm text-muted-foreground">{t("devices.addDialog.credDescription")}</Dialog.Description>
        <div className="grid gap-2">
          <Label htmlFor="add-device-kind">{t("devices.addDialog.kind")}</Label>
          <select id="add-device-kind" className={SELECT_CLASS} value={kind} onChange={(e) => setKind(e.target.value as CredKind)}>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {t(`profile.title.${k}`)}
              </option>
            ))}
          </select>
        </div>
        {/* keyed by kind so switching the kind never carries typed secrets over */}
        <ProfileForm key={kind} owner={`device:${deviceId}`} kind={kind} onSaved={onClose} />
        <Button type="button" variant="outline" onClick={onClose}>
          {t("devices.addDialog.later")}
        </Button>
      </>
    );
  }

  return (
    <form onSubmit={(e) => void submit(e)} className="grid gap-4" noValidate>
      <Dialog.Title className="text-lg font-semibold">{t("devices.addDialog.title")}</Dialog.Title>
      <Dialog.Description className="text-sm text-muted-foreground">{t("devices.addDialog.description")}</Dialog.Description>
      <div className="grid gap-2">
        <Label htmlFor="add-device-name">{t("devices.addDialog.name")}</Label>
        <Input id="add-device-name" name="name" autoComplete="off" autoFocus />
      </div>
      <div className="grid grid-cols-[1fr_6rem] gap-2">
        <div className="grid gap-2">
          <Label htmlFor="add-device-address">{t("devices.addDialog.address")}</Label>
          <Input id="add-device-address" name="address" autoComplete="off" spellCheck={false} />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="add-device-port">{t("devices.addDialog.port")}</Label>
          <Input id="add-device-port" name="port" type="number" min={1} max={65535} defaultValue={161} />
        </div>
      </div>
      <div className="grid gap-2">
        {groups ? (
          <>
            <Label htmlFor="add-device-group">{t("devices.addDialog.group")}</Label>
            <select id="add-device-group" name="group_id" className={SELECT_CLASS}>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </>
        ) : (
          <>
            <Label htmlFor="add-device-group">{t("devices.addDialog.groupId")}</Label>
            <Input id="add-device-group" name="group_id" type="number" min={1} />
          </>
        )}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onClose}>
          {t("stepup.cancel")}
        </Button>
        <Button type="submit" disabled={create.isPending}>
          {t("devices.addDialog.create")}
        </Button>
      </div>
    </form>
  );
}
