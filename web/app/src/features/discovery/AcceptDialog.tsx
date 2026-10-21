import { useState, type FormEvent } from "react";
import { Dialog } from "radix-ui";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import type { Group } from "@/features/devices/api";
import { safeText } from "@/lib/text";
import { useAcceptDiscovered, type Discovered } from "./api";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

type Props = {
  item: Discovered | undefined;
  groups?: Group[];
  onClose: () => void;
  /** Called with the id of the created device. */
  onAccepted: (deviceId: number) => void;
};

/** Accepts a find as a device under a chosen name and group; open while `item` is set. */
export function AcceptDialog({ item, groups, onClose, onAccepted }: Props) {
  return (
    <Dialog.Root open={item !== undefined} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50" />
        <Dialog.Content className="fixed top-1/2 left-1/2 z-50 grid max-h-[90vh] w-full max-w-md -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-lg border bg-background p-6 shadow-lg">
          {/* mounted only with an item, so the fields start from that item's values */}
          {item && <AcceptForm item={item} groups={groups} onClose={onClose} onAccepted={onAccepted} />}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function AcceptForm({ item, groups, onClose, onAccepted }: Omit<Props, "item"> & { item: Discovered }) {
  const { t } = useTranslation();
  const accept = useAcceptDiscovered();
  const [error, setError] = useState<string | undefined>();

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(undefined);
    const fd = new FormData(e.currentTarget);
    const name = String(fd.get("name") ?? "").trim();
    const groupId = Number(fd.get("group_id"));
    if (!name || !Number.isInteger(groupId) || groupId <= 0) return setError(t("inbox.required"));
    try {
      onAccepted(await accept.mutateAsync({ id: item.id, name, group_id: groupId }));
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      if (err instanceof ApiError) return setError(t(errorKey({ error: { code: err.code } })));
      setError(t(err instanceof TypeError ? thrownKey(err) : "errors.unknown"));
    }
  };

  /* the device's own name is only a suggestion: control characters are dropped, the API validates the rest */
  const suggested = safeText(item.sys_name).replaceAll("\uFFFD", "").trim().slice(0, 200) || item.address;
  return (
    <form onSubmit={(e) => void submit(e)} className="grid gap-4" noValidate>
      <Dialog.Title className="text-lg font-semibold">{t("inbox.acceptTitle", { address: item.address })}</Dialog.Title>
      <Dialog.Description className="text-sm text-muted-foreground">{t("inbox.acceptDescription")}</Dialog.Description>
      <div className="grid gap-2">
        <Label htmlFor="accept-name">{t("devices.addDialog.name")}</Label>
        <Input id="accept-name" name="name" autoComplete="off" autoFocus defaultValue={suggested} />
      </div>
      <div className="grid gap-2">
        {groups ? (
          <>
            <Label htmlFor="accept-group">{t("devices.addDialog.group")}</Label>
            <select id="accept-group" name="group_id" className={SELECT_CLASS} defaultValue={item.group_id}>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </>
        ) : (
          <>
            <Label htmlFor="accept-group">{t("devices.addDialog.groupId")}</Label>
            <Input id="accept-group" name="group_id" type="number" min={1} defaultValue={item.group_id} />
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
        <Button type="submit" disabled={accept.isPending}>
          {t("inbox.accept")}
        </Button>
      </div>
    </form>
  );
}
