import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import type { Group } from "@/features/devices/api";
import { DEFAULT_SCAN_INTERVAL, MAX_SCAN_INTERVAL, MIN_SCAN_INTERVAL, useCreateScan } from "./api";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

/**
 * Message key of a failed scan request. cidr_too_wide (above /16) is unambiguous.
 * A malformed or reserved prefix (loopback, link-local, multicast, unspecified,
 * IPv4-mapped) shares the plain bad_request code with a bad interval or group, so
 * its message names all of them.
 */
export function scanErrorKey(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === "cidr_too_wide") return "scan.err.tooWide";
    if (err.code === "bad_request") return "scan.err.badRequest";
    return errorKey({ error: { code: err.code } });
  }
  return err instanceof TypeError ? thrownKey(err) : "errors.unknown";
}

type Props = {
  /** Groups to choose from; undefined when the caller may not list them (a numeric id is asked instead). */
  groups?: Group[];
  /** Called with the id of the created scan. */
  onCreated: (id: number) => void;
};

/** Schedules a subnet scan: CIDR, group and interval. The scan's own credential is set afterwards. */
export function ScanForm({ groups, onCreated }: Props) {
  const { t } = useTranslation();
  const create = useCreateScan();
  const [error, setError] = useState<string | undefined>();

  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setError(undefined);
    const form = e.currentTarget;
    const fd = new FormData(form);
    const cidr = String(fd.get("cidr") ?? "").trim();
    const groupId = Number(fd.get("group_id"));
    const interval = Number(fd.get("interval_s"));
    if (!cidr || !Number.isInteger(groupId) || groupId <= 0) return setError(t("scan.required"));
    if (!Number.isInteger(interval) || interval < MIN_SCAN_INTERVAL || interval > MAX_SCAN_INTERVAL) {
      return setError(t("scan.badInterval", { min: MIN_SCAN_INTERVAL, max: MAX_SCAN_INTERVAL }));
    }
    try {
      const id = await create.mutateAsync({ cidr, group_id: groupId, interval_s: interval });
      form.reset();
      onCreated(id);
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      setError(t(scanErrorKey(err)));
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} className="grid gap-4 rounded-md border p-4 sm:grid-cols-[1fr_1fr_10rem_auto] sm:items-end" noValidate>
      <div className="grid gap-2">
        <Label htmlFor="scan-cidr">{t("scan.cidr")}</Label>
        <Input id="scan-cidr" name="cidr" autoComplete="off" spellCheck={false} placeholder="192.0.2.0/24" />
      </div>
      <div className="grid gap-2">
        {groups ? (
          <>
            <Label htmlFor="scan-group">{t("scan.group")}</Label>
            <select id="scan-group" name="group_id" className={SELECT_CLASS}>
              {groups.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.name}
                </option>
              ))}
            </select>
          </>
        ) : (
          <>
            <Label htmlFor="scan-group">{t("scan.groupId")}</Label>
            <Input id="scan-group" name="group_id" type="number" min={1} />
          </>
        )}
      </div>
      <div className="grid gap-2">
        <Label htmlFor="scan-interval">{t("scan.interval")}</Label>
        <Input id="scan-interval" name="interval_s" type="number" min={MIN_SCAN_INTERVAL} max={MAX_SCAN_INTERVAL} defaultValue={DEFAULT_SCAN_INTERVAL} />
      </div>
      <Button type="submit" disabled={create.isPending}>
        {t("scan.create")}
      </Button>
      {error && (
        <p role="alert" className="text-sm text-destructive sm:col-span-4">
          {error}
        </p>
      )}
    </form>
  );
}
