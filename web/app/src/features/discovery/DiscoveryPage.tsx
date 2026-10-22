import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { useGroups } from "@/features/devices/api";
import { safeText } from "@/lib/text";
import { AcceptDialog } from "./AcceptDialog";
import { useIgnoreDiscovered, useInbox, useScans, useUpdateScan, type Discovered } from "./api";
import { ScanCredentialDialog } from "./ScanCredentialDialog";
import { ScanForm } from "./ScanForm";

/* a /16 scan can find tens of thousands of devices: the list is capped and the rest stays in the inbox */
const INBOX_LIMIT = 200;

const failText = (t: (k: string) => string, err: unknown) => t(err instanceof ApiError ? errorKey({ error: { code: err.code } }) : thrownKey(err));

type Props = {
  /** Whether the caller manages devices (a UI hint; the API decides). Without it nothing is requested or offered. */
  canManage: boolean;
  /** Whether group names can be fetched (global admin); otherwise "#<id>" is shown. */
  canListGroups?: boolean;
  /** Called with the id of a device created from an accepted find. */
  onOpenDevice: (id: number) => void;
};

/** Subnet scans (CIDR, group, interval, enabled, own credential) and the inbox of finds. Device-reported strings are shown as text. */
export function DiscoveryPage({ canManage, canListGroups = false, onOpenDevice }: Props) {
  const { t } = useTranslation();
  if (!canManage) {
    return (
      <section className="grid gap-2">
        <h1 className="text-xl font-semibold">{t("discovery.title")}</h1>
        <p className="text-sm text-muted-foreground">{t("discovery.noAccess")}</p>
      </section>
    );
  }
  return <Discovery canListGroups={canListGroups} onOpenDevice={onOpenDevice} />;
}

function Discovery({ canListGroups, onOpenDevice }: Pick<Props, "canListGroups" | "onOpenDevice">) {
  const { t, i18n } = useTranslation();
  const scans = useScans();
  const inbox = useInbox();
  const groups = useGroups(canListGroups);
  const update = useUpdateScan();
  const ignore = useIgnoreDiscovered();
  const [credScan, setCredScan] = useState<number | undefined>();
  const [accepting, setAccepting] = useState<Discovered | undefined>();
  const [note, setNote] = useState<string | undefined>();
  const groupNames = useMemo(() => new Map(groups.data?.map((g) => [g.id, g.name])), [groups.data]);
  const groupName = (id: number) => groupNames.get(id) ?? `#${id}`;
  const when = (iso: string) => new Date(iso).toLocaleString(i18n.language);

  const run = async (action: () => Promise<unknown>) => {
    setNote(undefined);
    try {
      await action();
    } catch (err) {
      if (!(err instanceof StepUpCancelled)) setNote(failText(t, err));
    }
  };

  const loadError = (e: unknown) => (e ? failText(t, e) : undefined);
  const finds = inbox.data ?? [];

  return (
    <section className="grid gap-6">
      <h1 className="text-xl font-semibold">{t("discovery.title")}</h1>
      {note && (
        <p role="alert" className="text-sm text-destructive">
          {note}
        </p>
      )}

      <div className="grid gap-3">
        <h2 className="text-lg font-semibold">{t("scan.title")}</h2>
        <ScanForm groups={groups.data} onCreated={setCredScan} />
        {loadError(scans.error) && (
          <p role="alert" className="text-sm text-destructive">
            {loadError(scans.error)}
          </p>
        )}
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full min-w-[44rem] text-sm" aria-label={t("scan.table")}>
            <thead className="bg-muted/50 text-left text-xs font-medium text-muted-foreground">
              <tr>
                <th className="p-3">{t("scan.cidr")}</th>
                <th className="p-3">{t("scan.group")}</th>
                <th className="p-3">{t("scan.interval")}</th>
                <th className="p-3">{t("scan.enabled")}</th>
                <th className="p-3">{t("scan.lastRun")}</th>
                <th className="p-3" />
              </tr>
            </thead>
            <tbody>
              {scans.data?.map((s) => (
                <tr key={s.id} className="border-t">
                  <td className="p-3 font-mono text-xs">{s.cidr}</td>
                  <td className="p-3">{groupName(s.group_id)}</td>
                  <td className="p-3 tabular-nums">{t("card.seconds", { n: s.interval_s })}</td>
                  <td className="p-3">
                    <input
                      type="checkbox"
                      className="size-4"
                      aria-label={t("scan.toggle", { cidr: s.cidr })}
                      checked={s.enabled}
                      disabled={update.isPending}
                      onChange={(e) => void run(() => update.mutateAsync({ id: s.id, enabled: e.target.checked }))}
                    />
                  </td>
                  <td className="p-3">{s.last_run_at ? when(s.last_run_at) : t("scan.never")}</td>
                  <td className="p-3 text-right">
                    <Button type="button" variant="outline" size="sm" onClick={() => setCredScan(s.id)}>
                      {t("scan.credential")}
                    </Button>
                  </td>
                </tr>
              ))}
              {scans.data?.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-4 text-muted-foreground">
                    {t("scan.empty")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="grid gap-3">
        <h2 className="text-lg font-semibold">{t("inbox.title")}</h2>
        {loadError(inbox.error) && (
          <p role="alert" className="text-sm text-destructive">
            {loadError(inbox.error)}
          </p>
        )}
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full min-w-[56rem] text-sm" aria-label={t("inbox.table")}>
            <thead className="bg-muted/50 text-left text-xs font-medium text-muted-foreground">
              <tr>
                <th className="p-3">{t("devices.col.address")}</th>
                <th className="p-3">{t("inbox.sysName")}</th>
                <th className="p-3">{t("inbox.sysDescr")}</th>
                <th className="p-3">{t("devices.col.group")}</th>
                <th className="p-3">{t("inbox.foundAt")}</th>
                <th className="p-3" />
              </tr>
            </thead>
            <tbody>
              {finds.slice(0, INBOX_LIMIT).map((d) => (
                <tr key={d.id} className="border-t align-top">
                  <td className="p-3 font-mono text-xs">{d.address}</td>
                  <td className="max-w-48 p-3 break-words">{safeText(d.sys_name)}</td>
                  <td className="max-w-md p-3 break-words text-muted-foreground">{safeText(d.sys_descr)}</td>
                  <td className="p-3">{groupName(d.group_id)}</td>
                  <td className="p-3">{when(d.found_at)}</td>
                  <td className="p-3 text-right whitespace-nowrap">
                    <Button type="button" size="sm" onClick={() => setAccepting(d)}>
                      {t("inbox.accept")}
                    </Button>{" "}
                    <Button type="button" variant="outline" size="sm" disabled={ignore.isPending} onClick={() => void run(() => ignore.mutateAsync(d.id))}>
                      {t("inbox.ignore")}
                    </Button>
                  </td>
                </tr>
              ))}
              {inbox.data && finds.length === 0 && (
                <tr>
                  <td colSpan={6} className="p-4 text-muted-foreground">
                    {t("inbox.empty")}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
        {finds.length > INBOX_LIMIT && <p className="text-xs text-muted-foreground">{t("inbox.count", { shown: INBOX_LIMIT, total: finds.length })}</p>}
      </div>

      <ScanCredentialDialog scanId={credScan} onClose={() => setCredScan(undefined)} />
      <AcceptDialog
        item={accepting}
        groups={groups.data}
        onClose={() => setAccepting(undefined)}
        onAccepted={(id) => {
          setAccepting(undefined);
          onOpenDevice(id);
        }}
      />
    </section>
  );
}
