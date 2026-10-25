import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { BACKUP_WATCH_MS, downloadUrl, useBackupDiff, useBackupNow, useBackups, useBackupState, type BackupVersion, type BackupWatch } from "./backups";
import { NeedsWrite, queryError } from "./ConfigTab";

const LINE_TONE = (l: string) =>
  l.startsWith("+") && !l.startsWith("+++")
    ? "bg-emerald-100 text-emerald-900 dark:bg-emerald-950 dark:text-emerald-200"
    : l.startsWith("-") && !l.startsWith("---")
      ? "bg-red-100 text-red-900 dark:bg-red-950 dark:text-red-200"
      : l.startsWith("@@")
        ? "text-sky-700 dark:text-sky-300"
        : "";

/* The fixed English texts of backup_state.last_error (internal/poller/backup.go) and their i18n keys; anything else is shown generically. */
const BACKUP_ERRORS: Record<string, string> = {
  "configuration backups are not configured on the poller": "noBackupKey",
  "reading the configuration of this model needs a write account; not backed up before phase 4": "needsWrite",
  "the driver cannot read the configuration": "noReader",
  "no usable SSH read credential": "noSSHProfile",
  "SSH connection failed": "sshFailed",
  "device identification failed": "identify",
  "configuration fetch failed": "fetchFailed",
  "configuration exceeds the 4 MiB limit": "tooLarge",
  "encryption of the configuration failed": "sealFailed",
  "storing the configuration failed": "storeFailed",
  "configuration backup timed out": "timeout",
  "the poller is busy with other backups; try again later": "busy",
};

/** Drift badge of a version (a change made outside a change session of the panel). */
export function DriftBadge() {
  const { t } = useTranslation();
  return <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] font-medium text-amber-800 dark:bg-amber-950 dark:text-amber-300">{t("backup.drift")}</span>;
}

/** "Бэкапы" tab: backup state, manual backup, the version list, a server-side diff of any two versions and the masked copy as a file. */
export function BackupsTab({ deviceId, canBackup }: { deviceId: number; canBackup: boolean }) {
  const { t, i18n } = useTranslation();
  const [watch, setWatch] = useState<BackupWatch | undefined>();
  const state = useBackupState(deviceId, watch);
  const versions = useBackups(deviceId);
  const now = useBackupNow(deviceId);
  const [note, setNote] = useState<{ ok: boolean; text: string } | undefined>();
  const list = useMemo(() => versions.data?.pages.flatMap((p) => p.items) ?? [], [versions.data]);
  const [a, setA] = useState<number | undefined>();
  const [b, setB] = useState<number | undefined>();
  const [pair, setPair] = useState<{ a: number; b: number } | undefined>();
  const fmt = (s: string) => new Date(s).toLocaleString(i18n.language);

  const backupNow = async () => {
    setNote(undefined);
    const before = { ok: state.data?.last_ok_at ?? null, err: state.data?.last_error ?? null };
    try {
      const n = await now.mutateAsync();
      if (!n) setWatch({ ...before, until: Date.now() + BACKUP_WATCH_MS });
      setNote({ ok: true, text: t(n ? "backup.recent" : "backup.queued") });
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      setNote({ ok: false, text: t(err instanceof ApiError ? errorKey({ error: { code: err.code } }) : err instanceof TypeError ? thrownKey(err) : "errors.unknown") });
    }
  };

  const compare = () => {
    const va = list.find((v) => v.id === a);
    const vb = list.find((v) => v.id === b);
    if (!va || !vb) return;
    /* the earlier version is always the left side */
    setPair(Date.parse(va.taken_at) <= Date.parse(vb.taken_at) ? { a: va.id, b: vb.id } : { a: vb.id, b: va.id });
  };

  const s = state.data;
  return (
    <div className="grid gap-4">
      {s?.needs_write && <NeedsWrite />}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <dl className="flex flex-wrap gap-x-6 gap-y-1 text-sm">
          <div>
            <dt className="text-xs text-muted-foreground">{t("backup.lastOk")}</dt>
            <dd>{s?.last_ok_at ? fmt(s.last_ok_at) : t("backup.never")}</dd>
          </div>
          {s?.last_error && (
            <div>
              <dt className="text-xs text-muted-foreground">{t("backup.lastError")}</dt>
              <dd className="text-destructive">{t(`backup.error.${Object.hasOwn(BACKUP_ERRORS, s.last_error) ? BACKUP_ERRORS[s.last_error] : "other"}`)}</dd>
            </div>
          )}
          {s?.latest_version?.drift && (
            <div>
              <dt className="text-xs text-muted-foreground">{t("backup.latest")}</dt>
              <dd>
                <DriftBadge />
              </dd>
            </div>
          )}
        </dl>
        {canBackup && !s?.needs_write && (
          <Button type="button" onClick={() => void backupNow()} disabled={now.isPending}>
            {t("backup.now")}
          </Button>
        )}
      </div>
      {note && (
        <p role={note.ok ? "status" : "alert"} className={cn("text-sm", note.ok ? "text-muted-foreground" : "text-destructive")}>
          {note.text}
        </p>
      )}
      {versions.error && (
        <p role="alert" className="text-sm text-destructive">
          {queryError(t, versions.error)}
        </p>
      )}
      {versions.isPending ? (
        <p className="text-sm text-muted-foreground">{t("card.loading")}</p>
      ) : list.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("backup.none")}</p>
      ) : (
        <>
          <VersionTable deviceId={deviceId} list={list} a={a} b={b} onA={setA} onB={setB} fmt={fmt} />
          <div className="flex flex-wrap items-center gap-2">
            {versions.hasNextPage && (
              <Button type="button" variant="outline" size="sm" disabled={versions.isFetchingNextPage} onClick={() => void versions.fetchNextPage()}>
                {t("backup.more")}
              </Button>
            )}
            <Button type="button" size="sm" disabled={a === undefined || b === undefined || a === b} onClick={compare}>
              {t("backup.compare")}
            </Button>
          </div>
        </>
      )}
      {pair && <DiffView deviceId={deviceId} pair={pair} fmt={fmt} />}
    </div>
  );
}

type TableProps = { deviceId: number; list: BackupVersion[]; a?: number; b?: number; onA: (id: number) => void; onB: (id: number) => void; fmt: (s: string) => string };

function VersionTable({ deviceId, list, a, b, onA, onB, fmt }: TableProps) {
  const { t, i18n } = useTranslation();
  return (
    <div className="overflow-x-auto rounded-md border">
      <table className="w-full min-w-[40rem] text-left text-sm" aria-label={t("backup.versions")}>
        <thead className="bg-muted/50 text-xs text-muted-foreground">
          <tr>
            <th scope="col" className="px-3 py-2 font-medium">
              {t("backup.sideA")}
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {t("backup.sideB")}
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {t("backup.takenAt")}
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {t("backup.source")}
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {t("backup.size")}
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              SHA-256
            </th>
            <th scope="col" className="px-3 py-2 font-medium">
              {t("backup.export")}
            </th>
          </tr>
        </thead>
        <tbody>
          {list.map((v) => {
            const when = fmt(v.taken_at);
            return (
              <tr key={v.id} className="border-t">
                <td className="px-3 py-2">
                  <input type="radio" name="side-a" aria-label={t("backup.pickA", { when })} checked={a === v.id} onChange={() => onA(v.id)} />
                </td>
                <td className="px-3 py-2">
                  <input type="radio" name="side-b" aria-label={t("backup.pickB", { when })} checked={b === v.id} onChange={() => onB(v.id)} />
                </td>
                <td className="px-3 py-2 whitespace-nowrap">
                  {when} {v.drift && <DriftBadge />}
                </td>
                <td className="px-3 py-2">{t(`backup.src.${v.source}`)}</td>
                <td className="px-3 py-2 tabular-nums">{v.size.toLocaleString(i18n.language)}</td>
                <td className="px-3 py-2 font-mono text-xs">{safeText(v.sha256)}</td>
                <td className="px-3 py-2">
                  {/* a same-origin attachment link: works under the CSP without blob: URLs */}
                  <a className="text-primary underline-offset-4 hover:underline" href={downloadUrl(deviceId, v.id)} download>
                    {t("backup.download")}
                  </a>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DiffView({ deviceId, pair, fmt }: { deviceId: number; pair: { a: number; b: number }; fmt: (s: string) => string }) {
  const { t } = useTranslation();
  const d = useBackupDiff(deviceId, pair);
  if (d.isPending) return <p className="text-sm text-muted-foreground">{t("card.loading")}</p>;
  if (d.error)
    return (
      <p role="alert" className="text-sm text-destructive">
        {queryError(t, d.error)}
      </p>
    );
  const lines = d.data.diff === "" ? [] : d.data.diff.replace(/\n$/, "").split("\n");
  return (
    <section className="grid gap-1" aria-label={t("backup.diff")}>
      <h3 className="text-sm font-medium">{t("backup.diffTitle", { a: fmt(d.data.a.taken_at), b: fmt(d.data.b.taken_at) })}</h3>
      {lines.length === 0 ? (
        <p className="text-sm text-muted-foreground">{t("backup.same")}</p>
      ) : (
        <pre data-testid="backup-diff" className="max-h-[65vh] overflow-auto rounded-md border bg-muted/30 py-2 font-mono text-xs">
          {lines.map((l, i) => (
            <div key={i} className={cn("px-3 whitespace-pre", LINE_TONE(l))}>
              {safeText(l.replace(/\t/g, "    ")) || " "}
            </div>
          ))}
        </pre>
      )}
    </section>
  );
}

const JOURNAL_VERSIONS = 10;

/** Journal block of the newest configuration versions (backups and drift); the syslog/trap feed follows it. */
export function BackupJournal({ deviceId }: { deviceId: number }) {
  const { t, i18n } = useTranslation();
  const versions = useBackups(deviceId);
  const list = versions.data?.pages[0]?.items.slice(0, JOURNAL_VERSIONS) ?? [];
  if (versions.error || list.length === 0) return null;
  return (
    <section className="grid gap-1" aria-label={t("backup.journal")}>
      <h3 className="text-sm font-medium">{t("backup.journal")}</h3>
      <ul className="grid gap-1 text-sm">
        {list.map((v) => (
          <li key={v.id} className="flex flex-wrap items-center gap-2">
            <time dateTime={v.taken_at} className="text-xs tabular-nums">
              {new Date(v.taken_at).toLocaleString(i18n.language)}
            </time>
            <span>{t(v.drift ? "backup.journalDrift" : "backup.journalVersion", { source: t(`backup.src.${v.source}`) })}</span>
            {v.drift && <DriftBadge />}
          </li>
        ))}
      </ul>
    </section>
  );
}
