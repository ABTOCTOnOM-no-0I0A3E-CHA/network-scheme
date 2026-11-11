import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { GitPullRequestArrow } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { paths } from "@/api/schema";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/features/common/EmptyState";
import { errText } from "@/features/common/errText";
import { unwrap } from "@/features/common/stepup";
import { useSessionHost } from "@/features/executor/SessionHost";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";

type Row = paths["/api/executor/changesets"]["get"]["responses"]["200"]["content"]["application/json"]["items"][number];

const TONE: Record<string, string> = {
  draft: "bg-muted text-muted-foreground",
  dry_run_ok: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
  dry_run_failed: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  approved: "bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-300",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  done: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
  rolled_back: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  rollback_failed: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  interrupted: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  discarded: "bg-muted text-muted-foreground line-through",
};

/* a running changeset is read again this often while the page is open */
const RUNNING_REFRESH_MS = 10_000;

/**
 * «Изменения» (FR-UI-2, Task 5.9): the changesets of the devices in the user's scope, from execpub.changeset_summary
 * (metadata only: the lines, dry-runs and configurations stay in the executor). «Открыть» and «Создать» open the
 * executor's own section in the shell's dock (its origin, its TOTP); nothing here decides anything.
 */
export function ChangesPage() {
  const { t, i18n } = useTranslation();
  const host = useSessionHost();
  const [busy, setBusy] = useState(false);
  const q = useQuery({
    queryKey: ["executor", "changesets"],
    retry: false,
    queryFn: async () => unwrap(await api.GET("/api/executor/changesets", { params: { query: { limit: 200 } } })).items,
    refetchInterval: (query) => (query.state.data?.some((r) => r.status === "running") ? RUNNING_REFRESH_MS : false),
  });
  const fmt = (iso: string) => new Date(iso).toLocaleString(i18n.language);
  const openIn = (id?: string) => setBusy(!host?.changeset(id));

  return (
    <section className="grid gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="mr-auto text-xl font-semibold">{t("nav.changes")}</h1>
        {host && (
          <Button type="button" onClick={() => openIn()} data-testid="changes-create">
            {t("changes.create")}
          </Button>
        )}
      </div>
      <p className="max-w-3xl text-sm text-muted-foreground">{t("changes.hint")}</p>
      {!host && (
        <p role="alert" className="text-sm text-destructive">
          {t("executor.frame.unavailable")}
        </p>
      )}
      {busy && (
        <p role="status" className="text-sm text-amber-700 dark:text-amber-300">
          {t("changes.sessionOpen")}
        </p>
      )}
      {q.error && (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, q.error)}
        </p>
      )}
      {q.isPending && <p className="text-sm text-muted-foreground">{t("card.loading")}</p>}
      {q.data?.length === 0 && <EmptyState icon={GitPullRequestArrow} title={t("changes.empty")} hint={t("changes.emptyHint")} />}
      {q.data && q.data.length > 0 && (
        <div className="overflow-x-auto rounded-md border">
          <table className="w-full min-w-[48rem] text-sm" aria-label={t("changes.table")}>
            <thead className="bg-muted/50 text-left text-xs font-medium text-muted-foreground">
              <tr>
                <th className="px-3 py-2">{t("changes.col.title")}</th>
                <th className="px-3 py-2">{t("changes.col.status")}</th>
                <th className="px-3 py-2">{t("changes.col.kind")}</th>
                <th className="px-3 py-2 text-right">{t("changes.col.devices")}</th>
                <th className="px-3 py-2">{t("changes.col.author")}</th>
                <th className="px-3 py-2">{t("changes.col.updated")}</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {q.data.map((r: Row) => (
                <tr key={r.changeset_id} className="border-t" data-testid={`change-${r.changeset_id}`}>
                  <td className="max-w-md px-3 py-2">
                    <div className="truncate font-medium" title={safeText(r.title)}>
                      {safeText(r.title)}
                    </div>
                    <div className="font-mono text-[11px] text-muted-foreground">{r.changeset_id.slice(0, 8)}</div>
                  </td>
                  <td className="px-3 py-2">
                    <span data-status={r.status} className={cn("inline-flex rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap", TONE[r.status] ?? TONE.draft)}>
                      {t(`changes.status.${r.status}`)}
                    </span>
                    {r.failed_device_id !== null && <div className="mt-0.5 text-xs text-muted-foreground">{t("changes.failedOn", { id: r.failed_device_id })}</div>}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{t(`changes.kind.${r.kind}`)}</td>
                  <td className="px-3 py-2 text-right tabular-nums">{r.device_count}</td>
                  <td className="px-3 py-2">{r.author === null ? t("changes.deletedUser", { id: r.author_id }) : safeText(r.author)}</td>
                  <td className="px-3 py-2 text-xs whitespace-nowrap tabular-nums">{fmt(r.updated_at)}</td>
                  <td className="px-3 py-2 text-right">
                    {host && (
                      <Button type="button" variant="outline" size="sm" aria-label={t("changes.openNamed", { title: safeText(r.title) })} onClick={() => openIn(r.changeset_id)}>
                        {t("changes.open")}
                      </Button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
