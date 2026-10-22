import { useTranslation } from "react-i18next";
import { errorKey } from "@/features/auth/errors";
import { ApiError } from "@/features/common/stepup";
import { useSystemStatus, type SystemStatus as Status } from "@/features/events/api";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";

/** An eventd instance is stale when its stats are older than this. */
export const EVENTD_STALE_MS = 30_000;
const WARN = "bg-red-50 dark:bg-red-950/40";
const TH = "px-3 py-2 font-medium";
const EVENTD_COLS = ["received", "accepted", "unknown_source", "auth_failed", "rate_limited", "dropped", "queue_depth"] as const;

/** A poller is silent when it owns devices and reports on none of them, or its heartbeat is older than this. */
export const POLLER_SILENT_MS = 90_000;

export function pollerSilent(p: Status["pollers"][number], now: number): boolean {
  return p.devices > 0 && (p.devices_reporting === 0 || (p.heartbeat_at !== null && now - Date.parse(p.heartbeat_at) > POLLER_SILENT_MS));
}

export function eventdStale(e: Status["eventd"][number], now: number): boolean {
  return now - Date.parse(e.updated_at) > EVENTD_STALE_MS;
}

function Flag({ children }: { children: string }) {
  return <span className="rounded bg-red-100 px-1.5 py-0.5 text-xs font-medium text-red-800 dark:bg-red-950 dark:text-red-300">{children}</span>;
}

/** System status (system.read): pollers, eventd counters, database size and job queues; problems are highlighted. */
export function SystemStatus() {
  const { t, i18n } = useTranslation();
  const q = useSystemStatus();
  if (q.isPending) return <p className="text-sm text-muted-foreground">{t("events.loading")}</p>;
  if (q.error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {q.error instanceof ApiError ? t(errorKey({ error: { code: q.error.code } })) : t("errors.unknown")}
      </p>
    );
  }
  const s = q.data;
  const now = Date.parse(s.now);
  const num = (n: number) => n.toLocaleString(i18n.language);

  return (
    <div className="grid gap-6">
      <section className="grid gap-2">
        <h2 className="text-base font-semibold">{t("system.pollers")}</h2>
        {s.pollers.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("system.noPollers")}</p>
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full min-w-[28rem] text-sm" aria-label={t("system.pollers")}>
              <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
                <tr>
                  <th className={TH}>{t("system.col.instance")}</th>
                  <th className={TH}>{t("system.col.devices")}</th>
                  <th className={TH}>{t("system.col.reporting")}</th>
                  <th className={TH}>{t("system.col.heartbeat")}</th>
                  <th className={TH} />
                </tr>
              </thead>
              <tbody>
                {s.pollers.map((p) => (
                  <tr key={p.id} data-alert={pollerSilent(p, now)} className={cn("border-t", pollerSilent(p, now) && WARN)}>
                    <td className="px-3 py-2 font-mono text-xs">{safeText(p.id)}</td>
                    <td className="px-3 py-2 tabular-nums">{num(p.devices)}</td>
                    <td className="px-3 py-2 tabular-nums">{num(p.devices_reporting)}</td>
                    <td className="px-3 py-2 text-xs tabular-nums">{p.heartbeat_at ? new Date(p.heartbeat_at).toLocaleString(i18n.language) : "—"}</td>
                    <td className="px-3 py-2">{pollerSilent(p, now) && <Flag>{t("system.silent")}</Flag>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="grid gap-2">
        <h2 className="text-base font-semibold">{t("system.eventd")}</h2>
        {s.eventd.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("system.noEventd")}</p>
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full min-w-[48rem] text-sm" aria-label={t("system.eventd")}>
              <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
                <tr>
                  <th className={TH}>{t("system.col.instance")}</th>
                  <th className={TH}>{t("system.col.updated")}</th>
                  {EVENTD_COLS.map((k) => (
                    <th key={k} className={TH}>
                      {t(`system.col.${k}`)}
                    </th>
                  ))}
                  <th className={TH} />
                </tr>
              </thead>
              <tbody>
                {s.eventd.map((e) => {
                  const stale = eventdStale(e, now);
                  return (
                    <tr key={e.instance} data-alert={stale} className={cn("border-t", stale && WARN)}>
                      <td className="px-3 py-2 font-mono text-xs">{safeText(e.instance)}</td>
                      <td className="px-3 py-2 text-xs tabular-nums">{new Date(e.updated_at).toLocaleString(i18n.language)}</td>
                      {EVENTD_COLS.map((k) => (
                        <td key={k} className="px-3 py-2 tabular-nums">
                          {num(e[k])}
                        </td>
                      ))}
                      <td className="px-3 py-2">{stale && <Flag>{t("system.stale")}</Flag>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="grid gap-2">
        <h2 className="text-base font-semibold">{t("system.database")}</h2>
        <p className="text-sm">{t("system.dbSize", { size: (s.db_size_bytes / 1048576).toLocaleString(i18n.language, { maximumFractionDigits: 1 }) })}</p>
      </section>

      <section className="grid gap-2">
        <h2 className="text-base font-semibold">{t("system.queues")}</h2>
        {s.queues.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("system.noQueues")}</p>
        ) : (
          <div className="overflow-x-auto rounded-md border">
            <table className="w-full min-w-[24rem] text-sm" aria-label={t("system.queues")}>
              <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
                <tr>
                  <th className={TH}>{t("system.col.queue")}</th>
                  <th className={TH}>{t("system.col.available")}</th>
                  <th className={TH}>{t("system.col.running")}</th>
                  <th className={TH}>{t("system.col.retryable")}</th>
                </tr>
              </thead>
              <tbody>
                {s.queues.map((r) => (
                  <tr key={r.name} className="border-t">
                    <td className="px-3 py-2 font-mono text-xs">{safeText(r.name)}</td>
                    <td className="px-3 py-2 tabular-nums">{num(r.available)}</td>
                    <td className="px-3 py-2 tabular-nums">{num(r.running)}</td>
                    <td className="px-3 py-2 tabular-nums">{num(r.retryable)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
