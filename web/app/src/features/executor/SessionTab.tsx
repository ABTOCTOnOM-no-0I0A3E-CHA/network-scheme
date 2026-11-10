import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { History, Play, SquareTerminal } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { paths } from "@/api/schema";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/features/common/EmptyState";
import { unwrap } from "@/features/common/stepup";
import { api } from "@/lib/api";
import { useSessionHost } from "./SessionHost";

type SessionRow = paths["/api/devices/{id}/sessions"]["get"]["responses"]["200"]["content"]["application/json"]["items"][number];
const STATUSES = ["open", "closed", "timeout", "interrupted", "rolled_back"];

/** «Сессия» of the device window: opens the change session for this device in the shell's executor dock (FR-CHG-7). */
export function SessionTab({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const host = useSessionHost();
  return (
    <div className="grid max-w-2xl gap-4">
      <div className="flex items-start gap-3">
        <SquareTerminal aria-hidden className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
        <div className="grid gap-1.5 text-sm">
          <h3 className="font-semibold">{t("session.title")}</h3>
          <p className="text-muted-foreground">{t("session.explain")}</p>
          <p className="text-muted-foreground">{t("session.persist")}</p>
        </div>
      </div>
      {!host && (
        <p role="alert" className="text-sm text-destructive">
          {t("executor.frame.unavailable")}
        </p>
      )}
      {host && (
        <div className="flex flex-wrap items-center gap-3">
          {host.sessionOpen && <span className="rounded bg-emerald-500/15 px-2 py-1 text-xs text-emerald-700 dark:text-emerald-400">{t("executor.dock.open")}</span>}
          <Button type="button" onClick={() => host.open(deviceId)}>
            {t(host.sessionOpen ? "session.show" : "session.open")}
          </Button>
        </div>
      )}
    </div>
  );
}

/** The change sessions of the device from execpub (FR-UI-DEV-7); «Воспроизвести» opens the executor's player for one. */
export function SessionHistory({ deviceId }: { deviceId: number }) {
  const { t, i18n } = useTranslation();
  const host = useSessionHost();
  const [note, setNote] = useState(false);
  const q = useQuery({
    queryKey: ["devices", deviceId, "sessions"],
    retry: false,
    queryFn: async () => unwrap(await api.GET("/api/devices/{id}/sessions", { params: { path: { id: deviceId }, query: { limit: 50 } } })).items,
  });
  if (q.isPending) return <p className="text-sm text-muted-foreground">{t("card.loading")}</p>;
  if (q.error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {t("journal.sessionsError")}
      </p>
    );
  }
  if (q.data.length === 0) return <EmptyState icon={History} title={t("journal.sessionsEmpty")} hint={t("journal.sessionsHint")} />;
  const when = (iso: string | null) => (iso ? new Date(iso).toLocaleString(i18n.language) : "-");
  const play = (s: SessionRow) => setNote(!host?.replay(s.session_id, deviceId));
  return (
    <div className="grid gap-2">
      {note && (
        <p role="status" className="text-sm text-muted-foreground">
          {t("journal.replayBusy")}
        </p>
      )}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full text-sm">
          <thead className="bg-muted/40 text-left text-xs text-muted-foreground">
            <tr>
              <th className="px-3 py-2 font-medium">{t("journal.col.opened")}</th>
              <th className="px-3 py-2 font-medium">{t("journal.col.closed")}</th>
              <th className="px-3 py-2 font-medium">{t("journal.col.user")}</th>
              <th className="px-3 py-2 font-medium">{t("journal.col.status")}</th>
              <th className="px-3 py-2 font-medium">{t("journal.col.after")}</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {q.data.map((s) => (
              <tr key={s.session_id} className="border-t" data-testid={`session-${s.session_id}`}>
                <td className="px-3 py-2 whitespace-nowrap">{when(s.opened_at)}</td>
                <td className="px-3 py-2 whitespace-nowrap">{when(s.closed_at)}</td>
                <td className="px-3 py-2">{s.username ?? t("journal.deletedUser", { id: s.user_id })}</td>
                <td className="px-3 py-2">{STATUSES.includes(s.status) ? t(`journal.status.${s.status}`) : s.status}</td>
                <td className="px-3 py-2 font-mono text-xs">{s.post_sha256 ?? "-"}</td>
                <td className="px-3 py-2 text-right">
                  {host && s.status !== "open" && (
                    <Button type="button" variant="outline" size="sm" onClick={() => play(s)}>
                      <Play aria-hidden />
                      {t("journal.replay")}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
