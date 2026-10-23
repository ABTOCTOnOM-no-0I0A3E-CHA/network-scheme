import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import type { components } from "@/api/schema";
import { errText } from "@/features/common/errText";
import { GroupField } from "@/features/common/GroupField";
import { StepUpCancelled, unwrap, withStepUp } from "@/features/common/stepup";
import { useGroups } from "@/features/devices/api";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";

type Window = components["schemas"]["MaintenanceWindow"];

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };
const KEY = ["maintenance"] as const;
const MAX_SPAN_MS = 7 * 86_400_000;
const MAX_COMMENT = 1000;

function useWindows(includeEnded: boolean) {
  return useQuery({
    queryKey: [...KEY, includeEnded],
    retry: false,
    queryFn: async () => unwrap(await api.GET("/api/maintenance", { params: { query: { include_ended: includeEnded ? "true" : "false" } } })),
  });
}

function useCreateWindow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: { group_id: number; starts_at: string; ends_at: string; comment?: string }) =>
      withStepUp(async () => void unwrap(await api.POST("/api/maintenance", { params: CSRF, body }))),
    onSettled: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

function useEndWindow() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => withStepUp(async () => void unwrap(await api.DELETE("/api/maintenance/{id}", { params: { path: { id }, ...CSRF } }))),
    onSettled: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}

/** The server rules for a window: ends after it starts, lasts at most 7 days, ends in the future. Returns the i18n key suffix of the first violation. */
export function checkWindow(startsAt: number, endsAt: number, now: number): "required" | "order" | "tooLong" | "past" | undefined {
  if (Number.isNaN(startsAt) || Number.isNaN(endsAt)) return "required";
  if (endsAt <= startsAt) return "order";
  if (endsAt - startsAt > MAX_SPAN_MS) return "tooLong";
  if (endsAt <= now) return "past";
  return undefined;
}

type Props = {
  /** maintenance.manage hint; the API decides. */
  canManage: boolean;
  /** Whether group names can be fetched (global admin). */
  canListGroups: boolean;
};

/** Maintenance windows of a group: problems of its devices open suppressed while a window lasts. Read-only without maintenance.manage. */
export function MaintenancePage({ canManage, canListGroups }: Props) {
  const { t, i18n } = useTranslation();
  const [ended, setEnded] = useState(false);
  const windows = useWindows(ended);
  const groups = useGroups(canListGroups);
  const end = useEndWindow();
  const [error, setError] = useState<string | undefined>();

  const stop = async (w: Window) => {
    setError(undefined);
    try {
      await end.mutateAsync(w.id);
    } catch (err) {
      if (!(err instanceof StepUpCancelled)) setError(errText(t, err));
    }
  };
  const fmt = (iso: string) => new Date(iso).toLocaleString(i18n.language);
  /* "over" is judged at the moment the list was loaded */
  const now = windows.dataUpdatedAt;

  return (
    <section className="grid gap-4">
      <h1 className="text-xl font-semibold">{t("nav.maintenance")}</h1>
      <p className="text-sm text-muted-foreground">{t("maintenance.hint")}</p>
      {canManage && <WindowForm groups={groups.data} />}
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={ended} onChange={(e) => setEnded(e.target.checked)} />
        {t("maintenance.showEnded")}
      </label>
      {(windows.error || error) && (
        <p role="alert" className="text-sm text-destructive">
          {error ?? errText(t, windows.error)}
        </p>
      )}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[40rem] text-sm" aria-label={t("maintenance.table")}>
          <thead className="bg-muted/50 text-left text-xs font-medium text-muted-foreground">
            <tr>
              <th className="px-3 py-2">{t("maintenance.col.group")}</th>
              <th className="px-3 py-2">{t("maintenance.col.starts")}</th>
              <th className="px-3 py-2">{t("maintenance.col.ends")}</th>
              <th className="px-3 py-2">{t("maintenance.col.comment")}</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {windows.data?.map((w) => {
              const over = Date.parse(w.ends_at) <= now;
              return (
                <tr key={w.id} className="border-t">
                  <td className="max-w-48 px-3 py-2">
                    <div className="truncate" title={safeText(w.group_name)}>
                      {safeText(w.group_name)}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs tabular-nums">{fmt(w.starts_at)}</td>
                  <td className="px-3 py-2 text-xs tabular-nums">{fmt(w.ends_at)}</td>
                  <td className="max-w-64 px-3 py-2">
                    <div className="truncate" title={safeText(w.comment)}>
                      {safeText(w.comment)}
                    </div>
                  </td>
                  <td className="px-3 py-2 text-right">
                    {over ? (
                      <span className="text-xs text-muted-foreground">{t("maintenance.over")}</span>
                    ) : (
                      canManage && (
                        <Button type="button" variant="outline" size="sm" disabled={end.isPending} aria-label={t("maintenance.endNamed", { name: safeText(w.group_name) })} onClick={() => void stop(w)}>
                          {t("maintenance.end")}
                        </Button>
                      )
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {windows.isPending && <p className="p-4 text-sm text-muted-foreground">{t("events.loading")}</p>}
        {windows.data?.length === 0 && <p className="p-4 text-sm text-muted-foreground">{t("maintenance.empty")}</p>}
      </div>
    </section>
  );
}

/* datetime-local value (local time, minute precision) for a timestamp */
function localInput(ms: number): string {
  const d = new Date(ms - new Date(ms).getTimezoneOffset() * 60_000);
  return d.toISOString().slice(0, 16);
}

function WindowForm({ groups }: { groups?: components["schemas"]["Group"][] }) {
  const { t } = useTranslation();
  const create = useCreateWindow();
  const [groupId, setGroupId] = useState("");
  const [starts, setStarts] = useState(() => localInput(Date.now()));
  const [ends, setEnds] = useState(() => localInput(Date.now() + 3_600_000));
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | undefined>();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    const g = Number(groupId);
    if (!Number.isInteger(g) || g <= 0) return setError(t("templates.err.group"));
    const s = Date.parse(starts);
    const en = Date.parse(ends);
    const bad = checkWindow(s, en, Date.now());
    if (bad) return setError(t(`maintenance.err.${bad}`));
    if ([...comment].length > MAX_COMMENT) return setError(t("maintenance.err.comment", { max: MAX_COMMENT }));
    try {
      await create.mutateAsync({ group_id: g, starts_at: new Date(s).toISOString(), ends_at: new Date(en).toISOString(), comment: comment || undefined });
      setComment("");
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      setError(errText(t, err));
    }
  };

  return (
    <form onSubmit={(e) => void submit(e)} noValidate aria-label={t("maintenance.add")} className="grid gap-4 rounded-md border p-4">
      <h2 className="text-sm font-semibold">{t("maintenance.add")}</h2>
      <div className="grid gap-4 sm:grid-cols-2">
        <GroupField id="mw-group" label={t("maintenance.col.group")} value={groupId} onChange={setGroupId} groups={groups} />
        <div className="grid gap-1.5">
          <Label htmlFor="mw-comment">{t("maintenance.col.comment")}</Label>
          <Input id="mw-comment" value={comment} autoComplete="off" onChange={(e) => setComment(e.target.value)} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="mw-starts">{t("maintenance.col.starts")}</Label>
          <Input id="mw-starts" type="datetime-local" value={starts} onChange={(e) => setStarts(e.target.value)} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="mw-ends">{t("maintenance.col.ends")}</Label>
          <Input id="mw-ends" type="datetime-local" value={ends} onChange={(e) => setEnds(e.target.value)} />
        </div>
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div>
        <Button type="submit" disabled={create.isPending}>
          {t("maintenance.create")}
        </Button>
      </div>
    </form>
  );
}
