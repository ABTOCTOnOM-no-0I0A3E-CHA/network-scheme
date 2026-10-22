import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errText } from "@/features/common/errText";
import { StepUpCancelled } from "@/features/common/stepup";
import { useDevices } from "@/features/devices/api";
import { SeverityBadge } from "@/features/events/EventFeed";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { SEVERITIES, useAckProblem, useProblem, useProblems, validateComment, type EventSeverity, type Problem, type ProblemFilter } from "./api";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
const STATES = ["problem", "acknowledged", "resolved"] as const;

type Filters = { state: "" | Problem["state"]; severityMin: "" | EventSeverity; suppressed: "" | "true" | "false"; deviceId: string };
const INITIAL: Filters = { state: "", severityMin: "", suppressed: "", deviceId: "" };

function toQuery(f: Filters, fixedDeviceId?: number): ProblemFilter {
  return {
    state: f.state || undefined,
    severityMin: f.severityMin || undefined,
    suppressed: f.suppressed || undefined,
    deviceId: fixedDeviceId ?? (f.deviceId ? Number(f.deviceId) : undefined),
  };
}

/* a comment keeps its line breaks and tabs; every other control character is replaced */
function commentText(c: string): string {
  return c
    .split("\n")
    .map((l) => safeText(l.replaceAll("\t", "  ")))
    .join("\n");
}

/** Acknowledgement history of a problem plus the comment form (hidden for a resolved problem or without problems.ack). */
function Details({ p, canAck }: { p: Problem; canAck: boolean }) {
  const { t, i18n } = useTranslation();
  const detail = useProblem(p.id);
  const ack = useAckProblem();
  const [comment, setComment] = useState("");
  const [error, setError] = useState<string | undefined>();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    if (!validateComment(comment)) return setError(t("problems.ack.invalid"));
    try {
      await ack.mutateAsync({ id: p.id, comment });
      setComment("");
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      setError(errText(t, err));
    }
  };

  return (
    <div className="mt-2 grid gap-3 rounded-md bg-muted/30 px-3 py-3" data-testid="problem-details">
      {p.last_value && (
        <p className="text-xs break-words">
          <span className="text-muted-foreground">{t("problems.lastValue")}:</span> <span className="font-mono">{safeText(p.last_value)}</span>
        </p>
      )}
      {p.resolve_reason && (
        <p className="text-xs text-muted-foreground">
          {t("problems.resolveReason")}: {t(`problems.reason.${p.resolve_reason}`, { defaultValue: safeText(p.resolve_reason) })}
        </p>
      )}
      <div>
        <h3 className="text-xs font-semibold">{t("problems.acks")}</h3>
        {detail.isPending && <p className="text-xs text-muted-foreground">{t("events.loading")}</p>}
        {detail.error && (
          <p role="alert" className="text-xs text-destructive">
            {errText(t, detail.error)}
          </p>
        )}
        {detail.data && detail.data.acks.length === 0 && <p className="text-xs text-muted-foreground">{t("problems.noAcks")}</p>}
        <ul className="grid gap-1">
          {detail.data?.acks.map((a) => (
            <li key={a.id} className="text-xs break-words">
              <span className="font-medium">{safeText(a.username) || `#${a.user_id}`}</span> <time dateTime={a.at}>{new Date(a.at).toLocaleString(i18n.language)}</time>:{" "}
              <span className="whitespace-pre-wrap">{commentText(a.comment)}</span>
            </li>
          ))}
        </ul>
      </div>
      {canAck && p.state !== "resolved" && (
        <form onSubmit={(e) => void submit(e)} noValidate className="grid gap-2" aria-label={t("problems.ack.title")}>
          <label className="grid gap-1 text-xs">
            {t("problems.ack.comment")}
            <textarea
              className="min-h-16 rounded-md border border-input bg-transparent px-3 py-2 text-sm dark:bg-input/30"
              maxLength={1000}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
            />
          </label>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <div>
            <Button type="submit" size="sm" disabled={ack.isPending}>
              {t("problems.ack.submit")}
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}

type Props = {
  /** Fixes the device (Problems tab of a device card): the device filter and column are hidden. */
  deviceId?: number;
  /** UI hint; the API decides. */
  canAck: boolean;
};

/** Problem list with server-side filters (state, severity, suppressed, device). All names and values derive from devices and are rendered as text. */
export function ProblemList({ deviceId, canAck }: Props) {
  const { t, i18n } = useTranslation();
  const [filters, setFilters] = useState<Filters>(INITIAL);
  const [open, setOpen] = useState<Set<number>>(new Set());
  const devices = useDevices();
  const list = useProblems(toQuery(filters, deviceId));
  const items = list.data?.pages.flatMap((p) => p.items) ?? [];
  const patch = (p: Partial<Filters>) => setFilters((f) => ({ ...f, ...p }));
  const toggle = (id: number) =>
    setOpen((s) => {
      const n = new Set(s);
      if (!n.delete(id)) n.add(id);
      return n;
    });

  return (
    <section className="grid gap-4">
      <div className="flex flex-wrap gap-2">
        <select aria-label={t("problems.filter.state")} className={SELECT_CLASS} value={filters.state} onChange={(e) => patch({ state: e.target.value as Filters["state"] })}>
          <option value="">{t("problems.filter.anyState")}</option>
          {STATES.map((s) => (
            <option key={s} value={s}>
              {t(`problems.state.${s}`)}
            </option>
          ))}
        </select>
        <select aria-label={t("problems.filter.severity")} className={SELECT_CLASS} value={filters.severityMin} onChange={(e) => patch({ severityMin: e.target.value as Filters["severityMin"] })}>
          <option value="">{t("events.filter.anySeverity")}</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {t("events.filter.atLeast", { severity: t(`events.severity.${s}`) })}
            </option>
          ))}
        </select>
        <select aria-label={t("problems.filter.suppressed")} className={SELECT_CLASS} value={filters.suppressed} onChange={(e) => patch({ suppressed: e.target.value as Filters["suppressed"] })}>
          <option value="">{t("problems.filter.suppressedAll")}</option>
          <option value="true">{t("problems.filter.suppressedOnly")}</option>
          <option value="false">{t("problems.filter.suppressedHide")}</option>
        </select>
        {deviceId === undefined && (
          <select aria-label={t("events.filter.device")} className={SELECT_CLASS} value={filters.deviceId} onChange={(e) => patch({ deviceId: e.target.value })}>
            <option value="">{t("events.filter.allDevices")}</option>
            {devices.data?.map((d) => (
              <option key={d.id} value={d.id}>
                {safeText(d.name)}
              </option>
            ))}
          </select>
        )}
      </div>
      {list.error && (
        <p role="alert" className="text-sm text-destructive">
          {errText(t, list.error)}
        </p>
      )}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[48rem] text-sm" aria-label={t("problems.table")}>
          <thead className="bg-muted/50 text-left text-xs font-medium text-muted-foreground">
            <tr>
              <th className="px-3 py-2">{t("events.col.severity")}</th>
              <th className="px-3 py-2">{t("problems.col.state")}</th>
              <th className="px-3 py-2">{t("problems.col.name")}</th>
              {deviceId === undefined && <th className="px-3 py-2">{t("events.col.device")}</th>}
              <th className="px-3 py-2">{t("problems.col.opened")}</th>
              <th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody>
            {items.map((p) => {
              const name = safeText(p.name) + (p.object ? ` (${safeText(p.object)})` : "");
              const expanded = open.has(p.id);
              return (
                <tr key={p.id} className="border-t align-top" data-problem-id={p.id}>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={p.severity} />
                  </td>
                  <td className="px-3 py-2">
                    <span className={cn("text-xs", p.state === "resolved" && "text-muted-foreground")}>{t(`problems.state.${p.state}`)}</span>
                    {p.suppressed && <span className="ml-1 rounded bg-muted px-1.5 py-0.5 text-[10px] text-muted-foreground">{t("problems.suppressed")}</span>}
                  </td>
                  <td className="max-w-80 min-w-0 px-3 py-2">
                    <div className="truncate" title={name}>
                      {name}
                    </div>
                    {expanded && <Details p={p} canAck={canAck} />}
                  </td>
                  {deviceId === undefined && (
                    <td className="max-w-48 px-3 py-2">
                      <div className="truncate" title={safeText(p.device_name)}>
                        {safeText(p.device_name) || "-"}
                      </div>
                    </td>
                  )}
                  <td className="px-3 py-2 text-xs tabular-nums">
                    <time dateTime={p.opened_at}>{new Date(p.opened_at).toLocaleString(i18n.language)}</time>
                  </td>
                  <td className="px-3 py-2">
                    <Button type="button" variant="outline" size="sm" aria-expanded={expanded} aria-label={t("problems.details", { name })} onClick={() => toggle(p.id)}>
                      {t(canAck && p.state !== "resolved" ? "problems.ack.open" : "problems.open")}
                    </Button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {list.isPending && <p className="p-4 text-sm text-muted-foreground">{t("events.loading")}</p>}
        {!list.isPending && !list.error && items.length === 0 && <p className="p-4 text-sm text-muted-foreground">{t("problems.empty")}</p>}
      </div>
      <div className="flex items-center gap-3">
        <p className="text-xs text-muted-foreground">{t("events.count", { count: items.length })}</p>
        {list.hasNextPage && (
          <Button type="button" variant="outline" size="sm" disabled={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()}>
            {t("events.loadMore")}
          </Button>
        )}
      </div>
    </section>
  );
}
