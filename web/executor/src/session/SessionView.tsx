import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { z } from "zod";
import { Button } from "@nms/shared/ui/button";
import { sessionPost, type Poster, type Result } from "../client";
import type { Message } from "../errors";
import { closedAnswer, diffAnswer, oneDiffAnswer, openedAnswer, sessionGone, sessionMessage, type DeviceDiff, type Opened, type RolledBack } from "./api";
import { Alert, Dialog } from "./Dialog";
import { DeviceTerminal, type Flow } from "./DeviceTerminal";
import { DiffView } from "./DiffView";
import { FormPanel } from "./FormPanel";
import type { SocketFactory } from "./socket";
import { EndDialog, ExtendDialog, RollbackDialog, SaveDialog } from "./SessionDialogs";

const LINE_NAMES: Record<string, string> = { mes6: "MES 6.x", mes10: "MES 10.x", esr: "ESR" };
export const lineName = (l: string) => LINE_NAMES[l] ?? l;

/* mm:ss (or h:mm:ss) of a non-negative number of seconds */
export function clock(sec: number): string {
  const s = Math.max(0, Math.floor(sec));
  const h = Math.floor(s / 3600);
  const mm = String(Math.floor((s % 3600) / 60)).padStart(h > 0 ? 2 : 1, "0");
  const ss = String(s % 60).padStart(2, "0");
  return h > 0 ? `${h}:${mm}:${ss}` : `${mm}:${ss}`;
}

/* ESR: a commit waits for its confirm; the device reverts it itself when the timer ends (no confirm within 15 s of it). */
function EsrBanner({ dev, secs, busy, onConfirm }: { dev: number; secs: number; busy: boolean; onConfirm: (dev: number) => void }) {
  const { t } = useTranslation();
  return (
    <div role="alert" data-testid={`esr-banner-${dev}`}
      className="flex flex-wrap items-center gap-3 rounded-lg border border-amber-400/70 bg-amber-50 px-4 py-2.5 text-sm text-amber-950 dark:border-amber-500/40 dark:bg-amber-950/50 dark:text-amber-100">
      <span aria-hidden className="size-2.5 shrink-0 animate-pulse rounded-full bg-amber-500" />
      <span className="flex-1 font-medium">
        {secs > 0 ? t("executor.session.esr.pending", { id: dev, n: Math.ceil(secs) }) : t("executor.session.esr.expired", { id: dev })}
      </span>
      {secs > 15 && (
        <Button type="button" size="sm" disabled={busy} onClick={() => onConfirm(dev)}>
          {t("executor.session.esr.confirm")}
        </Button>
      )}
    </div>
  );
}

type DialogState =
  | { kind: "diff"; diffs: DeviceDiff[] }
  | { kind: "save"; diff: DeviceDiff }
  | { kind: "rollback" }
  | { kind: "extend" }
  | { kind: "end" }
  | null;

export type Ended = { reason: "closed" | "gone"; rolledBack?: boolean };

type Props = {
  poster: Poster;
  opened: Opened;
  token: string;
  compact: boolean;
  onExpand: () => void;
  onUpdate: (o: Opened) => void;
  onEnded: (e: Ended) => void;
  now?: () => number;
  open?: SocketFactory;
};

/*
 * The open change session (FR-CHG-7): the indicator (timer, idle, devices, Diff / Сохранить / Откатить / Завершить),
 * the ESR banner of an unconfirmed commit with its countdown, one terminal tab per device and the forms. In the panel's
 * compact dock only the indicator bar shows; the terminals stay connected underneath.
 */
export function SessionView({ poster, opened, token, compact, onExpand, onUpdate, onEnded, now = Date.now, open }: Props) {
  const { t } = useTranslation();
  const id = opened.session_id;
  const [active, setActive] = useState(opened.devices[0].device_id);
  const [dialog, setDialog] = useState<DialogState>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [dialogMsg, setDialogMsg] = useState<Message | null>(null);
  const [pending, setPending] = useState<Record<number, string>>({});
  const [side, setSide] = useState(true);
  const [tick, setTick] = useState(now());
  const [last, setLast] = useState(now());
  const inFlight = useRef(false);
  useEffect(() => {
    const h = window.setInterval(() => setTick(now()), 1000);
    return () => window.clearInterval(h);
  }, [now]);

  const touch = useCallback(() => setLast(now()), [now]);
  const gone = useCallback(() => onEnded({ reason: "gone" }), [onEnded]);

  /* every diff the executor returns says whether an ESR commit waits for its confirm */
  const seeDiff = useCallback((d: DeviceDiff) => {
    setPending((p) => {
      const n = { ...p };
      if (d.commit_pending_until) n[d.device_id] = d.commit_pending_until;
      else delete n[d.device_id];
      return n;
    });
  }, []);

  /* one session action at a time, with the bearer token; a gone session ends the screen */
  const act = useCallback(
    async <T,>(op: string, body: Record<string, unknown>, schema: z.ZodType<T>): Promise<Result<T>> => {
      if (inFlight.current) return { ok: false, failure: { kind: "local", code: "busy" } };
      inFlight.current = true;
      setBusy(true);
      try {
        const r = await sessionPost(`/x/sessions/${id}/${op}`, token, body, schema);
        setLast(now());
        if (!r.ok && sessionGone(r.failure)) gone();
        return r;
      } finally {
        inFlight.current = false;
        setBusy(false);
      }
    },
    [id, token, now, gone],
  );

  const diff = async () => {
    setMsg(null);
    const r = await act("diff", {}, diffAnswer);
    if (!r.ok) return setMsg(sessionMessage(r.failure));
    r.value.result.forEach(seeDiff);
    setDialog({ kind: "diff", diffs: r.value.result });
  };

  const openSave = async (device: number) => {
    setMsg(null);
    setDialogMsg(null);
    const r = await act("diff", {}, diffAnswer);
    if (!r.ok) return setMsg(sessionMessage(r.failure));
    r.value.result.forEach(seeDiff);
    const d = r.value.result.find((x) => x.device_id === device);
    if (d) setDialog({ kind: "save", diff: d });
  };

  const save = async (d: DeviceDiff) => {
    setDialogMsg(null);
    const r = await act("save", { device_id: d.device_id, sha256: d.sha256 }, oneDiffAnswer);
    if (!r.ok) return setDialogMsg(sessionMessage(r.failure));
    seeDiff(r.value.result);
    setDialog(null);
    setMsg({ key: d.line === "esr" ? "executor.session.save.doneEsr" : "executor.session.save.done", params: { id: d.device_id } });
  };

  const commit = async (device: number) => {
    setMsg(null);
    const r = await act("commit", { device_id: device }, oneDiffAnswer);
    if (!r.ok) return setMsg(sessionMessage(r.failure));
    seeDiff(r.value.result);
  };

  const extend = async (code: string) => {
    setDialogMsg(null);
    setBusy(true);
    const r = await poster.post(`/x/sessions/${id}/extend`, { totp: code }, openedAnswer);
    setBusy(false);
    if (!r.ok) {
      if (sessionGone(r.failure)) return gone();
      return setDialogMsg(sessionMessage(r.failure));
    }
    onUpdate(r.value.result);
    setLast(now());
    setDialog(null);
  };

  const end = async () => {
    setDialogMsg(null);
    const r = await act("close", {}, closedAnswer);
    if (r.ok) return onEnded({ reason: "closed" });
    if (!sessionGone(r.failure)) setDialogMsg(sessionMessage(r.failure));
  };

  const onFlow = useCallback(
    (f: Flow) => {
      if (f.diff) seeDiff(f.diff);
      if (f.kind === "save") {
        if (f.diff) setDialog({ kind: "save", diff: f.diff });
      } else if (f.kind === "rollback") setDialog({ kind: "rollback" });
    },
    [seeDiff],
  );

  const rolledBack = (r: RolledBack[]) => {
    setPending({});
    if (r.every((d) => !d.error)) setMsg({ key: "executor.session.rollback.done" });
  };

  const left = (Date.parse(opened.expires) - tick) / 1000;
  const idleLeft = opened.idle_seconds - (tick - last) / 1000;
  const activeDev = opened.devices.find((d) => d.device_id === active) ?? opened.devices[0];
  const esr = activeDev.line === "esr";
  const banners = Object.entries(pending).map(([dev, until]) => ({ dev: Number(dev), secs: (Date.parse(until) - tick) / 1000 }));
  const secsOf = (dev: number) => banners.find((b) => b.dev === dev)?.secs;

  /* a button of the compact strip first asks the panel to show the frame at full size */
  const run = (fromCompact: boolean, what: "diff" | "save" | "rollback" | "end", device = active) => {
    if (fromCompact) onExpand();
    if (what === "diff") void diff();
    else if (what === "save") void openSave(device);
    else setDialog({ kind: what });
  };
  const buttons = (fromCompact: boolean) => (
    <div className={`flex items-center gap-2 ${fromCompact ? "" : "flex-wrap"}`}>
      <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => run(fromCompact, "diff")}>
        {t("executor.session.actions.diff")}
      </Button>
      <Button type="button" size="sm" disabled={busy} onClick={() => run(fromCompact, "save")} data-testid="save-button">
        {t(esr ? "executor.session.actions.confirm" : "executor.session.actions.save")}
      </Button>
      <Button type="button" variant="outline" size="sm" className="border-destructive/50 text-destructive hover:bg-destructive/10" disabled={busy}
        onClick={() => run(fromCompact, "rollback")}>
        {t("executor.session.actions.rollback")}
      </Button>
      <Button type="button" variant="outline" size="sm" disabled={busy} onClick={() => run(fromCompact, "end")}>
        {t("executor.session.actions.end")}
      </Button>
    </div>
  );

  const timer = (
    <div className="flex items-center gap-4 text-sm tabular-nums">
      <span data-testid="timer" className={left < 300 ? "font-semibold text-destructive" : "font-semibold"}>
        {t("executor.session.left", { time: clock(left) })}
      </span>
      <span data-testid="idle" className={idleLeft < 120 ? "text-amber-700 dark:text-amber-300" : "text-muted-foreground"}>
        {t("executor.session.idle", { time: clock(idleLeft) })}
      </span>
    </div>
  );

  const confirmEsr = (dev: number) => run(false, "save", dev);
  const banner = banners.map((b) => <EsrBanner key={b.dev} dev={b.dev} secs={b.secs} busy={busy} onConfirm={confirmEsr} />);

  return (
    <>
      {compact && (
        <div className="flex h-full items-center gap-4 overflow-hidden px-4 whitespace-nowrap" data-testid="compact-bar">
          <span className="flex items-center gap-2 text-sm font-semibold">
            <span aria-hidden className="size-2 rounded-full bg-emerald-500" />
            {t("executor.session.title")}
          </span>
          <span className={`text-sm font-semibold tabular-nums ${left < 300 ? "text-destructive" : ""}`}>{t("executor.session.left", { time: clock(left) })}</span>
          <span className={`text-sm tabular-nums ${idleLeft < 120 ? "text-amber-700 dark:text-amber-300" : "text-muted-foreground"}`}>
            {t("executor.session.idleShort", { time: clock(idleLeft) })}
          </span>
          <span className="min-w-0 truncate text-sm text-muted-foreground">{opened.devices.map((d) => t("executor.session.deviceShort", { id: d.device_id })).join(", ")}</span>
          {banners.length > 0 && (
            <span className="min-w-0 truncate text-sm font-medium text-amber-700 dark:text-amber-300">
              {t("executor.session.esr.compact", { n: Math.max(0, Math.ceil(Math.min(...banners.map((b) => b.secs)))) })}
            </span>
          )}
          <div className="ml-auto shrink-0">{buttons(true)}</div>
        </div>
      )}
      <div className={compact ? "hidden" : "flex h-full min-h-0 flex-col gap-3"} data-testid="session-view">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border bg-card px-4 py-2.5">
          <div className="min-w-0">
            <p className="text-sm font-semibold">{t("executor.session.title")}</p>
            <p className="font-mono text-xs text-muted-foreground" data-testid="session-id">
              {id}
            </p>
          </div>
          {timer}
          <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setDialog({ kind: "extend" })}>
            {t("executor.session.actions.extend")}
          </Button>
          <div className="ml-auto">{buttons(false)}</div>
        </div>
        {banner}
        {msg && <Alert tone={msg.key.startsWith("executor.session.save.done") || msg.key === "executor.session.rollback.done" ? "info" : "error"}>{t(msg.key, msg.params)}</Alert>}
        <div className="flex min-h-0 flex-1 gap-3">
          <div className="flex min-w-0 flex-1 flex-col rounded-lg border bg-card">
            <div role="tablist" aria-label={t("executor.session.devices")} className="flex items-end gap-1 overflow-x-auto border-b px-2 pt-1.5">
              {opened.devices.map((d) => (
                <button key={d.device_id} type="button" role="tab" aria-selected={d.device_id === active} data-testid={`tab-${d.device_id}`}
                  className={`-mb-px flex shrink-0 items-center gap-2 border-b-2 px-3 py-2 text-sm whitespace-nowrap ${d.device_id === active ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
                  onClick={() => setActive(d.device_id)}>
                  {t("executor.session.deviceLabel", { id: d.device_id })}
                  <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] font-medium text-muted-foreground">{lineName(d.line)}</span>
                  {pending[d.device_id] && <span aria-hidden className="size-1.5 rounded-full bg-amber-500" />}
                </button>
              ))}
              <div className="ml-auto flex items-center gap-2 pb-1.5">
                {esr && !pending[active] && (
                  <Button type="button" variant="outline" size="xs" disabled={busy} onClick={() => void commit(active)}>
                    {t("executor.session.actions.commit")}
                  </Button>
                )}
                <Button type="button" variant="ghost" size="xs" onClick={() => setSide((v) => !v)} aria-pressed={side}>
                  {t("executor.session.form.toggle")}
                </Button>
              </div>
            </div>
            <div className="min-h-0 flex-1 p-2">
              {opened.devices.map((d) => (
                <div key={d.device_id} className={d.device_id === active ? "h-full" : "hidden"} role="tabpanel">
                  <DeviceTerminal poster={poster} session={id} token={token} device={d.device_id} active={!compact && d.device_id === active}
                    onActivity={touch} onFlow={onFlow} onGone={gone} open={open} />
                </div>
              ))}
            </div>
            <p className="border-t px-3 py-1.5 text-xs text-muted-foreground">{t("executor.session.term.hint")}</p>
          </div>
          {side && (
            <aside className="w-80 shrink-0 space-y-3 overflow-y-auto rounded-lg border bg-card p-4" aria-label={t("executor.session.form.title")}>
              <p className="text-sm font-semibold">{t("executor.session.form.title", { id: active })}</p>
              <p className="text-xs text-muted-foreground">{t("executor.session.form.explain")}</p>
              <FormPanel key={active} device={active} act={act} busy={busy} onApplied={seeDiff} />
            </aside>
          )}
        </div>
      </div>
      {dialog?.kind === "diff" && (
        <Dialog title={t("executor.session.diff.title")} wide onClose={() => setDialog(null)} testId="diff-dialog">
          {dialog.diffs.map((d) => (
            <DiffView key={d.device_id} diff={d} title={`${t("executor.session.deviceLabel", { id: d.device_id })} · ${lineName(d.line)}`} />
          ))}
          <Button type="button" variant="outline" onClick={() => setDialog(null)}>
            {t("executor.session.close")}
          </Button>
        </Dialog>
      )}
      {dialog?.kind === "save" && (
        <SaveDialog diff={dialog.diff} esr={dialog.diff.line === "esr"} busy={busy} msg={dialogMsg} secondsLeft={secsOf(dialog.diff.device_id)}
          onSave={() => void save(dialog.diff)} onClose={() => setDialog(null)} />
      )}
      {dialog?.kind === "rollback" && <RollbackDialog poster={poster} session={id} onClose={() => setDialog(null)} onDone={rolledBack} />}
      {dialog?.kind === "extend" && <ExtendDialog busy={busy} msg={dialogMsg} onExtend={(c) => void extend(c)} onClose={() => setDialog(null)} />}
      {dialog?.kind === "end" && (
        <EndDialog busy={busy} msg={dialogMsg} pendingEsr={banners.some((b) => b.secs > 0)} onEnd={() => void end()} onClose={() => setDialog(null)} />
      )}
    </>
  );
}
