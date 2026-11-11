import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Message } from "../errors";
import { GateNotice, useConfirmGate } from "../frame";
import { Alert, Dialog } from "../session/Dialog";
import { interruptedVersions, messageOf, okAnswer, op, stages, statesFromEvents, workspaceGone, type Detail } from "./api";
import { deviceTone, useCode } from "./parts";

/* "line 3: not_safe", "commit: device_failed" -> the text of the code with where it happened */
export function useRunError() {
  const { t } = useTranslation();
  const code = useCode();
  return (e: string) => {
    const m = /^(line (\d+)|commit|confirm|save): (.+)$/.exec(e);
    if (!m) return code("executor.changesets.runError", e);
    const what = code("executor.changesets.runError", m[3]);
    return m[2] ? t("executor.changesets.runAt.line", { n: m[2], what }) : t(`executor.changesets.runAt.${m[1]}`, { what });
  };
}

/*
 * A run (Task 5.5): the canary, then the batches, each device's state, lines sent, error and its recording (a run's
 * device is a service session). The states come from this process's run, else from the stored events (a restart).
 * "Стоп" stops sending and rolls back every device that got a line (D6); the dialog says so. An interrupted run says
 * honestly that nothing was rolled back and names the pre_session versions a restore changeset brings back.
 */
export function ProgressView({ token, detail, onChanged, onGone, onRecordings, onRestore }: {
  token: string;
  detail: Detail;
  onChanged: () => void;
  onGone: () => void;
  onRecordings: (session: string, device: number) => void;
  onRestore: (items: { device: number; version: number }[]) => void;
}) {
  const { t } = useTranslation();
  const runError = useRunError();
  const [stop, setStop] = useState(false);
  const run = detail.run;
  const fromEvents = statesFromEvents(detail.events, detail.revision);
  const live = new Map((run?.devices ?? []).map((d) => [d.device_id, d]));
  const state = (id: number) => {
    const l = live.get(id);
    if (l) return { state: l.state, sent: l.lines_sent, error: l.error, session: l.session_id };
    const e = fromEvents.get(id);
    /* without the run's memory a device with no event is unknown after a restart, untouched otherwise */
    const none = detail.status === "running" ? "pending" : detail.status === "interrupted" ? "unknown" : "not_started";
    return { state: e?.state ?? none, sent: undefined, error: e?.error, session: e?.session };
  };
  const running = detail.status === "running" && (!run || !run.result);
  const phase = run?.phase ?? "";
  const batchN = /^batch (\d+)$/.exec(phase)?.[1];
  const versions = detail.status === "interrupted" ? interruptedVersions(detail) : {};
  const failed = run?.failed_device_id ?? [...detail.events].reverse().find((e) => e.revision === detail.revision && e.kind === detail.status)?.device_id;
  const reason = run?.reason ?? (([...detail.events].reverse().find((e) => e.revision === detail.revision && e.kind === detail.status)?.payload ?? {}) as { reason?: string }).reason;

  return (
    <div className="space-y-3" data-testid="cs-progress">
      <div className="flex flex-wrap items-center gap-3">
        {running && (
          <p className="text-sm font-medium" data-testid="run-phase">
            <span className="mr-2 inline-block size-2 animate-pulse rounded-full bg-blue-500 align-middle" />
            {batchN ? t("executor.changesets.phase.batch", { n: batchN }) : t(`executor.changesets.phase.${phase || "starting"}`, { defaultValue: phase })}
          </p>
        )}
        {running && (
          <Button type="button" variant="destructive" size="sm" className="ml-auto" onClick={() => setStop(true)} data-testid="cs-stop">
            {t("executor.changesets.stop.button")}
          </Button>
        )}
      </div>
      {detail.status === "done" && <Alert tone="info" testId="run-outcome">{t("executor.changesets.outcome.done")}</Alert>}
      {detail.status === "rolled_back" && (
        <Alert tone="warn" testId="run-outcome">
          {t(reason === "stopped" ? "executor.changesets.outcome.stopped" : "executor.changesets.outcome.rolled_back", { id: failed ?? "-", reason: reason ? runError(reason) : "-" })}
        </Alert>
      )}
      {detail.status === "rollback_failed" && <Alert testId="run-outcome">{t("executor.changesets.outcome.rollback_failed", { id: failed ?? "-", reason: reason ? runError(reason) : "-" })}</Alert>}
      {detail.status === "interrupted" && (
        <div className="space-y-2 rounded-lg border border-destructive/50 bg-destructive/5 px-4 py-3 text-sm" data-testid="run-outcome">
          <p className="font-semibold text-destructive">{t("executor.changesets.outcome.interruptedTitle")}</p>
          <p>{t("executor.changesets.outcome.interrupted")}</p>
          <ul className="font-mono text-xs">
            {detail.content.device_ids.map((d) => (
              <li key={d}>{t("executor.changesets.outcome.preVersion", { id: d, version: versions[String(d)] ?? t("executor.changesets.outcome.noVersion") })}</li>
            ))}
          </ul>
          {Object.keys(versions).length > 0 && (
            <Button type="button" size="sm" variant="outline" data-testid="cs-restore-interrupted"
              onClick={() => onRestore(Object.entries(versions).map(([d, v]) => ({ device: Number(d), version: v })))}>
              {t("executor.changesets.outcome.restore")}
            </Button>
          )}
        </div>
      )}
      <ol className="space-y-2">
        {stages(detail.content.device_ids, detail.content.batch_size).map((ids, i) => {
          const current = running && ((i === 0 && phase === "canary") || (batchN !== undefined && Number(batchN) === i));
          return (
            <li key={i} className={`rounded-lg border p-2.5 ${current ? "border-blue-500/60 bg-blue-500/5" : ""}`} data-testid={`stage-${i}`}>
              <p className="mb-2 text-xs font-semibold text-muted-foreground uppercase">
                {i === 0 ? t("executor.changesets.canary") : t("executor.changesets.phase.batch", { n: i })}
                {i === 0 && detail.content.settle_s > 0 && <span className="ml-2 font-normal normal-case">{t("executor.changesets.settleThen", { s: detail.content.settle_s })}</span>}
              </p>
              <div className="flex flex-wrap gap-2">
                {ids.map((id) => {
                  const s = state(id);
                  return (
                    <div key={id} className={`min-w-44 rounded-md border px-2.5 py-1.5 text-[13px] ${deviceTone(s.state)}`} data-testid={`run-${id}`} data-state={s.state}>
                      <div className="flex items-baseline gap-2">
                        <span className="font-semibold">{t("executor.changesets.deviceShort", { id })}</span>
                        <span className="text-xs">{t(`executor.changesets.devState.${s.state}`, { defaultValue: s.state })}</span>
                      </div>
                      {s.sent !== undefined && s.sent > 0 && <p className="text-xs opacity-80">{t("executor.changesets.linesSent", { count: s.sent })}</p>}
                      {s.error && <p className="text-xs font-medium break-all">{runError(s.error)}</p>}
                      {s.session && (
                        <button type="button" className="text-xs underline underline-offset-2 opacity-80 hover:opacity-100" onClick={() => onRecordings(s.session as string, id)}>
                          {t("executor.changesets.recording")}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
            </li>
          );
        })}
      </ol>
      {stop && <StopDialog token={token} id={detail.changeset_id} onClose={() => setStop(false)} onGone={onGone} onStopped={() => {
        setStop(false);
        onChanged();
      }} />}
    </div>
  );
}

/* "Стоп" (gated like a confirm): the executor sends no further line and rolls back every device that got one. */
function StopDialog({ token, id, onClose, onStopped, onGone }: { token: string; id: string; onClose: () => void; onStopped: () => void; onGone: () => void }) {
  const { t } = useTranslation();
  const { ref: gateRef, ...gate } = useConfirmGate();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const go = async () => {
    if (!gate.visibleNow()) return;
    setMsg(null);
    setBusy(true);
    const r = await op(token, "stop", { changeset_id: id }, okAnswer);
    setBusy(false);
    if (r.ok) return onStopped();
    if (workspaceGone(r.failure)) return onGone();
    setMsg(messageOf(r.failure));
  };
  return (
    <Dialog title={t("executor.changesets.stop.title")} tone="danger" busy={busy} onClose={onClose} testId="stop-dialog">
      <div className="space-y-2">
        <div ref={gateRef} className="space-y-3">
          <p>{t("executor.changesets.stop.explain")}</p>
          <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
            <li>{t("executor.changesets.stop.rule1")}</li>
            <li>{t("executor.changesets.stop.rule2")}</li>
            <li>{t("executor.changesets.stop.rule3")}</li>
          </ul>
          <div className="flex gap-2">
            <Button type="button" variant="destructive" disabled={busy || !gate.unobscured} onClick={() => void go()} data-testid="cs-stop-confirm">
              {t("executor.changesets.stop.confirm")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {t("executor.confirm.cancel")}
            </Button>
          </div>
        </div>
        <GateNotice gate={gate} />
        {msg && <Alert>{t(msg.key, msg.params)}</Alert>}
      </div>
    </Dialog>
  );
}
