import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Poster } from "../client";
import type { Failure, Message } from "../errors";
import { GateNotice, useConfirmGate } from "../frame";
import { Alert, Dialog } from "../session/Dialog";
import { ApproveDialog } from "./ApproveDialog";
import { approvedUntil, detailAnswer, EDITABLE, messageOf, okAnswer, op, stages, startedAnswer, storedDryRun, workspaceGone, type Detail as D, type Workspace } from "./api";
import { DryRunView } from "./DryRunView";
import { FailureView } from "./Editor";
import { ProgressView, useRunError } from "./ProgressView";
import { section, StatusBadge, when } from "./parts";

/* How often a running dry-run or run is read again (op progress: no code, not audited). */
export const POLL_MS = 1500;
const RUN_STATES = ["running", "done", "rolled_back", "rollback_failed", "interrupted"];

/*
 * One changeset: what it changes (devices in the order of the run, the canary first; steps or versions), its dry-run,
 * its approval (the author's, then a second person's where the policy wants one), its run and its history. The first
 * read is audited (changeset.view); the polling while a dry-run or a run goes on is not.
 */
export function Detail({ poster, token, me, id, onBack, onEdit, onRestore, onGone, onRecordings }: {
  poster: Poster;
  token: string;
  me: Workspace;
  id: string;
  onBack: () => void;
  onEdit: (d: D) => void;
  onRestore: (items: { device: number; version: number }[]) => void;
  onGone: () => void;
  onRecordings: (session: string, device: number) => void;
}) {
  const { t } = useTranslation();
  const runError = useRunError();
  const [d, setD] = useState<D | null>(null);
  const [fail, setFail] = useState<{ msg: Message; failure?: Failure } | null>(null);
  const [busy, setBusy] = useState(false);
  const [approve, setApprove] = useState(false);
  const [discard, setDiscard] = useState(false);
  const [note, setNote] = useState<Message | null>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const read = useCallback(
    (name: "get" | "progress") =>
      op(token, name, { changeset_id: id }, detailAnswer).then((r) => {
        if (!alive.current) return;
        if (r.ok) return setD(r.value.result);
        if (workspaceGone(r.failure)) return onGone();
        setFail({ msg: messageOf(r.failure), failure: r.failure });
      }),
    [token, id, onGone],
  );
  useEffect(() => {
    void read("get");
  }, [read]);
  const polling = !!d && (d.dry_run?.running === true || (d.status === "running" && !d.run?.result));
  useEffect(() => {
    if (!polling) return;
    const h = window.setInterval(() => void read("progress"), POLL_MS);
    return () => window.clearInterval(h);
  }, [polling, read]);

  if (!d) {
    return (
      <div className="space-y-3">
        <Button type="button" variant="ghost" size="sm" onClick={onBack}>
          {t("executor.changesets.back")}
        </Button>
        {fail ? <FailureView f={fail} /> : <p className="text-sm text-muted-foreground">{t("executor.changesets.loading")}</p>}
      </div>
    );
  }

  const isAuthor = me.user_id === d.author_id;
  const editable = EDITABLE.includes(d.status);
  const dry = d.dry_run?.result?.revision === d.revision ? d.dry_run.result : undefined;
  const stored = dry ? undefined : storedDryRun(d);
  const until = d.status === "approved" ? approvedUntil(d) : undefined;

  const dryRun = async () => {
    setFail(null);
    setNote(null);
    setBusy(true);
    const r = await op(token, "dry-run", { changeset_id: d.changeset_id, revision: d.revision }, startedAnswer);
    setBusy(false);
    if (!r.ok) return workspaceGone(r.failure) ? onGone() : setFail({ msg: messageOf(r.failure), failure: r.failure });
    await read("progress");
  };

  return (
    <div className="space-y-4" data-testid="cs-detail">
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" variant="ghost" size="sm" onClick={onBack}>
          {t("executor.changesets.back")}
        </Button>
        <Button type="button" variant="ghost" size="sm" className="ml-auto" disabled={busy} onClick={() => void read("progress")}>
          {t("executor.changesets.refresh")}
        </Button>
      </div>

      <section className={section}>
        <div className="flex flex-wrap items-start gap-3">
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold break-words" data-testid="cs-title">
              {d.title}
            </h2>
            <p className="mt-0.5 font-mono text-xs text-muted-foreground" data-testid="cs-id">
              {d.changeset_id}
            </p>
          </div>
          <StatusBadge status={d.status} />
        </div>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-sm sm:grid-cols-4">
          <Fact k={t("executor.changesets.col.kind")} v={t(`executor.changesets.kind.${d.kind}`)} />
          <Fact k={t("executor.changesets.col.author")} v={`${d.author}${isAuthor ? ` (${t("executor.changesets.you")})` : ""}`} />
          <Fact k={t("executor.changesets.col.revision")} v={String(d.revision)} />
          <Fact k={t("executor.changesets.col.updated")} v={when(d.updated)} />
          <Fact k={t("executor.changesets.col.devices")} v={String(d.content.device_ids.length)} />
          <Fact k={t("executor.changesets.editor.batch")} v={String(d.content.batch_size)} />
          <Fact k={t("executor.changesets.editor.settle")} v={String(d.content.settle_s)} />
        </dl>

        <div className="grid gap-4 lg:grid-cols-[2fr_3fr]">
          <div>
            <p className="mb-1.5 text-xs font-semibold text-muted-foreground uppercase">{t("executor.changesets.order")}</p>
            <ol className="space-y-1 text-[13px]">
              {stages(d.content.device_ids, d.content.batch_size).map((ids, i) => (
                <li key={i} className="flex flex-wrap items-baseline gap-x-2">
                  <span className="w-20 shrink-0 text-xs text-muted-foreground">{i === 0 ? t("executor.changesets.canary") : t("executor.changesets.phase.batch", { n: i })}</span>
                  <span className="font-mono">{ids.map((x) => `#${x}`).join(", ")}</span>
                </li>
              ))}
            </ol>
          </div>
          <div>
            <p className="mb-1.5 text-xs font-semibold text-muted-foreground uppercase">{t(d.kind === "restore" ? "executor.changesets.versions" : "executor.changesets.steps")}</p>
            {d.kind === "restore" ? (
              <ul className="space-y-0.5 font-mono text-[13px]">
                {(d.content.restore ?? []).map((r) => (
                  <li key={r.device_id}>{t("executor.changesets.restoreItem", { id: r.device_id, version: r.version_id })}</li>
                ))}
              </ul>
            ) : (
              <pre className="max-h-64 overflow-auto rounded-md border bg-muted/30 px-3 py-2 font-mono text-[12.5px] leading-5" data-testid="cs-lines">
                {(d.content.steps ?? []).map((s, i) => (
                  <div key={i} className="break-all whitespace-pre-wrap">
                    <span className="mr-3 inline-block w-5 text-right text-muted-foreground select-none">{i + 1}</span>
                    {s.form ? t("executor.changesets.formStep", { kind: t(`executor.session.form.kinds.${s.form.kind}`, { defaultValue: s.form.kind }), args: [s.form.interface, s.form.description, s.form.vlan || "", s.form.name, s.form.kind === "interface-state" ? t(s.form.up ? "executor.session.form.up" : "executor.session.form.down") : ""].filter(Boolean).join(" ") }) : s.line}
                  </div>
                ))}
              </pre>
            )}
            {d.content.vars && Object.keys(d.content.vars).length > 0 && (
              <p className="mt-1 text-xs text-muted-foreground">{t("executor.changesets.hasVars", { count: Object.keys(d.content.vars).length })}</p>
            )}
          </div>
        </div>

        <div className={`flex flex-wrap gap-2 border-t pt-3 ${editable ? "" : "hidden"}`} data-testid="cs-actions">
          {editable && isAuthor && (
            <Button type="button" variant="outline" disabled={busy} onClick={() => onEdit(d)}>
              {t("executor.changesets.edit")}
            </Button>
          )}
          {editable && (
            <Button type="button" variant={d.status === "draft" || d.status === "dry_run_failed" ? "default" : "outline"} disabled={busy || d.dry_run?.running} onClick={() => void dryRun()} data-testid="cs-dry-run-button">
              {t(d.status === "draft" ? "executor.changesets.dryRun.start" : "executor.changesets.dryRun.again")}
            </Button>
          )}
          {d.status === "dry_run_ok" && isAuthor && (
            <Button type="button" disabled={busy} onClick={() => setApprove(true)} data-testid="cs-approve">
              {t("executor.changesets.approve.button")}
            </Button>
          )}
          {d.status === "approved" && !isAuthor && (
            <Button type="button" disabled={busy} onClick={() => setApprove(true)} data-testid="cs-approve-second">
              {t("executor.changesets.approve.buttonSecond")}
            </Button>
          )}
          {editable && isAuthor && (
            <Button type="button" variant="ghost" className="text-destructive" disabled={busy} onClick={() => setDiscard(true)}>
              {t("executor.changesets.discard.button")}
            </Button>
          )}
        </div>
        {!isAuthor && editable && <p className="text-xs text-muted-foreground">{t("executor.changesets.notAuthor", { author: d.author })}</p>}
        {d.status === "approved" && (
          <Alert tone="warn" testId="awaiting-second">
            {isAuthor
              ? t("executor.changesets.awaiting.author", { until: until ? when(until) : "-", id: d.changeset_id })
              : t("executor.changesets.awaiting.second", { author: d.author, until: until ? when(until) : "-" })}
          </Alert>
        )}
        {note && <Alert tone="info">{t(note.key, note.params)}</Alert>}
        {fail && <FailureView f={fail} />}
      </section>

      {(d.dry_run?.running || dry || stored || d.dry_run?.error) && (
        <section className={section}>
          <h3 className="text-sm font-semibold">{t("executor.changesets.dryRun.title")}</h3>
          {d.dry_run?.running && (
            <p className="text-sm" data-testid="dry-run-running">
              <span className="mr-2 inline-block size-2 animate-pulse rounded-full bg-sky-500 align-middle" />
              {t("executor.changesets.dryRun.running")}
            </p>
          )}
          {d.dry_run?.error && <Alert>{t("executor.changesets.dryRun.error")}</Alert>}
          {dry && <DryRunView ok={dry.ok} plan={dry.plan_sha256} devices={dry.devices} preview={dry.preview} />}
          {!dry && !d.dry_run?.running && stored && <DryRunView ok={stored.ok} plan={stored.plan} devices={stored.devices} stale />}
        </section>
      )}

      {RUN_STATES.includes(d.status) && (
        <section className={section}>
          <h3 className="text-sm font-semibold">{t("executor.changesets.run")}</h3>
          <ProgressView token={token} detail={d} onChanged={() => void read("progress")} onGone={onGone} onRecordings={onRecordings} onRestore={onRestore} />
        </section>
      )}

      <section className={section}>
        <h3 className="text-sm font-semibold">{t("executor.changesets.history")}</h3>
        <ol className="space-y-1 text-[13px]" data-testid="cs-history">
          {[...d.events].reverse().map((e, i) => {
            const p = (e.payload ?? {}) as Record<string, unknown>;
            const reason = typeof p.reason === "string" && p.reason !== "" ? runError(p.reason) : "";
            return (
              <li key={i} className="flex flex-wrap items-baseline gap-x-3 border-b border-dashed py-1 last:border-0">
                <span className="w-36 shrink-0 font-mono text-xs text-muted-foreground">{when(e.at)}</span>
                <span className="w-10 shrink-0 font-mono text-xs text-muted-foreground">r{e.revision}</span>
                <span className="font-medium">{t(`executor.changesets.event.${e.kind}`, { defaultValue: e.kind })}</span>
                {e.device_id ? <span className="font-mono text-xs">#{e.device_id}</span> : null}
                {reason && <span className="text-xs text-muted-foreground">{reason}</span>}
                {e.session_id && e.device_id ? (
                  <button type="button" className="text-xs underline underline-offset-2" onClick={() => onRecordings(e.session_id as string, e.device_id as number)}>
                    {t("executor.changesets.recording")}
                  </button>
                ) : null}
              </li>
            );
          })}
          <li className="flex flex-wrap items-baseline gap-x-3 py-1">
            <span className="font-medium text-muted-foreground">{t("executor.changesets.event.created", { author: d.author })}</span>
          </li>
        </ol>
      </section>

      {approve && (
        <ApproveDialog poster={poster} detail={d} me={me} onClose={() => setApprove(false)} onDone={(status) => {
          setApprove(false);
          setNote({ key: status === "running" ? "executor.changesets.approve.started" : "executor.changesets.approve.waiting" });
          void read("progress");
        }} />
      )}
      {discard && <DiscardDialog token={token} id={d.changeset_id} onClose={() => setDiscard(false)} onGone={onGone} onDone={() => {
        setDiscard(false);
        void read("progress");
      }} />}
    </div>
  );
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-muted-foreground">{k}</dt>
      <dd className="truncate">{v}</dd>
    </div>
  );
}

/* Discarding a changeset (the author's own): no run may start it any more; gated like a confirm. */
function DiscardDialog({ token, id, onClose, onDone, onGone }: { token: string; id: string; onClose: () => void; onDone: () => void; onGone: () => void }) {
  const { t } = useTranslation();
  const { ref: gateRef, ...gate } = useConfirmGate();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const go = async () => {
    if (!gate.visibleNow()) return;
    setBusy(true);
    const r = await op(token, "discard", { changeset_id: id }, okAnswer);
    setBusy(false);
    if (r.ok) return onDone();
    if (workspaceGone(r.failure)) return onGone();
    setMsg(messageOf(r.failure));
  };
  return (
    <Dialog title={t("executor.changesets.discard.title")} busy={busy} onClose={onClose} testId="discard-dialog">
      <div className="space-y-2">
        <div ref={gateRef} className="space-y-3">
          <p>{t("executor.changesets.discard.explain")}</p>
          <div className="flex gap-2">
            <Button type="button" variant="destructive" disabled={busy || !gate.unobscured} onClick={() => void go()}>
              {t("executor.changesets.discard.confirm")}
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
