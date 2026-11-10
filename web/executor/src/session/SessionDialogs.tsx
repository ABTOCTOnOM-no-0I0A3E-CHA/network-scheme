import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Poster } from "../client";
import { ConfirmPanel, type ShownField } from "../ConfirmPanel";
import type { Message } from "../errors";
import { GateNotice, useConfirmGate } from "../frame";
import { challengeSchema, refusalKey, ROLLBACK, rollbackAnswer, sessionMessage, type Challenge, type DeviceDiff, type RolledBack } from "./api";
import { Alert, Dialog } from "./Dialog";
import { DiffView } from "./DiffView";

/* The label of a rollback field: per-device keys (address_12, pre_sha256_12, state_12) name the device. */
function useFieldLabel() {
  const { t, i18n } = useTranslation();
  return (k: string) => {
    const m = /^(address|pre_sha256|state)_(\d+)$/.exec(k);
    if (m) return t(`executor.session.field.${m[1]}_of`, { id: m[2] });
    return i18n.exists(`executor.session.field.${k}`) ? t(`executor.session.field.${k}`) : k;
  };
}

/*
 * "Откатить всю сессию" (security 5.3, Task 4c.4): confirm(H) over the session, its devices, each one's registry
 * address:port, pre-session hash and state, and the write groups. Every field is shown (H covers all of them), the
 * state of a device says what will happen to it. The code is the user's NEW change TOTP; a spent code is never resent.
 */
export function RollbackDialog({ poster, session, onClose, onDone }: { poster: Poster; session: string; onClose: () => void; onDone: (r: RolledBack[]) => void }) {
  const { t } = useTranslation();
  const label = useFieldLabel();
  const [c, setC] = useState<Challenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [result, setResult] = useState<RolledBack[] | null>(null);

  const issue = async () => {
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/confirm/issue", { action: ROLLBACK, params: { session_id: session } }, challengeSchema);
    setBusy(false);
    if (!r.ok) return setMsg(sessionMessage(r.failure));
    if (r.value.action !== ROLLBACK || !r.value.fields.some((f) => f.key === "session" && f.value === session)) return setMsg({ key: "executor.session.rollback.mismatch" });
    setC(r.value);
  };

  const confirm = async (code: string) => {
    if (!c) return;
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/confirm", { challenge_id: c.challenge_id, h: c.h, code }, rollbackAnswer);
    setBusy(false);
    if (r.ok) {
      setResult(r.value.result.devices);
      onDone(r.value.result.devices);
      return;
    }
    const f = r.failure;
    setMsg(sessionMessage(f));
    /* refused, or the executor failed (the challenge may be spent): start again; a lock or limit waits for the next code */
    if (f.kind === "http" && (f.status === 422 || f.status >= 500 || f.code === "denied")) setC(null);
  };

  const warn = (k: string, v: string) => {
    if (!k.startsWith("state_")) return undefined;
    return v === "open" || v === "interrupted" ? undefined : t(`executor.session.rollback.state.${v === "commit_pending" ? "commit_pending" : "closed"}`);
  };
  const fields: ShownField[] = c ? c.fields.map((f) => ({ key: f.key, label: label(f.key), value: f.value, warn: warn(f.key, f.value) })) : [];

  return (
    <Dialog title={t("executor.session.rollback.title")} wide tone="danger" busy={busy} onClose={onClose} testId="rollback-dialog">
      {!c && !result && (
        <>
          <p>{t("executor.session.rollback.explain")}</p>
          <p className="text-muted-foreground">{t("executor.session.rollback.cost")}</p>
          <div className="flex gap-2">
            <Button type="button" variant="destructive" disabled={busy} onClick={() => void issue()}>
              {t("executor.session.rollback.issue")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
              {t("executor.confirm.cancel")}
            </Button>
          </div>
        </>
      )}
      {c && !result && (
        <ConfirmPanel title={t("executor.session.rollback.confirmTitle")} fields={fields} h={c.h} confirmLabel={t("executor.session.rollback.confirm")} busy={busy}
          onConfirm={(code) => void confirm(code)} onCancel={onClose} fieldsView={<RollbackFields fields={fields} />}>
          <p className="text-muted-foreground">{t("executor.session.rollback.newCode")}</p>
        </ConfirmPanel>
      )}
      {result && (
        <div className="space-y-2" data-testid="rollback-result">
          <ul className="space-y-1.5">
            {result.map((d) => (
              <li key={d.device_id} className="flex flex-wrap items-baseline gap-x-2 rounded-md border px-3 py-2">
                <span className="font-medium">{t("executor.session.deviceLabel", { id: d.device_id })}</span>
                {d.error ? (
                  <span className="text-destructive">{t(refusalKey(d.error) ?? "executor.session.refused.rollback_failed")}</span>
                ) : (
                  <span className="text-emerald-700 dark:text-emerald-400">{t("executor.session.rollback.ok", { sha: (d.sha256 ?? "").slice(0, 16) })}</span>
                )}
              </li>
            ))}
          </ul>
          <Button type="button" variant="outline" onClick={onClose}>
            {t("executor.session.close")}
          </Button>
        </div>
      )}
      {msg && <Alert>{t(msg.key, msg.params)}</Alert>}
    </Dialog>
  );
}

/*
 * The rollback description laid out to fit a dock (review 4c.6 I1): the session-wide fields as a list, then one row
 * per device (registry address:port, state, the full pre-session hash on one line). Every field is shown once, each
 * with its data-testid; a key of no known shape stays in the list.
 */
function RollbackFields({ fields }: { fields: ShownField[] }) {
  const { t } = useTranslation();
  const rows = new Map<string, Partial<Record<"address" | "pre_sha256" | "state", ShownField>>>();
  const rest: ShownField[] = [];
  for (const f of fields) {
    const m = /^(address|pre_sha256|state)_(\d+)$/.exec(f.key);
    if (!m) {
      rest.push(f);
      continue;
    }
    const r = rows.get(m[2]) ?? {};
    r[m[1] as "address" | "pre_sha256" | "state"] = f;
    rows.set(m[2], r);
  }
  const cell = (f: ShownField | undefined, cls: string): ReactNode => (
    <td className={`px-2.5 py-1.5 align-top ${cls}`} data-testid={f ? `field-${f.key}` : undefined}>
      {f?.value ?? "-"}
      {f?.warn && <span className="block font-sans text-xs whitespace-normal text-destructive">{f.warn}</span>}
    </td>
  );
  return (
    <div className="space-y-2">
      <dl className="grid grid-cols-[minmax(7rem,auto)_1fr] gap-x-4 gap-y-1 rounded-lg border bg-muted/40 px-3 py-2">
        {rest.flatMap((f) => [
          <dt key={`${f.key}-k`} className="text-muted-foreground">
            {f.label}
          </dt>,
          <dd key={`${f.key}-v`} className="font-mono text-[13px] break-all" data-testid={`field-${f.key}`}>
            {f.value}
          </dd>,
        ])}
      </dl>
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-[13px]">
          <thead className="bg-muted/40 text-left text-xs text-muted-foreground">
            <tr>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.session.rollback.col.device")}</th>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.session.rollback.col.address")}</th>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.session.rollback.col.state")}</th>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.session.rollback.col.pre")}</th>
            </tr>
          </thead>
          <tbody>
            {[...rows].sort((a, b) => Number(a[0]) - Number(b[0])).map(([id, r]) => (
              <tr key={id} className="border-t" data-testid={`rollback-row-${id}`}>
                <td className="px-2.5 py-1.5 align-top font-medium whitespace-nowrap">{t("executor.session.deviceShort", { id })}</td>
                {cell(r.address, "font-mono whitespace-nowrap")}
                {cell(r.state, "font-mono whitespace-nowrap")}
                {cell(r.pre_sha256, "font-mono text-[11.5px] whitespace-nowrap")}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/* A dialog's gated part: the observed element holds the text and the buttons; the notices stay outside it. */
function Gated({ children, notice }: { children: (gate: Omit<ReturnType<typeof useConfirmGate>, "ref">) => ReactNode; notice?: ReactNode }) {
  const { ref: gateRef, ...gate } = useConfirmGate();
  return (
    <div className="space-y-2">
      <div ref={gateRef} className="space-y-3">
        {children(gate)}
      </div>
      <GateNotice gate={gate} />
      {notice}
    </div>
  );
}

/*
 * Save (MES: the startup configuration) or confirm the pending commit (ESR) of one device, with the diff the user saw:
 * its hash is what the executor saves, anything else is refused (diff_changed). The button is gated like a confirm.
 */
export function SaveDialog(p: { diff: DeviceDiff; esr: boolean; busy: boolean; msg: Message | null; secondsLeft?: number; onSave: () => void; onClose: () => void }) {
  const { t } = useTranslation();
  const late = p.esr && p.secondsLeft !== undefined && p.secondsLeft <= 15;
  const nothing = p.esr && !p.diff.commit_pending_until;
  return (
    <Dialog title={t(p.esr ? "executor.session.save.titleEsr" : "executor.session.save.title", { id: p.diff.device_id })} wide busy={p.busy} onClose={p.onClose} testId="save-dialog">
      <Gated notice={p.msg && <Alert>{t(p.msg.key, p.msg.params)}</Alert>}>
        {(gate) => (
          <>
            <p>{t(p.esr ? "executor.session.save.explainEsr" : "executor.session.save.explain")}</p>
            <DiffView diff={p.diff} maxHeight="max-h-[35vh]" />
            {nothing && <Alert tone="warn">{t("executor.session.refused.nothing_to_confirm")}</Alert>}
            {late && <Alert>{t("executor.session.refused.commit_timer")}</Alert>}
            <div className="flex gap-2">
              <Button type="button" disabled={p.busy || !gate.unobscured || nothing || late} onClick={() => gate.visibleNow() && p.onSave()}>
                {t(p.esr ? "executor.session.save.confirmEsr" : "executor.session.save.confirm")}
              </Button>
              <Button type="button" variant="outline" disabled={p.busy} onClick={p.onClose}>
                {t("executor.confirm.cancel")}
              </Button>
            </div>
          </>
        )}
      </Gated>
    </Dialog>
  );
}

/* The extension of the session: session_minutes from now, for a new change TOTP code. */
export function ExtendDialog({ busy, msg, onExtend, onClose }: { busy: boolean; msg: Message | null; onExtend: (code: string) => void; onClose: () => void }) {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  return (
    <Dialog title={t("executor.session.extend.title")} busy={busy} onClose={onClose} testId="extend-dialog">
      <p>{t("executor.session.extend.explain")}</p>
      <label className="block font-medium">
        {t("executor.confirm.code")}
        <input className="mt-1 block h-9 w-36 rounded-md border bg-background px-3 font-mono text-base tracking-[0.3em] outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
          id="ex-code" name="ex-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} />
      </label>
      {msg && <Alert>{t(msg.key, msg.params)}</Alert>}
      <div className="flex gap-2">
        <Button type="button" disabled={busy || !/^\d{6}$/.test(code)} onClick={() => {
          const c = code;
          setCode(""); /* sent once, never again */
          onExtend(c);
        }}>
          {t("executor.session.extend.confirm")}
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
          {t("executor.confirm.cancel")}
        </Button>
      </div>
    </Dialog>
  );
}

/* Ending the session (gated like a confirm): ESR devices with a commit not confirmed are restored by the executor. */
export function EndDialog({ busy, msg, pendingEsr, onEnd, onClose }: { busy: boolean; msg: Message | null; pendingEsr: boolean; onEnd: () => void; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Dialog title={t("executor.session.end.title")} busy={busy} onClose={onClose} testId="end-dialog">
      <Gated notice={msg && <Alert>{t(msg.key, msg.params)}</Alert>}>
        {(gate) => (
          <>
            <p>{t("executor.session.end.explain")}</p>
            {pendingEsr && <Alert tone="warn">{t("executor.session.end.pendingEsr")}</Alert>}
            <div className="flex gap-2">
              <Button type="button" variant="destructive" disabled={busy || !gate.unobscured} onClick={() => gate.visibleNow() && onEnd()}>
                {t("executor.session.end.confirm")}
              </Button>
              <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
                {t("executor.confirm.cancel")}
              </Button>
            </div>
          </>
        )}
      </Gated>
    </Dialog>
  );
}

/* ESR commit (gated like a confirm): the policy's confirm timer starts, then the health check; confirm afterwards. */
export function CommitDialog({ device, busy, msg, onCommit, onClose }: { device: number; busy: boolean; msg: Message | null; onCommit: () => void; onClose: () => void }) {
  const { t } = useTranslation();
  return (
    <Dialog title={t("executor.session.commit.title", { id: device })} busy={busy} onClose={onClose} testId="commit-dialog">
      <Gated notice={msg && <Alert>{t(msg.key, msg.params)}</Alert>}>
        {(gate) => (
          <>
            <p>{t("executor.session.commit.explain")}</p>
            <div className="flex gap-2">
              <Button type="button" disabled={busy || !gate.unobscured} onClick={() => gate.visibleNow() && onCommit()}>
                {t("executor.session.commit.confirm")}
              </Button>
              <Button type="button" variant="outline" disabled={busy} onClick={onClose}>
                {t("executor.confirm.cancel")}
              </Button>
            </div>
          </>
        )}
      </Gated>
    </Dialog>
  );
}
