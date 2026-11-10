import { useCallback, useEffect, useReducer, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Poster } from "../client";
import { ConfirmPanel, type ShownField } from "../ConfirmPanel";
import { failureMessage, type Message } from "../errors";
import { useUnobscured } from "../useUnobscured";
import { refusalKey, type DeviceDiff } from "./api";
import { Alert, Dialog } from "./Dialog";
import { connectTerminal, type SocketFactory, type TermSocket } from "./socket";
import { initialTerm, screenOf, termReducer, type Challenge, type Notice, type Pending } from "./term";
import { Terminal } from "./Terminal";

/* Refusal codes of the terminal with a text of their own (executor.session.term.*); the rest use the session's. */
const TERM_CODES = ["line_limit", "device_error", "send_failed", "rest_dropped", "nothing_pending", "device_name", "rate_limited", "changed",
  "no_device_name", "denied", "frozen", "disabled", "locked", "unavailable", "too_many_challenges", "control", "writes_disabled"];

export function noticeKey(n: Notice): string {
  return TERM_CODES.includes(n.code) ? `executor.session.term.${n.code}` : (refusalKey(n.code) ?? "executor.session.term.other");
}

export type Flow = { kind: "commit" | "save" | "rollback"; device: number; diff?: DeviceDiff };

type Props = {
  poster: Poster;
  session: string;
  token: string;
  device: number;
  active: boolean;
  /* a key, a paste or a confirmation went to the executor (the session's idle timer restarts) */
  onActivity: () => void;
  /* a typed control line opened a flow (save, commit, rollback) */
  onFlow: (f: Flow) => void;
  /* the executor ended the terminal because the session is gone */
  onGone: () => void;
  open?: SocketFactory;
};

/*
 * One device's terminal: its own WebSocket, the line the executor edits, the dangerous-line and paste confirmations.
 * Stays mounted while another device's tab is shown (the connection and its transcript are kept).
 */
export function DeviceTerminal({ poster, session, token, device, active, onActivity, onFlow, onGone, open }: Props) {
  const { t, i18n } = useTranslation();
  const [s, dispatch] = useReducer(termReducer, initialTerm);
  const sock = useRef<TermSocket | null>(null);
  const [gen, setGen] = useState(0);
  const cb = useRef({ onFlow, onGone });
  useEffect(() => {
    cb.current = { onFlow, onGone };
  }, [onFlow, onGone]);

  useEffect(() => {
    const so = connectTerminal({
      session,
      token,
      device,
      open,
      onMessage: (m) => dispatch({ type: "message", m }),
      onClose: () => dispatch({ type: "closed" }),
    });
    sock.current = so;
    return () => {
      so.close();
      if (sock.current === so) sock.current = null;
    };
  }, [session, token, device, open, gen]);

  /* a flow the executor opened goes to the session screen once */
  const seq = s.flow?.seq;
  useEffect(() => {
    if (!s.flow) return;
    cb.current.onFlow({ kind: s.flow.kind, device, diff: s.flow.diff });
    dispatch({ type: "flow_done" });
  }, [seq, s.flow, device]);
  useEffect(() => {
    if (s.ended === "no_session") cb.current.onGone();
  }, [s.ended]);

  const send = useCallback(
    (f: Parameters<TermSocket["send"]>[0]) => {
      const ok = sock.current?.send(f) ?? false;
      if (ok) onActivity();
      return ok;
    },
    [onActivity],
  );

  const screen = screenOf(s);
  const lost = s.conn === "closed" && s.ended !== "no_session";
  return (
    <div className="flex h-full min-h-0 flex-col gap-2" data-testid={`device-term-${device}`}>
      {s.notice && (
        <div className="flex items-start gap-2" data-testid="term-notice">
          <div className="flex-1">
            <Alert tone="warn">
              {t(noticeKey(s.notice))}
              {s.notice.reason && i18n.exists(`executor.session.reason.${s.notice.reason}`) && ` (${t(`executor.session.reason.${s.notice.reason}`)})`}
            </Alert>
          </div>
          <Button type="button" variant="ghost" size="sm" onClick={() => dispatch({ type: "dismiss" })}>
            {t("executor.session.dismiss")}
          </Button>
        </div>
      )}
      {s.limited && <p className="text-xs text-muted-foreground">{t("executor.session.term.limited")}</p>}
      {lost && (
        <div className="flex items-center gap-3" data-testid="term-lost">
          <div className="flex-1">
            <Alert tone="warn">{t("executor.session.term.lost")}</Alert>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={() => setGen((g) => g + 1)}>
            {t("executor.session.term.reconnect")}
          </Button>
        </div>
      )}
      <Terminal output={screen.text} caret={s.conn === "ready" ? screen.caret : undefined} readOnly={s.conn !== "ready"} className="min-h-64 flex-1"
        onKeys={(k) => send({ type: "keys", data: k })} onPaste={(p) => send({ type: "paste", data: p })} />
      {active && s.dangerous && (
        <DangerousDialog
          poster={poster}
          pending={s.dangerous}
          onIssue={(ticket) => send({ type: "dangerous_issue", ticket })}
          onConfirm={(c, name, code, ticket) => send({ type: "dangerous_confirm", challenge_id: c.challenge_id, device_name: name, totp: code, ticket })}
          onCancel={() => {
            send({ type: "keys", data: "\x03" }); /* Ctrl-C: the executor drops the line and discards its challenge */
            dispatch({ type: "local_cancel" });
          }}
        />
      )}
      {active && s.paste && (
        <PasteDialog
          text={s.paste.text}
          lines={s.paste.lines}
          onAnswer={(accept) => {
            send({ type: "paste_confirm", accept });
            dispatch({ type: "local_cancel" });
          }}
        />
      )}
    </div>
  );
}

const field = (c: Challenge, k: string) => c.fields.find((f) => f.key === k)?.value ?? "";

/*
 * A dangerous line (security 5.3): never sent as typed. Step 1 asks the executor for a challenge with a fresh ticket;
 * step 2 shows everything H covers (the registry's address:port and id of the device, its name, the line, the mode,
 * the session: ruling R8) and takes the device name typed exactly (a guard against a mistaken device) and a NEW change
 * TOTP code. The confirm is gated by useUnobscured (ConfirmPanel). Whatever the outcome, the line is spent.
 */
function DangerousDialog(p: {
  poster: Poster;
  pending: Pending;
  onIssue: (ticket: string) => boolean;
  onConfirm: (c: Challenge, name: string, code: string, ticket: string) => boolean;
  onCancel: () => void;
}) {
  const { t, i18n } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [msg, setMsg] = useState<Message | null>(null);
  const c = p.pending.challenge;
  const expected = c ? field(c, "device") : "";

  const issue = async () => {
    setMsg(null);
    setBusy(true);
    const r = await p.poster.ticket();
    if (!r.ok) {
      setBusy(false);
      setMsg(failureMessage(r.failure));
      return;
    }
    if (!p.onIssue(r.value)) setMsg({ key: "executor.session.term.lost" });
    setBusy(false);
  };

  const confirm = async (code: string) => {
    if (!c || name !== expected) return; /* the typed name must be exactly the device's */
    setMsg(null);
    setBusy(true);
    const r = await p.poster.ticket(code);
    if (!r.ok) {
      setBusy(false);
      setMsg(failureMessage(r.failure));
      return;
    }
    if (!p.onConfirm(c, name, code, r.value)) {
      setBusy(false);
      setMsg({ key: "executor.session.term.lost" });
    }
    /* stays busy: the executor's answer (output or refusal) closes the dialog */
  };

  const label = (k: string) => (i18n.exists(`executor.session.field.${k}`) ? t(`executor.session.field.${k}`) : k);
  const fields: ShownField[] = c ? c.fields.map((f) => ({ key: f.key, label: label(f.key), value: f.value })) : [];
  const lineBox = (
    <div className="rounded-lg border border-destructive/50 bg-destructive/5 px-3 py-2">
      <p className="text-xs text-muted-foreground">{t("executor.session.dangerous.line")}</p>
      <p className="font-mono text-[15px] font-semibold break-all" data-testid="dangerous-line">
        {c ? field(c, "line") : p.pending.line}
      </p>
      {p.pending.reason && (
        <p className="mt-1 text-xs text-muted-foreground">
          {t("executor.session.dangerous.reason", {
            reason: i18n.exists(`executor.session.reason.${p.pending.reason}`) ? t(`executor.session.reason.${p.pending.reason}`) : p.pending.reason,
          })}
        </p>
      )}
    </div>
  );
  return (
    <Dialog title={t("executor.session.dangerous.title")} tone="danger" busy={busy} onClose={c ? undefined : p.onCancel} testId="dangerous-dialog">
      {!c && (
        <>
          {lineBox}
          <p>{t("executor.session.dangerous.explain")}</p>
          <div className="flex gap-2">
            <Button type="button" variant="destructive" disabled={busy} onClick={() => void issue()}>
              {t("executor.session.dangerous.issue")}
            </Button>
            <Button type="button" variant="outline" disabled={busy} onClick={p.onCancel}>
              {t("executor.session.dangerous.drop")}
            </Button>
          </div>
        </>
      )}
      {c && (
        <ConfirmPanel title={t("executor.session.dangerous.confirmTitle")} fields={fields} h={c.h} confirmLabel={t("executor.session.dangerous.send")} busy={busy}
          extraReady={name !== "" && name === expected} onConfirm={(code) => void confirm(code)} onCancel={p.onCancel} lead={lineBox}>
          <label className="block font-medium">
            {t("executor.session.dangerous.typeName")}
            <input className="mt-1 block h-9 w-full max-w-sm rounded-md border bg-background px-3 font-mono outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
              id="dg-name" name="dg-name" autoComplete="off" spellCheck={false} value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          {name !== "" && name !== expected && <p className="text-destructive" data-testid="name-mismatch">{t("executor.session.dangerous.nameMismatch")}</p>}
          <p className="text-muted-foreground">{t("executor.session.dangerous.newCode")}</p>
        </ConfirmPanel>
      )}
      {msg && <Alert>{t(msg.key, msg.params)}</Alert>}
    </Dialog>
  );
}

/* A paste with more lines than the policy lets through unasked: the executor holds it and shows it here first. */
function PasteDialog({ text, lines, onAnswer }: { text: string; lines: number; onAnswer: (accept: boolean) => void }) {
  const { t } = useTranslation();
  const { ref, unobscured, supported } = useUnobscured();
  const seen = useRef(false);
  useEffect(() => {
    seen.current = unobscured;
  }, [unobscured]);
  return (
    <Dialog title={t("executor.session.paste.title", { count: lines })} onClose={() => onAnswer(false)} testId="paste-dialog">
      <div ref={ref} className="space-y-3">
        <p>{t("executor.session.paste.explain")}</p>
        <pre className="max-h-[45vh] overflow-auto rounded-md border bg-muted/30 px-3 py-2 font-mono text-[12.5px] leading-5 whitespace-pre-wrap break-all" data-testid="paste-text">
          {text}
        </pre>
        {!unobscured && <Alert>{t(supported ? "executor.obscured" : "executor.visibilityUnsupported")}</Alert>}
        <div className="flex gap-2">
          <Button type="button" disabled={!unobscured} onClick={() => seen.current && onAnswer(true)}>
            {t("executor.session.paste.send", { count: lines })}
          </Button>
          <Button type="button" variant="outline" onClick={() => onAnswer(false)}>
            {t("executor.confirm.cancel")}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
