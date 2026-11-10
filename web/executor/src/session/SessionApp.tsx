import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { openedAnswer, SESSION_ID, sessionMessage, type Opened } from "./api";
import { Alert } from "./Dialog";
import { RollbackDialog } from "./SessionDialogs";
import { SessionView, type Ended } from "./SessionView";
import type { SocketFactory } from "./socket";

const input = "mt-1 block h-9 w-full rounded-md border bg-background px-3 outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";
const codeInput = `${input} max-w-36 font-mono text-base tracking-[0.3em]`;

/* "12, 14 15" -> [12, 14, 15]; null when anything is not a device id */
export function parseDevices(s: string): number[] | null {
  const parts = s.split(/[\s,;]+/).filter(Boolean);
  if (parts.length === 0 || parts.length > 64 || !parts.every((p) => /^\d{1,18}$/.test(p) && Number(p) > 0)) return null;
  return [...new Set(parts.map(Number))];
}

type State = { phase: "start" } | { phase: "open"; opened: Opened; token: string } | { phase: "ended"; ended: Ended; session: string };

/*
 * The change session screen (Task 4c.6): open a session (devices + ticket + change TOTP), reattach to one (a new token
 * for the same user), the open session, and what is left after it ended (the rollback stays possible for an
 * interrupted session; the recording is in "Записи"). The token lives in this component's memory only.
 */
export function SessionApp({ poster, preset, compact, onOpenChange, onExpand, onRecordings, open }: {
  poster: Poster;
  preset: number[];
  compact: boolean;
  onOpenChange: (open: boolean) => void;
  onExpand: () => void;
  onRecordings: (session: string, device?: number) => void;
  open?: SocketFactory;
}) {
  const { t } = useTranslation();
  const [st, setSt] = useState<State>({ phase: "start" });
  const [devices, setDevices] = useState(preset.join(", "));
  const [code, setCode] = useState("");
  const [attachId, setAttachId] = useState("");
  const [attachCode, setAttachCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [rollback, setRollback] = useState(false);

  const isOpen = st.phase === "open";
  useEffect(() => onOpenChange(isOpen), [isOpen, onOpenChange]);

  const start = async (path: string, body: Record<string, unknown>) => {
    setMsg(null);
    setBusy(true);
    const r = await poster.post(path, body, openedAnswer);
    setBusy(false);
    if (!r.ok) return setMsg(sessionMessage(r.failure));
    const o = r.value.result;
    if (!o.token) return setMsg({ key: "executor.error.bad_response" });
    setSt({ phase: "open", opened: o, token: o.token });
  };

  const openSession = () => {
    const ids = parseDevices(devices);
    if (!ids || !/^\d{6}$/.test(code)) return;
    const c = code;
    setCode(""); /* sent once, never again */
    void start("/x/sessions", { totp: c, device_ids: ids });
  };
  const attach = () => {
    if (!SESSION_ID.test(attachId) || !/^\d{6}$/.test(attachCode)) return;
    const c = attachCode;
    setAttachCode("");
    void start(`/x/sessions/${attachId}/attach`, { totp: c });
  };

  if (st.phase === "open") {
    return (
      <SessionView poster={poster} opened={st.opened} token={st.token} compact={compact} onExpand={onExpand} open={open}
        onUpdate={(o) => setSt({ phase: "open", opened: o, token: o.token ?? st.token })}
        onEnded={(e) => setSt({ phase: "ended", ended: e, session: st.opened.session_id })} />
    );
  }

  if (compact) {
    return (
      <div className="flex h-full items-center gap-4 px-4" data-testid="compact-bar">
        <span className="text-sm text-muted-foreground">{t("executor.session.none")}</span>
        <Button type="button" size="sm" variant="outline" className="ml-auto" onClick={onExpand}>
          {t("executor.session.expand")}
        </Button>
      </div>
    );
  }

  const ids = parseDevices(devices);
  return (
    <div className="mx-auto grid max-w-5xl gap-4 lg:grid-cols-[3fr_2fr]">
      {st.phase === "ended" && (
        <section className="space-y-3 rounded-xl border bg-card p-5 lg:col-span-2" data-testid="session-ended">
          <h2 className="text-base font-semibold">{t(st.ended.reason === "closed" ? "executor.session.ended.closed" : "executor.session.ended.gone")}</h2>
          <p className="font-mono text-xs text-muted-foreground">{st.session}</p>
          {st.ended.reason === "gone" && <p className="text-sm">{t("executor.session.ended.goneExplain")}</p>}
          <div className="flex flex-wrap gap-2">
            {st.ended.reason === "gone" && (
              <Button type="button" variant="outline" className="border-destructive/50 text-destructive hover:bg-destructive/10" onClick={() => setRollback(true)}>
                {t("executor.session.actions.rollback")}
              </Button>
            )}
            <Button type="button" variant="outline" onClick={() => onRecordings(st.session)}>
              {t("executor.session.ended.recordings")}
            </Button>
            <Button type="button" variant="ghost" onClick={() => setSt({ phase: "start" })}>
              {t("executor.session.ended.new")}
            </Button>
          </div>
          {rollback && <RollbackDialog poster={poster} session={st.session} onClose={() => setRollback(false)} onDone={() => {}} />}
        </section>
      )}
      <section className="space-y-4 rounded-xl border bg-card p-5" data-testid="session-start">
        <div>
          <h2 className="text-base font-semibold">{t("executor.session.start.title")}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("executor.session.start.explain")}</p>
        </div>
        <label className="block text-sm font-medium">
          {t("executor.session.start.devices")}
          <input className={`${input} font-mono`} id="ss-devices" name="ss-devices" autoComplete="off" spellCheck={false} value={devices}
            onChange={(e) => setDevices(e.target.value)} />
          <span className="mt-1 block text-xs font-normal text-muted-foreground">{t("executor.session.start.devicesHint")}</span>
        </label>
        {devices !== "" && !ids && <p className="text-sm text-destructive">{t("executor.session.start.badDevices")}</p>}
        <label className="block text-sm font-medium">
          {t("executor.confirm.code")}
          <input className={codeInput} id="ss-code" name="ss-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code}
            onChange={(e) => setCode(e.target.value)} />
        </label>
        <p className="rounded-md border border-amber-400/60 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-200" data-testid="preset-note">
          {t("executor.session.start.presetNote")}
        </p>
        <ul className="list-disc space-y-1 pl-5 text-xs text-muted-foreground">
          <li>{t("executor.session.start.ruleTimer")}</li>
          <li>{t("executor.session.start.ruleRecord")}</li>
          <li>{t("executor.session.start.ruleDanger")}</li>
        </ul>
        <Button type="button" disabled={busy || !ids || !/^\d{6}$/.test(code)} onClick={openSession}>
          {t("executor.session.start.open")}
        </Button>
        {msg && <Alert testId="failure">{t(msg.key, msg.params)}</Alert>}
      </section>
      <section className="space-y-4 rounded-xl border bg-card p-5" data-testid="session-attach">
        <div>
          <h2 className="text-base font-semibold">{t("executor.session.attach.title")}</h2>
          <p className="mt-1 text-sm text-muted-foreground">{t("executor.session.attach.explain")}</p>
        </div>
        <label className="block text-sm font-medium">
          {t("executor.session.attach.id")}
          <input className={`${input} font-mono text-xs`} id="sa-id" name="sa-id" autoComplete="off" spellCheck={false} maxLength={36} value={attachId}
            onChange={(e) => setAttachId(e.target.value.trim().toLowerCase())} />
        </label>
        <label className="block text-sm font-medium">
          {t("executor.confirm.code")}
          <input className={codeInput} id="sa-code" name="sa-code" inputMode="numeric" maxLength={6} autoComplete="off" value={attachCode}
            onChange={(e) => setAttachCode(e.target.value)} />
        </label>
        <Button type="button" variant="outline" disabled={busy || !SESSION_ID.test(attachId) || !/^\d{6}$/.test(attachCode)} onClick={attach}>
          {t("executor.session.attach.go")}
        </Button>
      </section>
    </div>
  );
}
