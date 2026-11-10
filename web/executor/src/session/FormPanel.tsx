import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Result } from "../client";
import type { Message } from "../errors";
import { GateNotice, useConfirmGate } from "../frame";
import { EMPTY_FORM, FORMS, formAppliedAnswer, formLinesAnswer, sessionMessage, type DeviceDiff, type FormField, type FormValues } from "./api";
import { Alert } from "./Dialog";

type Act = <T>(op: string, body: Record<string, unknown>, schema: import("zod").ZodType<T>) => Promise<Result<T>>;

const input =
  "mt-1 block h-9 w-full rounded-md border bg-background px-3 text-sm outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";

/*
 * The GUI forms of a session (FR-UI-DEV-2): one generic renderer over the fields each form kind uses (the executor's
 * forms.Params). "Эквивалентные команды" are the lines the executor renders, shown exactly as they will be sent; they
 * are applied only as shown (the executor renders them again and compares), each one through the session's Classify.
 * Any change of a field drops the lines shown. No <form> element; autocomplete off on every input.
 */
export function FormPanel({ device, act, busy, onApplied }: { device: number; act: Act; busy: boolean; onApplied: (d: DeviceDiff, sent: number) => void }) {
  const { t } = useTranslation();
  const [v, setV] = useState<FormValues>(EMPTY_FORM);
  const [lines, setLines] = useState<string[] | null>(null);
  const [msg, setMsg] = useState<Message | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
  const { ref: gateRef, ...gate } = useConfirmGate();

  const set = (patch: Partial<FormValues>) => {
    setV((o) => ({ ...o, ...patch }));
    setLines(null);
    setNote(null);
  };
  const fields = FORMS[v.kind] ?? [];

  const render = async () => {
    setMsg(null);
    setWorking(true);
    const r = await act("form", { device_id: device, form: v }, formLinesAnswer);
    setWorking(false);
    if (r.ok) setLines(r.value.result.lines);
    else setMsg(sessionMessage(r.failure));
  };

  const apply = async () => {
    if (!lines || !gate.visibleNow()) return;
    setMsg(null);
    setWorking(true);
    const r = await act("form-apply", { device_id: device, form: v, lines }, formAppliedAnswer);
    setWorking(false);
    setLines(null);
    if (r.ok) {
      setNote(t("executor.session.form.applied", { sent: r.value.result.sent }));
      onApplied(r.value.result.diff, r.value.result.sent);
    } else setMsg(sessionMessage(r.failure));
  };

  const control = (f: FormField) => {
    const id = `fm-${f}-${device}`;
    switch (f) {
      case "up":
        return (
          <label key={f} className="block text-sm font-medium" htmlFor={id}>
            {t("executor.session.form.field.up")}
            <select id={id} name={id} className={input} autoComplete="off" value={v.up ? "up" : "down"} onChange={(e) => set({ up: e.target.value === "up" })}>
              <option value="up">{t("executor.session.form.up")}</option>
              <option value="down">{t("executor.session.form.down")}</option>
            </select>
          </label>
        );
      case "vlan":
        return (
          <label key={f} className="block text-sm font-medium" htmlFor={id}>
            {t("executor.session.form.field.vlan")}
            <input id={id} name={id} className={input} inputMode="numeric" maxLength={4} autoComplete="off" value={v.vlan === 0 ? "" : String(v.vlan)}
              onChange={(e) => set({ vlan: /^\d{0,4}$/.test(e.target.value) ? Number(e.target.value || 0) : v.vlan })} />
          </label>
        );
      default:
        return (
          <label key={f} className="block text-sm font-medium" htmlFor={id}>
            {t(`executor.session.form.field.${f}`)}
            <input id={id} name={id} className={input} autoComplete="off" spellCheck={false} maxLength={f === "description" ? 240 : 64} value={v[f]}
              onChange={(e) => set({ [f]: e.target.value })} />
          </label>
        );
    }
  };

  return (
    <div className="space-y-3" data-testid="form-panel">
      <label className="block text-sm font-medium" htmlFor={`fm-kind-${device}`}>
        {t("executor.session.form.kind")}
        <select id={`fm-kind-${device}`} name={`fm-kind-${device}`} className={input} autoComplete="off" value={v.kind} onChange={(e) => set({ kind: e.target.value })}>
          {Object.keys(FORMS).map((k) => (
            <option key={k} value={k}>
              {t(`executor.session.form.kinds.${k}`)}
            </option>
          ))}
        </select>
      </label>
      <div className="grid gap-3">{fields.map(control)}</div>
      <Button type="button" variant="outline" size="sm" disabled={busy || working} onClick={() => void render()}>
        {t("executor.session.form.render")}
      </Button>
      {lines && (
        <div className="space-y-2">
          <div ref={gateRef} className="space-y-2" data-testid="equivalent">
            <p className="text-sm font-semibold">{t("executor.session.form.equivalent")}</p>
            <pre className="overflow-auto rounded-md border bg-neutral-950 px-3 py-2 font-mono text-[12.5px] leading-5 text-neutral-100">
              {lines.map((l, i) => (
                <div key={i} className="whitespace-pre-wrap break-all" data-testid="equivalent-line">
                  {l}
                </div>
              ))}
            </pre>
            <p className="text-xs text-muted-foreground">{t("executor.session.form.exact")}</p>
            <Button type="button" size="sm" disabled={busy || working || !gate.unobscured} onClick={() => void apply()}>
              {t("executor.session.form.apply", { count: lines.length })}
            </Button>
          </div>
          <GateNotice gate={gate} />
        </div>
      )}
      {note && <Alert tone="info">{note}</Alert>}
      {msg && <Alert>{t(msg.key, msg.params)}</Alert>}
    </div>
  );
}
