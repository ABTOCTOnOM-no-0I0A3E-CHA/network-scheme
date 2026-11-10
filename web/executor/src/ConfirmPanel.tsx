import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { GateNotice, useConfirmGate } from "./frame";

/* One line of what the executor says it will do (and H covers). A warn is a text key shown beside the value. */
export type ShownField = { key: string; label: string; value: string; warn?: string };

/*
 * The one place a change is confirmed (ruling R4): the description and H and the TOTP field are in one element that
 * is gated by useUnobscured, so a panel overlay cannot hide them while the code field stays usable. The confirm
 * button is disabled while the element is covered (or taller than the frame: then GateNotice offers to expand it)
 * and the observer's latest answer is re-checked at the click. The notices are outside the observed element: they
 * never change its height. The code is cleared once handed to onConfirm: a code sent is never sent again. Text only;
 * no <form>, autocomplete off.
 */
export function ConfirmPanel(p: {
  title: string;
  fields: ShownField[];
  h: string;
  confirmLabel: string;
  busy: boolean;
  onConfirm: (code: string) => void;
  onCancel: () => void;
  children?: ReactNode;
  /* a further condition of the caller's (e.g. the device name typed exactly), checked like the code */
  extraReady?: boolean;
  /* emphasised fields: shown first, larger */
  lead?: ReactNode;
  /* the fields laid out by the caller (every one of them, with data-testid field-<key>) instead of the list */
  fieldsView?: ReactNode;
}) {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const { ref: gateRef, ...gate } = useConfirmGate();
  const ready = /^\d{6}$/.test(code) && p.extraReady !== false;

  const send = () => {
    if (!gate.visibleNow() || !ready || p.busy) return;
    const c = code;
    setCode("");
    p.onConfirm(c);
  };

  return (
    <div className="space-y-2">
      <div ref={gateRef} className="space-y-3 text-sm" data-testid="confirm">
        <p className="text-base font-semibold">{p.title}</p>
        {p.lead}
        {p.fieldsView ?? (
          <dl className="grid grid-cols-[minmax(8rem,auto)_1fr] gap-x-4 gap-y-1.5 rounded-lg border bg-muted/40 px-3 py-2.5">
            {p.fields.flatMap((f) => [
              <dt key={`${f.key}-k`} className="text-muted-foreground">
                {f.label}
              </dt>,
              <dd key={`${f.key}-v`} className="font-mono text-[13px] break-all" data-testid={`field-${f.key}`}>
                {f.value}
                {f.warn && <strong className="ml-2 font-sans text-destructive">{f.warn}</strong>}
              </dd>,
            ])}
          </dl>
        )}
        <div className="rounded-lg border-2 border-foreground/80 px-3 py-2">
          <p className="text-xs text-muted-foreground">{t("executor.confirm.hHint")}</p>
          <p className="font-mono text-[15px] leading-6 font-semibold tracking-wide break-all" data-testid="h">
            H: {p.h}
          </p>
        </div>
        {p.children}
        <label className="block font-medium">
          {t("executor.confirm.code")}
          <input className="mt-1 block h-9 w-36 rounded-md border bg-background px-3 font-mono text-base tracking-[0.3em] outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
            id="cp-code" name="cp-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} />
        </label>
        <div className="flex gap-2 pt-1">
          <Button type="button" disabled={p.busy || !gate.unobscured || !ready} onClick={send}>
            {p.confirmLabel}
          </Button>
          <Button type="button" variant="outline" onClick={p.onCancel} disabled={p.busy}>
            {t("executor.confirm.cancel")}
          </Button>
        </div>
      </div>
      <GateNotice gate={gate} />
    </div>
  );
}
