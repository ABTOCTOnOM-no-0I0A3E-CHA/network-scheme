import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { useUnobscured } from "./useUnobscured";

/* One line of what the executor says it will do (and H covers). A warn is a text key shown beside the value. */
export type ShownField = { key: string; label: string; value: string; warn?: string };

/*
 * The one place a change is confirmed (ruling R4): the description and H and the TOTP field are in one element that
 * is gated by useUnobscured, so a panel overlay cannot hide them while the code field stays usable. The confirm
 * button is disabled while the element is covered and the observer's latest answer is re-checked at the click. The
 * code is cleared once handed to onConfirm: a code sent is never sent again. Text only; no <form>, autocomplete off.
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
}) {
  const { t } = useTranslation();
  const [code, setCode] = useState("");
  const { ref, unobscured, supported } = useUnobscured();
  const visible = useRef(false);
  useEffect(() => {
    visible.current = unobscured;
  }, [unobscured]);
  const ready = /^\d{6}$/.test(code);

  const send = () => {
    if (!visible.current || !ready || p.busy) return;
    const c = code;
    setCode("");
    p.onConfirm(c);
  };

  return (
    <div ref={ref} className="space-y-2" data-testid="confirm">
      <p className="font-semibold">{p.title}</p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3">
        {p.fields.flatMap((f) => [
          <dt key={`${f.key}-k`}>{f.label}</dt>,
          <dd key={`${f.key}-v`} className="break-all" data-testid={`field-${f.key}`}>
            {f.value}
            {f.warn && <strong className="ml-2 text-destructive">{f.warn}</strong>}
          </dd>,
        ])}
      </dl>
      <p className="font-mono text-base break-all" data-testid="h">
        H: {p.h}
      </p>
      {p.children}
      <label className="block">
        {t("executor.confirm.code")}
        <input className="block w-32 rounded border px-2 py-1" id="cp-code" name="cp-code" inputMode="numeric" maxLength={6} autoComplete="off"
          value={code} onChange={(e) => setCode(e.target.value)} />
      </label>
      {!unobscured && <p role="alert">{t(supported ? "executor.obscured" : "executor.visibilityUnsupported")}</p>}
      <div className="flex gap-2">
        <Button type="button" disabled={p.busy || !unobscured || !ready} onClick={send}>
          {p.confirmLabel}
        </Button>
        <Button type="button" variant="outline" onClick={p.onCancel} disabled={p.busy}>
          {t("executor.confirm.cancel")}
        </Button>
      </div>
    </div>
  );
}
