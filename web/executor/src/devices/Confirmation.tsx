import { useState } from "react";
import { useTranslation } from "react-i18next";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { ConfirmPanel, type ShownField } from "../ConfirmPanel";
import { doneSchema, messageOf, type Challenge } from "./api";

/* Hosts of the confirm: key -> warning text key. A panel-sourced address is the panel's claim, not the registry's. */
const WARN: Record<string, (v: string) => string | undefined> = {
  address_source: (v) => (v === "panel" ? "executor.devices.warn.panel" : undefined),
};

/*
 * Confirms one issued challenge: EVERY field of the description is shown (nothing is filtered: H covers all of them),
 * the host key fingerprint is to be compared out of band, and the TOTP is entered inside the gated panel. A code
 * sent is never resent; after any server answer other than success the challenge is dropped (start again).
 */
export function Confirmation({ poster, challenge, onDone, onClose }: { poster: Poster; challenge: Challenge; onDone: () => void; onClose: (m?: Message) => void }) {
  const { t, i18n } = useTranslation();
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [done, setDone] = useState(false);

  const label = (k: string) => (i18n.exists(`executor.devices.field.${k}`) ? t(`executor.devices.field.${k}`) : k);
  const fields: ShownField[] = challenge.fields.map((f) => {
    const w = WARN[f.key]?.(f.value);
    return { key: f.key, label: label(f.key), value: f.value, warn: w ? t(w) : undefined };
  });

  const confirm = async (code: string) => {
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/confirm", { challenge_id: challenge.challenge_id, h: challenge.h, code }, doneSchema);
    setBusy(false);
    if (r.ok) {
      setDone(true);
      onDone();
      return;
    }
    const f = r.failure;
    const m = messageOf(f);
    /* refused, or the executor failed (the challenge may be spent): start again; otherwise wait for the next code */
    if (f.kind === "http" && (f.status === 422 || f.status >= 500 || f.code === "denied")) onClose(m);
    else setMsg(m);
  };

  return (
    <div className="space-y-2">
      {!done && (
        <ConfirmPanel title={t("executor.devices.confirmTitle")} fields={fields} h={challenge.h} confirmLabel={t("executor.devices.confirm")} busy={busy}
          onConfirm={(c) => void confirm(c)} onCancel={() => onClose()}>
          {challenge.fields.some((f) => f.key === "hostkey_fp") && <p data-testid="oob">{t("executor.devices.compareOutOfBand")}</p>}
          <p>{t("executor.devices.codeCost")}</p>
        </ConfirmPanel>
      )}
      {msg && (
        <p role="alert" className="text-destructive" data-testid="failure">
          {t(msg.key, msg.params)}
        </p>
      )}
    </div>
  );
}
