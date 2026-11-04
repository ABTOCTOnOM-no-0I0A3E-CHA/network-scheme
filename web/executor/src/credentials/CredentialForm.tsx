import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { z } from "zod";
import { Button } from "@nms/shared/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@nms/shared/ui/card";
import { getKeys, type Poster } from "../client";
import { codeSpent, failureMessage, type Failure, type Message } from "../errors";
import { useUnobscured } from "../useUnobscured";
import { checkWriteSecret, parseWriteKey, sealWriteCredential, type WriteKey } from "./writeKey";

/* The action of cmd/executor/internal/wcreds. */
export const ACTION = "credential.set";

const challenge = z.object({
  challenge_id: z.string().max(64),
  action: z.literal(ACTION),
  h: z.string().regex(/^[0-9a-f]{64}$/),
  fields: z.array(z.object({ key: z.string().max(64), value: z.string() })).max(256),
  expires: z.string(),
});
type Challenge = z.infer<typeof challenge>;
const stored = z.object({
  action: z.literal(ACTION),
  result: z.object({ device_id: z.number(), created_at: z.string(), method: z.string().max(64) }),
});

/* What the executor tells before the code (only its registry: the ciphertext is covered by H but never shown). */
const SHOWN = ["device_id", "address"] as const;
/* Refusal codes of wcreds (422) with a text of their own. */
const REFUSALS = ["malformed", "denied", "not_registered", "changed", "mismatch", "stale", "replay", "weak", "key_type"];

function messageOf(f: Failure): Message {
  if (f.kind === "http" && f.status === 422 && REFUSALS.includes(f.code)) return { key: `executor.credentials.refused.${f.code}` };
  if (f.kind === "http" && f.status === 503 && f.code === "outcome_unknown") return { key: "executor.credentials.outcomeUnknown" };
  if (f.kind === "http" && f.status === 400) return { key: "executor.credentials.refused.malformed" };
  return failureMessage(f);
}

const field = (c: Challenge, k: string) => c.fields.find((f) => f.key === k)?.value;

/*
 * Write credential of one registered device (Task 4b.4): sealed in the browser to the write-domain key of this
 * origin's keys.json, stored after the write-admin's change TOTP. The fingerprint shown is the anchor: the
 * administrator compares it with the one nmsctl printed at install, and the executor's own fingerprint in the
 * challenge must equal it or nothing is confirmed.
 *
 * No <form> and no username/password pair: the browser's password manager must not offer to save the write password.
 * The secret is held only in component state and dropped as soon as it is sealed; nothing is stored in the browser and
 * nothing of a stored credential is shown again. Every request takes a fresh ticket (Poster); a code once sent is
 * never sent again.
 */
export function CredentialForm({ poster }: { poster: Poster }) {
  const { t } = useTranslation();
  const [key, setKey] = useState<WriteKey | null>(null);
  const [keyFailed, setKeyFailed] = useState(false);
  const [deviceId, setDeviceId] = useState("");
  const [account, setAccount] = useState("");
  const [method, setMethod] = useState<"password" | "private_key">("password");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState<Challenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [done, setDone] = useState<{ device: number; at: string; method: string } | null>(null);
  const { ref, unobscured, supported } = useUnobscured();
  const visible = useRef(false);
  useEffect(() => {
    visible.current = unobscured;
  }, [unobscured]);

  useEffect(() => {
    const ac = new AbortController();
    void getKeys(ac.signal).then((r) => {
      if (ac.signal.aborted) return;
      try {
        if (!r.ok) throw new Error("keys");
        setKey(parseWriteKey(r.value));
      } catch {
        setKeyFailed(true);
      }
    });
    return () => ac.abort();
  }, []);

  const seal = async () => {
    setMsg(null);
    setDone(null);
    const id = Number(deviceId);
    if (!key || !/^[1-9]\d{0,17}$/.test(deviceId) || !Number.isSafeInteger(id)) return setMsg({ key: "executor.credentials.badDevice" });
    const s = method === "password" ? { username: account, password: secret } : { username: account, private_key: secret };
    const problem = checkWriteSecret(s);
    if (problem) return setMsg({ key: `executor.credentials.problem.${problem.problem}` });
    let ciphertext: string;
    try {
      ciphertext = sealWriteCredential(key, id, s);
    } catch {
      return setMsg({ key: "executor.credentials.refused.malformed" });
    }
    setSecret(""); /* sealed: the plaintext is no longer needed */
    setBusy(true);
    const r = await poster.post("/x/confirm/issue", { action: ACTION, params: { device_id: id, ciphertext } }, challenge);
    setBusy(false);
    if (!r.ok) return setMsg(messageOf(r.failure));
    /* the executor opens with the key whose fingerprint it states: it must be the one this page sealed to */
    if (field(r.value, "write_key") !== key.fingerprint || field(r.value, "device_id") !== deviceId) return setMsg({ key: "executor.credentials.keyMismatch" });
    setPending(r.value);
  };

  const confirm = async () => {
    /* re-checked at the click: the observer's last answer, not the rendered one */
    if (!pending || !visible.current || !/^\d{6}$/.test(code)) return;
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/confirm", { challenge_id: pending.challenge_id, h: pending.h, code }, stored);
    setBusy(false);
    if (r.ok) {
      setPending(null);
      setCode("");
      setDeviceId("");
      setAccount("");
      setDone({ device: r.value.result.device_id, at: r.value.result.created_at, method: r.value.result.method });
      return;
    }
    /* a sent code may be spent: ask for the next one, never resend this one */
    if (codeSpent(r.failure)) setCode("");
    const f = r.failure;
    /* refused, or the executor failed (5xx: the challenge may be spent, the outcome unknown): start again */
    if (f.kind === "http" && (f.status === 422 || f.status >= 500 || f.code === "denied")) setPending(null);
    setMsg(messageOf(f));
  };

  const cancel = () => {
    setPending(null);
    setCode("");
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("executor.credentials.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        {key && (
          <p data-testid="write-key">
            {t("executor.credentials.key", { fp: key.fingerprint })} {t("executor.credentials.keyAnchor")}
          </p>
        )}
        {keyFailed && <p role="alert">{t("executor.credentials.noKey")}</p>}
        {!pending && (
          <div className="space-y-2" data-testid="entry">
            <label className="block">
              {t("executor.credentials.device")}
              <input className="block w-full rounded border px-2 py-1" id="wc-device" name="wc-device" inputMode="numeric" autoComplete="off"
                value={deviceId} onChange={(e) => setDeviceId(e.target.value)} />
            </label>
            <label className="block">
              {t("executor.credentials.username")}
              <input className="block w-full rounded border px-2 py-1" id="wc-account" name="wc-account" autoComplete="off" spellCheck={false}
                value={account} onChange={(e) => setAccount(e.target.value)} />
            </label>
            <fieldset className="flex gap-4">
              <legend className="sr-only">{t("executor.credentials.method")}</legend>
              {(["password", "private_key"] as const).map((m) => (
                <label key={m}>
                  <input type="radio" name="wc-method" checked={method === m} onChange={() => setMethod(m)} /> {t(`executor.credentials.${m}`)}
                </label>
              ))}
            </fieldset>
            <label className="block">
              {t(`executor.credentials.${method}`)}
              {method === "password" ? (
                <input type="password" className="block w-full rounded border px-2 py-1" id="wc-secret" name="wc-secret" autoComplete="off"
                  value={secret} onChange={(e) => setSecret(e.target.value)} />
              ) : (
                <textarea className="block w-full rounded border px-2 py-1 font-mono" id="wc-secret" name="wc-secret" rows={6} autoComplete="off"
                  spellCheck={false} value={secret} onChange={(e) => setSecret(e.target.value)} />
              )}
            </label>
            <Button type="button" disabled={!key || busy} onClick={() => void seal()}>
              {t("executor.credentials.seal")}
            </Button>
          </div>
        )}
        {pending && (
          <div ref={ref} className="space-y-2" data-testid="confirm">
            <p className="font-semibold">{t("executor.credentials.confirmTitle")}</p>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3">
              {SHOWN.map((k) => {
                const v = field(pending, k);
                return v === undefined ? null : [<dt key={`${k}-k`}>{t(`executor.credentials.field.${k}`)}</dt>, <dd key={`${k}-v`}>{v}</dd>];
              })}
            </dl>
            <p className="font-mono text-base break-all" data-testid="h">
              H: {pending.h}
            </p>
            <label className="block">
              {t("executor.credentials.code")}
              <input className="block w-32 rounded border px-2 py-1" id="wc-code" name="wc-code" inputMode="numeric" maxLength={6} autoComplete="off"
                value={code} onChange={(e) => setCode(e.target.value)} />
            </label>
            {!unobscured && <p role="alert">{t(supported ? "executor.obscured" : "executor.visibilityUnsupported")}</p>}
            <div className="flex gap-2">
              <Button type="button" disabled={busy || !unobscured || !/^\d{6}$/.test(code)} onClick={() => void confirm()}>
                {t("executor.credentials.confirm")}
              </Button>
              <Button type="button" variant="outline" onClick={cancel} disabled={busy}>
                {t("executor.credentials.cancel")}
              </Button>
            </div>
          </div>
        )}
        {done && <p data-testid="done">{t("executor.credentials.saved", { device: done.device, at: done.at, method: done.method })}</p>}
        {msg && (
          <p role="alert" className="text-destructive" data-testid="failure">
            {t(msg.key, msg.params)}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
