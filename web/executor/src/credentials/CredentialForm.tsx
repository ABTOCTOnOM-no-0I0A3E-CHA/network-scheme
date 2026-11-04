import { useEffect, useRef, useState, type FormEvent } from "react";
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
const stored = z.object({ action: z.literal(ACTION), result: z.object({ device_id: z.number(), created_at: z.string() }) });

/* Fields of the description shown for confirmation; the ciphertext is covered by H but never shown. */
const SHOWN = ["device_id", "address", "driver", "username", "method", "created_at", "replaces"] as const;
/* Refusal codes of wcreds (422) with a text of their own. */
const REFUSALS = ["malformed", "denied", "not_registered", "mismatch", "stale", "replay", "weak", "key_type"];

function messageOf(f: Failure): Message {
  if (f.kind === "http" && f.status === 422 && REFUSALS.includes(f.code)) return { key: `executor.credentials.refused.${f.code}` };
  if (f.kind === "http" && f.status === 400) return { key: "executor.credentials.refused.malformed" };
  return failureMessage(f);
}

/*
 * Write credential of one registered device (Task 4b.4): sealed in the browser to the write-domain key of this
 * origin's keys.json, described by the executor, stored after the write-admin's change TOTP. The secret is held only
 * in component state and dropped as soon as it is sealed; nothing is stored in the browser and nothing of a stored
 * credential is ever shown again. Every request takes a fresh ticket (Poster); a code once sent is never sent again.
 */
export function CredentialForm({ poster }: { poster: Poster }) {
  const { t } = useTranslation();
  const [key, setKey] = useState<WriteKey | null>(null);
  const [keyFailed, setKeyFailed] = useState(false);
  const [deviceId, setDeviceId] = useState("");
  const [username, setUsername] = useState("");
  const [method, setMethod] = useState<"password" | "private_key">("password");
  const [secret, setSecret] = useState("");
  const [code, setCode] = useState("");
  const [pending, setPending] = useState<Challenge | null>(null);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [done, setDone] = useState<{ device: number; at: string } | null>(null);
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

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setMsg(null);
    setDone(null);
    const id = Number(deviceId);
    if (!key || !/^[1-9]\d{0,17}$/.test(deviceId) || !Number.isSafeInteger(id)) return setMsg({ key: "executor.credentials.badDevice" });
    const s = method === "password" ? { username, password: secret } : { username, private_key: secret };
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
    setPending(r.value);
  };

  const confirm = async (e: FormEvent) => {
    e.preventDefault();
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
      setUsername("");
      setDone({ device: r.value.result.device_id, at: r.value.result.created_at });
      return;
    }
    /* a sent code may be spent: ask for the next one, never resend this one */
    if (codeSpent(r.failure)) setCode("");
    const f = r.failure;
    if (f.kind === "http" && (f.status === 422 || f.code === "denied")) setPending(null);
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
        {key && <p data-testid="write-key">{t("executor.credentials.key", { fp: key.fingerprint })}</p>}
        {keyFailed && <p role="alert">{t("executor.credentials.noKey")}</p>}
        {!pending && (
          <form className="space-y-2" onSubmit={(e) => void submit(e)} autoComplete="off">
            <label className="block">
              {t("executor.credentials.device")}
              <input className="block w-full rounded border px-2 py-1" inputMode="numeric" value={deviceId} onChange={(e) => setDeviceId(e.target.value)} />
            </label>
            <label className="block">
              {t("executor.credentials.username")}
              <input className="block w-full rounded border px-2 py-1" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" />
            </label>
            <fieldset className="flex gap-4">
              <legend className="sr-only">{t("executor.credentials.method")}</legend>
              {(["password", "private_key"] as const).map((m) => (
                <label key={m}>
                  <input type="radio" name="method" checked={method === m} onChange={() => setMethod(m)} /> {t(`executor.credentials.${m}`)}
                </label>
              ))}
            </fieldset>
            <label className="block">
              {t(`executor.credentials.${method}`)}
              {method === "password" ? (
                <input type="password" className="block w-full rounded border px-2 py-1" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="new-password" />
              ) : (
                <textarea className="block w-full rounded border px-2 py-1 font-mono" rows={6} value={secret} onChange={(e) => setSecret(e.target.value)} spellCheck={false} />
              )}
            </label>
            <Button type="submit" disabled={!key || busy}>
              {t("executor.credentials.seal")}
            </Button>
          </form>
        )}
        {pending && (
          <form ref={ref} className="space-y-2" onSubmit={(e) => void confirm(e)} autoComplete="off" data-testid="confirm">
            <p className="font-semibold">{t("executor.credentials.confirmTitle")}</p>
            <dl className="grid grid-cols-[auto_1fr] gap-x-3">
              {SHOWN.map((k) => {
                const v = pending.fields.find((f) => f.key === k)?.value;
                return v === undefined ? null : [<dt key={`${k}-k`}>{t(`executor.credentials.field.${k}`)}</dt>, <dd key={`${k}-v`}>{v}</dd>];
              })}
            </dl>
            <p className="font-mono text-base break-all" data-testid="h">
              H: {pending.h}
            </p>
            <label className="block">
              {t("executor.credentials.code")}
              <input className="block w-32 rounded border px-2 py-1" inputMode="numeric" maxLength={6} value={code} onChange={(e) => setCode(e.target.value)} autoComplete="one-time-code" />
            </label>
            {!unobscured && <p role="alert">{t(supported ? "executor.obscured" : "executor.visibilityUnsupported")}</p>}
            <div className="flex gap-2">
              <Button type="submit" disabled={busy || !unobscured || !/^\d{6}$/.test(code)}>
                {t("executor.credentials.confirm")}
              </Button>
              <Button type="button" variant="outline" onClick={cancel} disabled={busy}>
                {t("executor.credentials.cancel")}
              </Button>
            </div>
          </form>
        )}
        {done && <p data-testid="done">{t("executor.credentials.saved", { device: done.device, at: done.at })}</p>}
        {msg && (
          <p role="alert" className="text-destructive" data-testid="failure">
            {t(msg.key, msg.params)}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
