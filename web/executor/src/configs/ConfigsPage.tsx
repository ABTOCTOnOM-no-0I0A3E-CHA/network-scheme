import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@nms/shared/ui/card";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { ConfirmPanel, type ShownField } from "../ConfirmPanel";
import {
  ACTION_EXPORT, ACTION_VIEW, MAX_CONFIG, challengeSchema, listAnswer, matches, messageOf, saveText, shownAnswer,
  type Challenge, type ConfigAction, type Shown, type Version,
} from "./api";

type Pending = { action: ConfigAction; version: Version; challenge: Challenge };

/*
 * Unmasked configurations (Task 4d.1): a device's versions (one change TOTP code), then a version shown or exported,
 * each confirmed with confirm(H) over (device, version) and the next code in the gated ConfirmPanel. Every field of
 * the executor's description is shown. The configuration is device data: rendered as text only; the export is the
 * executor's text saved as a file (fetched with a ticket and the code in the body, never in a URL or a cookie).
 */
export function ConfigsPage({ poster, save = saveText }: { poster: Poster; save?: (name: string, body: string) => void }) {
  const { t, i18n } = useTranslation();
  const [device, setDevice] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [versions, setVersions] = useState<Version[] | null>(null);
  const [pending, setPending] = useState<Pending | null>(null);
  const [shown, setShown] = useState<Shown | null>(null);
  const [saved, setSaved] = useState(false);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const load = async () => {
    if (!/^\d{6}$/.test(code) || !/^\d{1,18}$/.test(device)) return;
    const c = code;
    setCode(""); /* sent once, never again */
    setMsg(null);
    setBusy(true);
    const r = await poster.post("/x/configs", { code: c, params: { device_id: Number(device) } }, listAnswer);
    if (!alive.current) return;
    setBusy(false);
    if (r.ok) setVersions(r.value.result);
    else setMsg(messageOf(r.failure));
  };

  const ask = async (action: ConfigAction, version: Version) => {
    setMsg(null);
    setShown(null);
    setSaved(false);
    setBusy(true);
    const r = await poster.post("/x/confirm/issue", { action, params: { device_id: version.device_id, version_id: version.version_id } }, challengeSchema);
    if (!alive.current) return;
    setBusy(false);
    if (!r.ok) return setMsg(messageOf(r.failure));
    if (!matches(r.value, action, version)) return setMsg({ key: "executor.configs.mismatch" });
    setPending({ action, version, challenge: r.value });
  };

  const confirm = async (c: string) => {
    if (!pending) return;
    const { action, version, challenge } = pending;
    const path = `${version.device_id}/${version.version_id}`;
    const body = { challenge_id: challenge.challenge_id, h: challenge.h, code: c };
    setMsg(null);
    setBusy(true);
    if (action === ACTION_VIEW) {
      const r = await poster.post(`/x/configs/${path}`, body, shownAnswer);
      if (!alive.current) return;
      setBusy(false);
      setPending(null); /* the challenge is spent whatever the answer: start again */
      if (r.ok) setShown(r.value.result);
      else setMsg(messageOf(r.failure));
      return;
    }
    const r = await poster.download(`/x/download/configs/${path}`, body, MAX_CONFIG);
    if (!alive.current) return;
    setBusy(false);
    setPending(null);
    if (!r.ok) return setMsg(messageOf(r.failure));
    save(`config-${version.device_id}-${version.version_id}.txt`, r.value);
    setSaved(true);
  };

  const label = (k: string) => (i18n.exists(`executor.configs.field.${k}`) ? t(`executor.configs.field.${k}`) : k);
  const fields: ShownField[] = pending ? pending.challenge.fields.map((f) => ({ key: f.key, label: label(f.key), value: f.value })) : [];
  const input = "mt-1 block h-9 w-36 rounded-md border bg-background px-3 font-normal outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("executor.configs.title")}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3 text-sm">
        <p className="text-muted-foreground">{t("executor.configs.cost")}</p>
        <div className="flex flex-wrap gap-3">
          <label className="block font-medium">
            {t("executor.configs.device")}
            <input className={input} name="cfg-device" inputMode="numeric" maxLength={18} autoComplete="off" value={device} onChange={(e) => setDevice(e.target.value)} />
          </label>
          <label className="block font-medium">
            {t("executor.confirm.code")}
            <input className={input} name="cfg-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code} onChange={(e) => setCode(e.target.value)} />
          </label>
        </div>
        <Button type="button" disabled={busy || !/^\d{6}$/.test(code) || !/^\d{1,18}$/.test(device)} onClick={() => void load()}>
          {t("executor.configs.load")}
        </Button>
        {msg && (
          <p role="alert" className="text-destructive" data-testid="failure">
            {t(msg.key, msg.params)}
          </p>
        )}
        {versions && versions.length === 0 && <p>{t("executor.configs.empty")}</p>}
        {versions && versions.length > 0 && !pending && (
          <ul className="space-y-1">
            {versions.map((v) => (
              <li key={v.version_id} className="flex flex-wrap items-center gap-2" data-testid={`version-${v.version_id}`}>
                <span>{t("executor.configs.row", { id: v.version_id, taken: v.taken_at, source: v.source, size: v.size })}</span>
                <span className="font-mono text-xs">{v.sha256.slice(0, 16)}</span>
                <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void ask(ACTION_VIEW, v)}>
                  {t("executor.configs.view")}
                </Button>
                <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void ask(ACTION_EXPORT, v)}>
                  {t("executor.configs.export")}
                </Button>
              </li>
            ))}
          </ul>
        )}
        {pending && (
          <ConfirmPanel title={t(pending.action === ACTION_VIEW ? "executor.configs.confirmView" : "executor.configs.confirmExport")}
            fields={fields} h={pending.challenge.h} confirmLabel={t("executor.configs.confirm")} busy={busy}
            onConfirm={(c) => void confirm(c)} onCancel={() => setPending(null)}>
            <p>{t("executor.configs.audited")}</p>
          </ConfirmPanel>
        )}
        {saved && <p data-testid="saved">{t("executor.configs.saved")}</p>}
        {shown && (
          <div className="space-y-2" data-testid="shown">
            <p>{t("executor.configs.shown", { id: shown.version_id, device: shown.device_id, taken: shown.taken_at })}</p>
            <p className="font-mono text-xs break-all">sha256: {shown.sha256}</p>
            <pre className="max-h-[60vh] overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs whitespace-pre" data-testid="config-text">
              {shown.text}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
