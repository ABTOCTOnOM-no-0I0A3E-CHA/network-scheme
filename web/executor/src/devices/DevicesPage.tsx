import { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@nms/shared/ui/card";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { CredentialForm } from "../credentials/CredentialForm";
import { Confirmation } from "./Confirmation";
import { KeyFlow } from "./KeyFlow";
import { ACTIONS, deviceList, issue, messageOf, type Challenge, type Device } from "./api";

type Flow = { kind: "register" } | { kind: "accept"; id: number } | { kind: "writes"; challenge: Challenge } | null;
const STATUSES = ["from_reset_unconfirmed", "writes_off", "writes_on"];

/*
 * Write device administration (Task 4b.9). Every read of the list costs one change TOTP code (the executor decides and
 * audits it), so the list is not refreshed on its own. Everything the executor says about a device is rendered as text.
 */
export function DevicesPage({ poster }: { poster: Poster }) {
  const { t, i18n } = useTranslation();
  const [devices, setDevices] = useState<Device[] | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [flow, setFlow] = useState<Flow>(null);
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  const load = async () => {
    if (!/^\d{6}$/.test(code)) return;
    const c = code;
    setCode(""); /* sent once, never again */
    setMsg(null);
    setNote(null);
    setBusy(true);
    const r = await poster.post("/x/devices", { code: c, params: {} }, deviceList);
    if (!alive.current) return;
    setBusy(false);
    if (r.ok) setDevices(r.value);
    else setMsg(messageOf(r.failure));
  };

  const finish = (m?: Message, ok?: boolean) => {
    setFlow(null);
    setMsg(m ?? null);
    setNote(ok ? "executor.devices.changed" : null);
    if (ok) setDevices(null); /* the list shown is stale now: reading it again costs a code */
  };

  const toggle = async (d: Device) => {
    setMsg(null);
    setNote(null);
    setBusy(true);
    const o = await issue(poster, ACTIONS.writes, { device_id: d.device_id, enabled: !d.writes_enabled });
    if (!alive.current) return;
    setBusy(false);
    if (o.ok) setFlow({ kind: "writes", challenge: o.value });
    else setMsg(o.msg);
  };

  const statusText = (s: string) => (STATUSES.includes(s) ? t(`executor.devices.status.${s}`) : t("executor.devices.status.unknown"));
  const gateText = (g?: string) => (g === undefined ? t("executor.devices.gate.hostSide") : i18n.exists(`executor.devices.gate.${g}`) ? t(`executor.devices.gate.${g}`) : t("executor.devices.gate.unknown"));

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>{t("executor.devices.title")}</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          {!flow && (
            <>
              <p>{t("executor.devices.listCost")}</p>
              <label className="block">
                {t("executor.confirm.code")}
                <input className="block w-32 rounded border px-2 py-1" id="dl-code" name="dl-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code}
                  onChange={(e) => setCode(e.target.value)} />
              </label>
              <div className="flex gap-2">
                <Button type="button" disabled={busy || !/^\d{6}$/.test(code)} onClick={() => void load()}>
                  {t("executor.devices.load")}
                </Button>
                <Button type="button" variant="outline" disabled={busy} onClick={() => setFlow({ kind: "register" })}>
                  {t("executor.devices.register")}
                </Button>
              </div>
            </>
          )}
          {note && <p data-testid="changed">{t(note)}</p>}
          {msg && (
            <p role="alert" className="text-destructive" data-testid="failure">
              {t(msg.key, msg.params)}
            </p>
          )}
          {flow?.kind === "register" && <KeyFlow poster={poster} kind="register" onFinished={finish} />}
          {flow?.kind === "accept" && <KeyFlow poster={poster} kind="accept_hostkey" deviceId={flow.id} onFinished={finish} />}
          {flow?.kind === "writes" && <Confirmation poster={poster} challenge={flow.challenge} onDone={() => finish(undefined, true)} onClose={(m) => finish(m)} />}
          {!flow && devices && devices.length === 0 && <p>{t("executor.devices.empty")}</p>}
          {!flow &&
            devices?.map((d) => (
              <div key={d.device_id} className="space-y-1 rounded border p-2" data-testid={`device-${d.device_id}`}>
                <p className="font-semibold">{t("executor.devices.row", { id: d.device_id, address: d.address, port: d.port })}</p>
                <dl className="grid grid-cols-[auto_1fr] gap-x-3">
                  <dt>{t("executor.devices.field.status")}</dt>
                  <dd data-testid="status">{statusText(d.status)}</dd>
                  <dt>{t("executor.devices.field.model_gate")}</dt>
                  <dd data-testid="gate">{gateText(d.model_gate)}</dd>
                  <dt>{t("executor.devices.field.writes_enabled")}</dt>
                  <dd data-testid="writes">{t(d.writes_enabled ? "executor.devices.on" : "executor.devices.off")}</dd>
                  <dt>{t("executor.devices.field.write_driver")}</dt>
                  <dd>{d.write_driver}</dd>
                  <dt>{t("executor.devices.field.write_group")}</dt>
                  <dd>{d.write_group}</dd>
                  <dt>{t("executor.devices.field.hostkey_algo")}</dt>
                  <dd className="break-all">{d.hostkey_algo ?? t("executor.devices.none")}</dd>
                  <dt>{t("executor.devices.field.hostkey_fp")}</dt>
                  <dd className="break-all">{d.hostkey_fp ?? t("executor.devices.none")}</dd>
                </dl>
                <div className="flex gap-2">
                  <Button type="button" variant="outline" disabled={busy} onClick={() => setFlow({ kind: "accept", id: d.device_id })}>
                    {t("executor.devices.accept")}
                  </Button>
                  <Button type="button" variant="outline" disabled={busy || (!d.writes_enabled && !d.hostkey_fp)} onClick={() => void toggle(d)}>
                    {t(d.writes_enabled ? "executor.devices.disableWrites" : "executor.devices.enableWrites")}
                  </Button>
                </div>
              </div>
            ))}
        </CardContent>
      </Card>
      <CredentialForm poster={poster} />
    </div>
  );
}
