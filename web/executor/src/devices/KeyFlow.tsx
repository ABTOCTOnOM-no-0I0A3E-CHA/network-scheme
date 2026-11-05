import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Poster } from "../client";
import type { Message } from "../errors";
import { Confirmation } from "./Confirmation";
import { ACTIONS, DRIVERS, issue, messageOf, shownFields, type Challenge } from "./api";

type Kind = "register" | "accept_hostkey";
const ACTION = { register: ACTIONS.register, accept_hostkey: ACTIONS.accept } as const;

/*
 * Registration of a device, or acceptance of its changed host key: the probe reads the key (one TOTP code), the
 * executor then describes the very same target and key, and the administrator confirms with the next code. The
 * description must equal what the probe showed. Entry fields are plain controls (no <form>, autocomplete off).
 */
export function KeyFlow({ poster, kind, deviceId, onFinished }: { poster: Poster; kind: Kind; deviceId?: number; onFinished: (m?: Message, ok?: boolean) => void }) {
  const { t } = useTranslation();
  const [id, setId] = useState(deviceId === undefined ? "" : String(deviceId));
  const [address, setAddress] = useState("");
  const [port, setPort] = useState("");
  const [group, setGroup] = useState("");
  const [driver, setDriver] = useState<(typeof DRIVERS)[number]>("mes6");
  const [sha1, setSha1] = useState(false);
  const [backup, setBackup] = useState(false);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<Message | null>(null);
  const [challenge, setChallenge] = useState<Challenge | null>(null);

  const probe = async () => {
    setMsg(null);
    const n = Number(id);
    if (!/^[1-9]\d{0,17}$/.test(id) || !Number.isSafeInteger(n)) return setMsg({ key: "executor.devices.badDevice" });
    const params: Record<string, unknown> = { device_id: n };
    if (address.trim() !== "") params.address = address.trim();
    if (port.trim() !== "") {
      if (!/^\d{1,5}$/.test(port.trim())) return setMsg({ key: "executor.devices.badPort" });
      params.port = Number(port);
    }
    if (kind === "register") {
      if (group.trim() === "") return setMsg({ key: "executor.devices.badGroup" });
      Object.assign(params, { write_group: group.trim(), write_driver: driver, allow_ssh_rsa_sha1: sha1, backup_via_executor: backup });
    }
    if (!/^\d{6}$/.test(code)) return;
    const c = code;
    setCode(""); /* sent once, never again */
    setBusy(true);
    const r = await poster.post("/x/devices/probe", { code: c, params: { kind, ...params } }, shownFields);
    if (!r.ok) {
      setBusy(false);
      return setMsg(messageOf(r.failure));
    }
    const f = r.value;
    if (!f.hostkey_algo || f.hostkey_algo === "none" || !f.hostkey_fp || f.hostkey_fp === "none") {
      setBusy(false);
      return setMsg({ key: "executor.devices.noKey" });
    }
    const o = await issue(poster, ACTION[kind], { ...params, hostkey_algo: f.hostkey_algo, hostkey_fp: f.hostkey_fp }, f);
    setBusy(false);
    if (!o.ok) return setMsg(o.msg);
    setChallenge(o.value);
  };

  if (challenge) {
    return <Confirmation poster={poster} challenge={challenge} onDone={() => onFinished(undefined, true)} onClose={(m) => onFinished(m)} />;
  }
  const input = "block w-full rounded border px-2 py-1";
  return (
    <div className="space-y-2" data-testid="keyflow">
      <p className="font-semibold">{t(kind === "register" ? "executor.devices.registerTitle" : "executor.devices.acceptTitle")}</p>
      <p>{t("executor.devices.probeCost")}</p>
      <label className="block">
        {t("executor.devices.field.device")}
        <input className={input} id="kf-device" name="kf-device" inputMode="numeric" autoComplete="off" value={id} readOnly={deviceId !== undefined}
          onChange={(e) => setId(e.target.value)} />
      </label>
      <label className="block">
        {t("executor.devices.field.address")}
        <input className={input} id="kf-address" name="kf-address" autoComplete="off" spellCheck={false} value={address} onChange={(e) => setAddress(e.target.value)} />
      </label>
      <label className="block">
        {t("executor.devices.field.port")}
        <input className={input} id="kf-port" name="kf-port" inputMode="numeric" autoComplete="off" value={port} onChange={(e) => setPort(e.target.value)} />
      </label>
      {kind === "register" && (
        <>
          <label className="block">
            {t("executor.devices.field.write_group")}
            <input className={input} id="kf-group" name="kf-group" autoComplete="off" spellCheck={false} value={group} onChange={(e) => setGroup(e.target.value)} />
          </label>
          <label className="block">
            {t("executor.devices.field.write_driver")}
            <select className={input} id="kf-driver" name="kf-driver" value={driver} onChange={(e) => setDriver(e.target.value as (typeof DRIVERS)[number])}>
              {DRIVERS.map((d) => (
                <option key={d} value={d}>
                  {d}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <input type="checkbox" checked={sha1} onChange={(e) => setSha1(e.target.checked)} /> {t("executor.devices.field.allow_ssh_rsa_sha1")}
          </label>
          <label className="block">
            <input type="checkbox" checked={backup} onChange={(e) => setBackup(e.target.checked)} /> {t("executor.devices.field.backup_via_executor")}
          </label>
        </>
      )}
      <label className="block">
        {t("executor.confirm.code")}
        <input className="block w-32 rounded border px-2 py-1" id="kf-code" name="kf-code" inputMode="numeric" maxLength={6} autoComplete="off" value={code}
          onChange={(e) => setCode(e.target.value)} />
      </label>
      <div className="flex gap-2">
        <Button type="button" disabled={busy || !/^\d{6}$/.test(code)} onClick={() => void probe()}>
          {t("executor.devices.probe")}
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={() => onFinished()}>
          {t("executor.confirm.cancel")}
        </Button>
      </div>
      {msg && (
        <p role="alert" className="text-destructive" data-testid="failure">
          {t(msg.key, msg.params)}
        </p>
      )}
    </div>
  );
}
