import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import type { Failure, Message } from "../errors";
import { Alert } from "../session/Dialog";
import { EMPTY_FORM, FORMS, type FormField } from "../session/api";
import { devicesAnswer, messageOf, op, savedAnswer, variablesOf, versionsAnswer, workspaceGone, type Content, type Detail, type FormParams, type Version, type Writable } from "./api";
import { input, section, when } from "./parts";

type Props = {
  token: string;
  kind: "lines" | "restore";
  /* the changeset being revised (its newest revision), or a new one */
  initial?: Detail;
  /* a new restore's first items (the panel's "Восстановить", an interrupted run's pre_session versions) */
  restore?: { device: number; version: number }[];
  onSaved: (id: string) => void;
  onCancel: () => void;
  onGone: () => void;
};

type StepDraft = { line: string } | { form: FormParams };

/* The failure and what it is about (device, step, the executor's reason), as text. */
export function FailureView({ f }: { f: { msg: Message; failure?: Failure } }) {
  const { t } = useTranslation();
  const d = f.failure?.kind === "http" ? f.failure.detail : undefined;
  return (
    <Alert testId="failure">
      {t(f.msg.key, f.msg.params)}
      {d && (d.device_id > 0 || d.step > 0 || d.reason) && (
        <span className="mt-1 block font-mono text-xs" data-testid="failure-detail">
          {[d.device_id > 0 ? t("executor.changesets.deviceShort", { id: d.device_id }) : "", d.step > 0 ? t("executor.changesets.stepN", { n: d.step }) : "", d.reason]
            .filter(Boolean)
            .join(" · ")}
        </span>
      )}
    </Alert>
  );
}

/*
 * The draft editor (Task 5.8): devices only from the executor's registry the user may write to now (op devices: writable,
 * a write grant on the group), in the order of the run (the first is the canary); a lines changeset's steps are lines
 * typed from the privileged prompt or GUI forms the device's driver renders (the equivalent commands of every device are
 * in the dry-run); {{name}} placeholders are set per device; a restore changeset names one backup version per device.
 * Saving stores a new revision: approvals of the old one are dropped by the executor.
 */
export function Editor(p: Props) {
  const { t } = useTranslation();
  const c = p.initial?.content;
  const [title, setTitle] = useState(c?.title ?? (p.restore ? t("executor.changesets.editor.restoreTitle", { ids: p.restore.map((r) => `#${r.device}`).join(", ") }) : ""));
  const [devices, setDevices] = useState<number[]>(c?.device_ids ?? p.restore?.map((r) => r.device) ?? []);
  const [steps, setSteps] = useState<StepDraft[]>(() => c?.steps?.map((s) => (s.form ? { form: s.form } : { line: s.line ?? "" })) ?? [{ line: "" }]);
  const [vars, setVars] = useState<Record<string, Record<string, string>>>(c?.vars ?? {});
  const [versions, setVersions] = useState<Record<number, number>>(() =>
    Object.fromEntries((c?.restore ?? []).map((r) => [r.device_id, r.version_id]).concat((p.restore ?? []).map((r) => [r.device, r.version]))),
  );
  const [batch, setBatch] = useState(String(c?.batch_size ?? 5));
  const [settle, setSettle] = useState(String(c?.settle_s ?? 30));
  const [writable, setWritable] = useState<Writable[] | null>(null);
  const [filter, setFilter] = useState("");
  const [bulk, setBulk] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [fail, setFail] = useState<{ msg: Message; failure?: Failure } | null>(null);
  const { token, onGone } = p;

  useEffect(() => {
    let live = true;
    void op(token, "devices", {}, devicesAnswer).then((r) => {
      if (!live) return;
      if (r.ok) setWritable(r.value.result);
      else if (workspaceGone(r.failure)) onGone();
      else setFail({ msg: messageOf(r.failure), failure: r.failure });
    });
    return () => {
      live = false;
    };
  }, [token, onGone]);

  const byId = useMemo(() => new Map((writable ?? []).map((d) => [d.device_id, d])), [writable]);
  const names = variablesOf(steps.map((s) => ("line" in s ? { line: s.line } : {})));
  const toggle = (id: number) => setDevices((ds) => (ds.includes(id) ? ds.filter((x) => x !== id) : [...ds, id]));
  const move = (i: number, by: number) =>
    setDevices((ds) => {
      const j = i + by;
      if (j < 0 || j >= ds.length) return ds;
      const n = [...ds];
      [n[i], n[j]] = [n[j], n[i]];
      return n;
    });
  const setStep = (i: number, s: StepDraft) => setSteps((ss) => ss.map((x, k) => (k === i ? s : x)));
  const moveStep = (i: number, by: number) =>
    setSteps((ss) => {
      const j = i + by;
      if (j < 0 || j >= ss.length) return ss;
      const n = [...ss];
      [n[i], n[j]] = [n[j], n[i]];
      return n;
    });

  const content = (): Content => {
    const base = { title: title.trim(), device_ids: devices, batch_size: Number(batch), settle_s: Number(settle) };
    if (p.kind === "restore") return { ...base, restore: devices.map((d) => ({ device_id: d, version_id: versions[d] ?? 0 })) };
    const lines = steps.filter((s) => !("line" in s) || s.line.trim() !== "").map((s) => ("line" in s ? { line: s.line.trim() } : { form: s.form }));
    const v = names.length === 0 ? undefined : Object.fromEntries(devices.map((d) => [String(d), Object.fromEntries(names.map((n) => [n, vars[d]?.[n] ?? ""]))]));
    return { ...base, steps: lines, ...(v ? { vars: v } : {}) };
  };

  const save = async () => {
    setFail(null);
    setBusy(true);
    const r = await op(p.token, "save", { changeset_id: p.initial?.changeset_id ?? "", revision: p.initial?.revision ?? 0, content: content() }, savedAnswer);
    setBusy(false);
    if (r.ok) return p.onSaved(r.value.result.changeset_id);
    if (workspaceGone(r.failure)) return p.onGone();
    setFail({ msg: messageOf(r.failure), failure: r.failure });
  };

  const okNums = /^\d{1,3}$/.test(batch) && /^\d{1,3}$/.test(settle);
  const ready = title.trim() !== "" && devices.length > 0 && okNums && (p.kind === "restore" ? devices.every((d) => versions[d] > 0) : steps.some((s) => !("line" in s) || s.line.trim() !== ""));
  const shown = (writable ?? []).filter((d) => filter === "" || `${d.device_id} ${d.address} ${d.write_group} ${d.line}`.toLowerCase().includes(filter.toLowerCase()));

  return (
    <div className="space-y-4" data-testid="cs-editor">
      <section className={section}>
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h2 className="text-base font-semibold">
            {t(p.initial ? "executor.changesets.editor.titleEdit" : p.kind === "restore" ? "executor.changesets.editor.titleRestore" : "executor.changesets.editor.titleNew")}
          </h2>
          {p.initial && <span className="font-mono text-xs text-muted-foreground">{t("executor.changesets.editor.fromRev", { rev: p.initial.revision })}</span>}
        </div>
        <label className="block text-sm font-medium">
          {t("executor.changesets.editor.name")}
          <input className={input} id="cs-title" name="cs-title" autoComplete="off" maxLength={120} value={title} onChange={(e) => setTitle(e.target.value)} />
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block text-sm font-medium">
            {t("executor.changesets.editor.batch")}
            <input className={`${input} max-w-28`} id="cs-batch" name="cs-batch" inputMode="numeric" maxLength={3} autoComplete="off" value={batch} onChange={(e) => setBatch(e.target.value)} />
            <span className="mt-1 block text-xs font-normal text-muted-foreground">{t("executor.changesets.editor.batchHint")}</span>
          </label>
          <label className="block text-sm font-medium">
            {t("executor.changesets.editor.settle")}
            <input className={`${input} max-w-28`} id="cs-settle" name="cs-settle" inputMode="numeric" maxLength={3} autoComplete="off" value={settle} onChange={(e) => setSettle(e.target.value)} />
            <span className="mt-1 block text-xs font-normal text-muted-foreground">{t("executor.changesets.editor.settleHint")}</span>
          </label>
        </div>
      </section>

      <section className={section}>
        <h3 className="text-sm font-semibold">{t("executor.changesets.editor.devices")}</h3>
        <p className="text-xs text-muted-foreground">{t("executor.changesets.editor.devicesHint")}</p>
        <div className="grid gap-4 lg:grid-cols-2">
          <div className="space-y-2">
            <input className={input} id="cs-filter" name="cs-filter" autoComplete="off" spellCheck={false} placeholder={t("executor.changesets.editor.filter")} value={filter}
              onChange={(e) => setFilter(e.target.value)} />
            {writable === null && <p className="text-sm text-muted-foreground">{t("executor.changesets.loading")}</p>}
            {writable && writable.length === 0 && <p className="text-sm">{t("executor.changesets.editor.noWritable")}</p>}
            {writable && writable.length > 0 && (
              <div className="max-h-72 overflow-auto rounded-lg border">
                <table className="w-full text-[13px]">
                  <thead className="sticky top-0 bg-muted text-left text-xs text-muted-foreground">
                    <tr>
                      <th className="w-8 px-2 py-1.5" />
                      <th className="px-2 py-1.5 font-medium">{t("executor.changesets.col.device")}</th>
                      <th className="px-2 py-1.5 font-medium">{t("executor.changesets.col.address")}</th>
                      <th className="px-2 py-1.5 font-medium">{t("executor.changesets.col.group")}</th>
                      <th className="px-2 py-1.5 font-medium">{t("executor.changesets.col.line")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((d) => (
                      <tr key={d.device_id} className="border-t hover:bg-muted/40">
                        <td className="px-2 py-1">
                          <input type="checkbox" aria-label={t("executor.changesets.deviceShort", { id: d.device_id })} data-testid={`pick-${d.device_id}`}
                            checked={devices.includes(d.device_id)} onChange={() => toggle(d.device_id)} />
                        </td>
                        <td className="px-2 py-1 font-medium">{d.device_id}</td>
                        <td className="px-2 py-1 font-mono">{d.address}</td>
                        <td className="px-2 py-1">{d.write_group}</td>
                        <td className="px-2 py-1 font-mono">{d.line}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
          <div className="space-y-2">
            <p className="text-sm font-medium">{t("executor.changesets.editor.order", { count: devices.length })}</p>
            {devices.length === 0 && <p className="text-sm text-muted-foreground">{t("executor.changesets.editor.noneChosen")}</p>}
            <ol className="space-y-1.5" data-testid="cs-order">
              {devices.map((d, i) => {
                const w = byId.get(d);
                return (
                  <li key={d} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5 text-[13px]">
                    <span className="w-6 text-right font-mono text-xs text-muted-foreground">{i + 1}</span>
                    <span className="font-medium">{t("executor.changesets.deviceShort", { id: d })}</span>
                    {w ? <span className="font-mono text-xs text-muted-foreground">{w.address} · {w.line}</span> : writable && <span className="text-xs text-destructive">{t("executor.changesets.editor.notWritable")}</span>}
                    {i === 0 && <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-xs font-medium text-amber-900 dark:text-amber-300">{t("executor.changesets.canary")}</span>}
                    {p.kind === "restore" && <VersionPicker token={p.token} device={d} value={versions[d]} onPick={(v) => setVersions((o) => ({ ...o, [d]: v }))} onGone={p.onGone} />}
                    <span className="ml-auto flex gap-1">
                      <Button type="button" size="xs" variant="ghost" aria-label={t("executor.changesets.editor.up")} disabled={i === 0} onClick={() => move(i, -1)}>
                        ↑
                      </Button>
                      <Button type="button" size="xs" variant="ghost" aria-label={t("executor.changesets.editor.down")} disabled={i === devices.length - 1} onClick={() => move(i, 1)}>
                        ↓
                      </Button>
                      <Button type="button" size="xs" variant="ghost" onClick={() => toggle(d)}>
                        {t("executor.changesets.editor.remove")}
                      </Button>
                    </span>
                  </li>
                );
              })}
            </ol>
          </div>
        </div>
      </section>

      {p.kind === "lines" && (
        <section className={section}>
          <h3 className="text-sm font-semibold">{t("executor.changesets.editor.steps")}</h3>
          <p className="text-xs text-muted-foreground">{t("executor.changesets.editor.stepsHint", { example: "{{port}}" })}</p>
          <ol className="space-y-2" data-testid="cs-steps">
            {steps.map((s, i) => (
              <li key={i} className="flex items-start gap-2">
                <span className="mt-2 w-6 text-right font-mono text-xs text-muted-foreground">{i + 1}</span>
                <div className="min-w-0 flex-1">
                  {"line" in s ? (
                    <input className={`${input} mt-0 font-mono`} aria-label={t("executor.changesets.stepN", { n: i + 1 })} name={`cs-step-${i}`} autoComplete="off" spellCheck={false}
                      maxLength={512} value={s.line} onChange={(e) => setStep(i, { line: e.target.value })} />
                  ) : (
                    <FormStep value={s.form} index={i} onChange={(f) => setStep(i, { form: f })} />
                  )}
                </div>
                <span className="mt-1 flex gap-1">
                  <Button type="button" size="xs" variant="ghost" aria-label={t("executor.changesets.editor.up")} disabled={i === 0} onClick={() => moveStep(i, -1)}>
                    ↑
                  </Button>
                  <Button type="button" size="xs" variant="ghost" aria-label={t("executor.changesets.editor.down")} disabled={i === steps.length - 1} onClick={() => moveStep(i, 1)}>
                    ↓
                  </Button>
                  <Button type="button" size="xs" variant="ghost" onClick={() => setSteps((ss) => ss.filter((_, k) => k !== i))}>
                    {t("executor.changesets.editor.remove")}
                  </Button>
                </span>
              </li>
            ))}
          </ol>
          <div className="flex flex-wrap gap-2">
            <Button type="button" size="sm" variant="outline" onClick={() => setSteps((ss) => [...ss, { line: "" }])}>
              {t("executor.changesets.editor.addLine")}
            </Button>
            <Button type="button" size="sm" variant="outline" onClick={() => setSteps((ss) => [...ss, { form: { ...EMPTY_FORM } }])}>
              {t("executor.changesets.editor.addForm")}
            </Button>
            <Button type="button" size="sm" variant="ghost" onClick={() => setBulk(bulk === null ? "" : null)}>
              {t("executor.changesets.editor.paste")}
            </Button>
          </div>
          {bulk !== null && (
            <div className="space-y-2">
              <textarea className="block h-32 w-full rounded-md border bg-background px-3 py-2 font-mono text-[13px] outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                name="cs-bulk" aria-label={t("executor.changesets.editor.paste")} autoComplete="off" spellCheck={false} value={bulk} onChange={(e) => setBulk(e.target.value)} />
              <Button type="button" size="sm" onClick={() => {
                const add = bulk.split(/\r?\n/).map((l) => l.trimEnd()).filter((l) => l.trim() !== "").map((line) => ({ line }));
                setSteps((ss) => [...ss.filter((x) => !("line" in x) || x.line.trim() !== ""), ...add]);
                setBulk(null);
              }}>
                {t("executor.changesets.editor.pasteAdd")}
              </Button>
            </div>
          )}
          {steps.some((s) => "form" in s) && <p className="text-xs text-muted-foreground">{t("executor.changesets.editor.formsNote")}</p>}
        </section>
      )}

      {p.kind === "lines" && names.length > 0 && devices.length > 0 && (
        <section className={section}>
          <h3 className="text-sm font-semibold">{t("executor.changesets.editor.vars")}</h3>
          <p className="text-xs text-muted-foreground">{t("executor.changesets.editor.varsHint")}</p>
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-[13px]" data-testid="cs-vars">
              <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
                <tr>
                  <th className="px-2 py-1.5 font-medium">{t("executor.changesets.col.device")}</th>
                  {names.map((n) => (
                    <th key={n} className="px-2 py-1.5 font-mono font-medium">{`{{${n}}}`}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d} className="border-t">
                    <td className="px-2 py-1 font-medium whitespace-nowrap">
                      {t("executor.changesets.deviceShort", { id: d })}
                      {byId.get(d) && <span className="ml-2 font-mono text-xs text-muted-foreground">{byId.get(d)?.line}</span>}
                    </td>
                    {names.map((n) => (
                      <td key={n} className="px-2 py-1">
                        <input className="block h-8 w-full min-w-28 rounded-md border bg-background px-2 font-mono text-[13px] outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
                          aria-label={`${n} ${d}`} name={`cs-var-${d}-${n}`} autoComplete="off" spellCheck={false} maxLength={128} value={vars[d]?.[n] ?? ""}
                          onChange={(e) => setVars((o) => ({ ...o, [d]: { ...o[d], [n]: e.target.value } }))} />
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {p.kind === "restore" && <Alert tone="info">{t("executor.changesets.editor.restoreNote")}</Alert>}
      {fail && <FailureView f={fail} />}
      <div className="flex flex-wrap gap-2">
        <Button type="button" disabled={busy || !ready} onClick={() => void save()} data-testid="cs-save">
          {t("executor.changesets.editor.save")}
        </Button>
        <Button type="button" variant="outline" disabled={busy} onClick={p.onCancel}>
          {t("executor.confirm.cancel")}
        </Button>
        {!ready && <span className="self-center text-xs text-muted-foreground">{t("executor.changesets.editor.incomplete")}</span>}
      </div>
    </div>
  );
}

/* One GUI form step: the fields its kind uses (the session's forms), rendered into lines by each device's driver. */
function FormStep({ value, index, onChange }: { value: FormParams; index: number; onChange: (f: FormParams) => void }) {
  const { t } = useTranslation();
  const fields: FormField[] = FORMS[value.kind] ?? [];
  const cls = "mt-0.5 block h-8 w-full rounded-md border bg-background px-2 text-[13px] outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";
  return (
    <div className="grid gap-2 rounded-md border border-dashed bg-muted/30 p-2 sm:grid-cols-[minmax(12rem,auto)_1fr_1fr]" data-testid={`cs-form-${index}`}>
      <label className="text-xs font-medium">
        {t("executor.session.form.kind")}
        <select className={cls} name={`cs-form-kind-${index}`} autoComplete="off" value={value.kind} onChange={(e) => onChange({ ...EMPTY_FORM, kind: e.target.value, interface: value.interface })}>
          {Object.keys(FORMS).map((k) => (
            <option key={k} value={k}>
              {t(`executor.session.form.kinds.${k}`)}
            </option>
          ))}
        </select>
      </label>
      {fields.map((f) => (
        <label key={f} className="text-xs font-medium">
          {t(`executor.session.form.field.${f}`)}
          {f === "up" ? (
            <select className={cls} name={`cs-form-up-${index}`} autoComplete="off" value={value.up ? "up" : "down"} onChange={(e) => onChange({ ...value, up: e.target.value === "up" })}>
              <option value="up">{t("executor.session.form.up")}</option>
              <option value="down">{t("executor.session.form.down")}</option>
            </select>
          ) : f === "vlan" ? (
            <input className={cls} name={`cs-form-vlan-${index}`} inputMode="numeric" maxLength={4} autoComplete="off" value={value.vlan === 0 ? "" : String(value.vlan)}
              onChange={(e) => /^\d{0,4}$/.test(e.target.value) && onChange({ ...value, vlan: Number(e.target.value || 0) })} />
          ) : (
            <input className={`${cls} font-mono`} name={`cs-form-${f}-${index}`} autoComplete="off" spellCheck={false} maxLength={f === "description" ? 240 : 64} value={value[f]}
              onChange={(e) => onChange({ ...value, [f]: e.target.value })} />
          )}
        </label>
      ))}
    </div>
  );
}

/* A device's backup versions (metadata only), newest first; the text is never read here. */
function VersionPicker({ token, device, value, onPick, onGone }: { token: string; device: number; value?: number; onPick: (v: number) => void; onGone: () => void }) {
  const { t } = useTranslation();
  const [list, setList] = useState<Version[] | null>(null);
  const [err, setErr] = useState<Message | null>(null);
  useEffect(() => {
    let live = true;
    void op(token, "versions", { device_id: device }, versionsAnswer).then((r) => {
      if (!live) return;
      if (r.ok) setList(r.value.result);
      else if (workspaceGone(r.failure)) onGone();
      else setErr(messageOf(r.failure));
    });
    return () => {
      live = false;
    };
  }, [token, device, onGone]);
  if (err) return <span className="text-xs text-destructive">{t(err.key, err.params)}</span>;
  if (!list) return <span className="text-xs text-muted-foreground">{t("executor.changesets.loading")}</span>;
  const known = value !== undefined && list.some((v) => v.version_id === value);
  return (
    <select className="h-7 w-96 max-w-full rounded-md border bg-background px-2 text-xs" aria-label={t("executor.changesets.editor.version", { id: device })} data-testid={`version-${device}`}
      value={value ?? ""} onChange={(e) => onPick(Number(e.target.value))}>
      <option value="">{t("executor.changesets.editor.pickVersion")}</option>
      {value !== undefined && !known && <option value={value}>{t("executor.changesets.editor.versionId", { id: value })}</option>}
      {list.map((v) => (
        <option key={v.version_id} value={v.version_id}>
          {`#${v.version_id} · ${when(v.taken_at)} · ${t(`executor.changesets.source.${v.source}`, { defaultValue: v.source })} · ${v.sha256.slice(0, 12)}`}
        </option>
      ))}
    </select>
  );
}
