import { useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { errText } from "@/features/common/errText";
import { StepUpCancelled } from "@/features/common/stepup";
import { SEVERITIES, type EventSeverity } from "@/features/problems/api";
import { useCreateTrigger, useUpdateTrigger, type Trigger } from "./api";
import {
  AVAIL_STATES,
  buildParams,
  EMPTY_PARAMS,
  formFromParams,
  KINDS,
  MAX_CONTAINS_CHARS,
  MAX_DURATION_S,
  MAX_IF_INDEX,
  MAX_NAME_CHARS,
  METRIC_BOUNDS,
  METRICS,
  OPS,
  parseDuration,
  SYSLOG_SEVERITIES,
  validName,
  type Kind,
  type ParamsForm,
} from "./params";

const SELECT_CLASS = "h-9 w-full rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

type Props = {
  templateId: number;
  /** Set to edit an existing trigger (its kind is fixed); absent to add one. */
  trigger?: Trigger;
  onDone: () => void;
};

/** Add or edit a trigger. Only the closed set of kinds and their typed parameters can be entered; the checks repeat the server's bounds. */
export function TriggerForm({ templateId, trigger, onDone }: Props) {
  const { t } = useTranslation();
  const create = useCreateTrigger();
  const update = useUpdateTrigger();
  const [name, setName] = useState(trigger?.name ?? "");
  const [kind, setKind] = useState<Kind>((trigger?.kind as Kind | undefined) ?? "availability");
  const [pf, setPf] = useState<ParamsForm>(trigger ? formFromParams(trigger.kind as Kind, trigger.params) : EMPTY_PARAMS);
  const [duration, setDuration] = useState(String(trigger?.duration_s ?? 0));
  const [severity, setSeverity] = useState<EventSeverity>(trigger?.severity ?? "warning");
  const [enabled, setEnabled] = useState(trigger?.enabled ?? true);
  const [error, setError] = useState<string | undefined>();
  const patch = (p: Partial<ParamsForm>) => setPf((f) => ({ ...f, ...p }));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    if (!validName(name)) return setError(t("templates.err.name", { max: MAX_NAME_CHARS }));
    const d = parseDuration(duration);
    if (d === null) return setError(t("templates.err.duration", { max: MAX_DURATION_S }));
    const built = buildParams(kind, pf);
    if ("err" in built) return setError(t(`templates.err.${built.err}`, { maxIf: MAX_IF_INDEX, maxContains: MAX_CONTAINS_CHARS, ...METRIC_BOUNDS[pf.metric] }));
    try {
      if (trigger) await update.mutateAsync({ templateId, id: trigger.id, body: { name, params: built.ok, duration_s: d, severity, enabled } });
      else await create.mutateAsync({ templateId, body: { name, kind, params: built.ok, duration_s: d, severity, enabled } });
      onDone();
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      setError(errText(t, err));
    }
  };

  const ifIndexField = (
    <div className="grid gap-1.5">
      <Label htmlFor="trg-ifindex">{t("templates.param.ifIndex")}</Label>
      <Input id="trg-ifindex" type="number" placeholder={t("templates.param.anyInterface")} value={pf.ifIndex} onChange={(e) => patch({ ifIndex: e.target.value })} />
    </div>
  );

  return (
    <form onSubmit={(e) => void submit(e)} noValidate aria-label={t(trigger ? "templates.trigger.edit" : "templates.trigger.add")} className="grid gap-4 rounded-md border p-4">
      <h3 className="text-sm font-semibold">{t(trigger ? "templates.trigger.edit" : "templates.trigger.add")}</h3>
      <div className="grid gap-4 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label htmlFor="trg-name">{t("templates.col.name")}</Label>
          <Input id="trg-name" value={name} maxLength={MAX_NAME_CHARS} autoComplete="off" onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="trg-kind">{t("templates.trigger.kind")}</Label>
          <select id="trg-kind" className={SELECT_CLASS} value={kind} disabled={!!trigger} onChange={(e) => setKind(e.target.value as Kind)}>
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {t(`templates.kind.${k}`)}
              </option>
            ))}
          </select>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="trg-severity">{t("events.col.severity")}</Label>
          <select id="trg-severity" className={SELECT_CLASS} value={severity} onChange={(e) => setSeverity(e.target.value as EventSeverity)}>
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {t(`events.severity.${s}`)}
              </option>
            ))}
          </select>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="trg-duration">{t("templates.trigger.duration")}</Label>
          <Input id="trg-duration" type="number" min={0} max={MAX_DURATION_S} value={duration} onChange={(e) => setDuration(e.target.value)} />
        </div>
      </div>
      <fieldset className="grid gap-3 sm:grid-cols-2">
        <legend className="mb-2 text-xs font-semibold text-muted-foreground">{t("templates.trigger.params")}</legend>
        {kind === "availability" && (
          <div className="flex flex-wrap gap-4 text-sm">
            {AVAIL_STATES.map((s) => (
              <label key={s} className="flex items-center gap-2">
                <input type="checkbox" checked={pf.states[s]} onChange={(e) => patch({ states: { ...pf.states, [s]: e.target.checked } })} />
                {t(`templates.param.state.${s}`)}
              </label>
            ))}
          </div>
        )}
        {kind === "if_oper_down" && ifIndexField}
        {kind === "metric_threshold" && (
          <>
            <div className="grid gap-1.5">
              <Label htmlFor="trg-metric">{t("templates.param.metric")}</Label>
              <select id="trg-metric" className={SELECT_CLASS} value={pf.metric} onChange={(e) => patch({ metric: e.target.value as ParamsForm["metric"], ifIndex: METRIC_BOUNDS[e.target.value as ParamsForm["metric"]].iface ? pf.ifIndex : "" })}>
                {METRICS.map((m) => (
                  <option key={m} value={m}>
                    {t(`templates.metric.${m}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="trg-op">{t("templates.param.op")}</Label>
              <select id="trg-op" className={SELECT_CLASS} value={pf.op} onChange={(e) => patch({ op: e.target.value as ParamsForm["op"] })}>
                {OPS.map((o) => (
                  <option key={o} value={o}>
                    {t(`templates.op.${o}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="trg-value">{t("templates.param.value", METRIC_BOUNDS[pf.metric])}</Label>
              <Input id="trg-value" type="number" step="any" value={pf.value} onChange={(e) => patch({ value: e.target.value })} />
            </div>
            {METRIC_BOUNDS[pf.metric].iface && ifIndexField}
          </>
        )}
        {kind === "trap" && (
          <div className="grid gap-1.5 sm:col-span-2">
            <Label htmlFor="trg-trap">{t("templates.param.trapName")}</Label>
            <Input id="trg-trap" value={pf.trapName} autoComplete="off" spellCheck={false} onChange={(e) => patch({ trapName: e.target.value })} />
          </div>
        )}
        {kind === "syslog" && (
          <>
            <div className="grid gap-1.5">
              <Label htmlFor="trg-sysev">{t("templates.param.syslogSeverity")}</Label>
              <select id="trg-sysev" className={SELECT_CLASS} value={pf.syslogSeverity} onChange={(e) => patch({ syslogSeverity: e.target.value })}>
                {SYSLOG_SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {t(`templates.syslogSeverity.${s}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="trg-contains">{t("templates.param.contains")}</Label>
              <Input id="trg-contains" value={pf.contains} maxLength={MAX_CONTAINS_CHARS} autoComplete="off" onChange={(e) => patch({ contains: e.target.value })} />
            </div>
          </>
        )}
      </fieldset>
      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
        {t("templates.trigger.enabled")}
      </label>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onDone}>
          {t("stepup.cancel")}
        </Button>
        <Button type="submit" disabled={create.isPending || update.isPending}>
          {t("profile.save")}
        </Button>
      </div>
    </form>
  );
}
