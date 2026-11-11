import { useTranslation } from "react-i18next";
import { DiffLines } from "../session/DiffView";
import type { DeviceResult, PreviewGroup } from "./api";
import { useCode } from "./parts";

/*
 * A dry-run's outcome (Task 5.3): per device the registry's address, group and line, the pre-session hash read, and
 * either "ready" or the refusal (step, line of the device's plan, class, the executor's reason); only Safe lines go to
 * a device (D2): a refused line goes through a change session instead. Then the previews, identical ones once: the
 * equivalent commands that will be sent (forms rendered by each device's driver), the current lines of the contexts
 * they enter and, for a restore, the masked diff of the running configuration against the version. Text only.
 */
export function DryRunView({ ok, plan, devices, preview, stale }: { ok: boolean; plan: string; devices: DeviceResult[]; preview?: PreviewGroup[] | null; stale?: boolean }) {
  const { t } = useTranslation();
  const code = useCode();
  const refused = devices.filter((d) => !d.ok);
  return (
    <div className="space-y-4" data-testid="cs-dry-run">
      <div className={`rounded-lg border px-4 py-3 ${ok ? "border-emerald-500/40 bg-emerald-500/5" : "border-amber-500/50 bg-amber-500/5"}`}>
        <p className="font-semibold" data-testid="dry-run-outcome">
          {ok ? t("executor.changesets.dryRun.ok", { count: devices.length }) : t("executor.changesets.dryRun.failed", { count: refused.length, total: devices.length })}
        </p>
        <p className="mt-1 font-mono text-xs break-all text-muted-foreground">plan_sha256: {plan}</p>
        {!ok && <p className="mt-1 text-xs">{t("executor.changesets.dryRun.safeOnly")}</p>}
      </div>
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-[13px]">
          <thead className="bg-muted/50 text-left text-xs text-muted-foreground">
            <tr>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.changesets.col.device")}</th>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.changesets.col.address")}</th>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.changesets.col.group")}</th>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.changesets.col.line")}</th>
              <th className="px-2.5 py-1.5 font-medium">{t("executor.changesets.col.result")}</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.device_id} className="border-t align-top" data-testid={`dry-${d.device_id}`}>
                <td className="px-2.5 py-1.5 font-medium whitespace-nowrap">{t("executor.changesets.deviceShort", { id: d.device_id })}</td>
                <td className="px-2.5 py-1.5 font-mono whitespace-nowrap">{d.address || "-"}</td>
                <td className="px-2.5 py-1.5">{d.write_group || "-"}</td>
                <td className="px-2.5 py-1.5 font-mono">{d.line || "-"}</td>
                <td className="px-2.5 py-1.5">
                  {d.ok ? (
                    <span className="text-emerald-700 dark:text-emerald-400">
                      {t("executor.changesets.dryRun.ready")}
                      {d.pre_sha256 && <span className="ml-2 font-mono text-xs text-muted-foreground">pre {d.pre_sha256.slice(0, 12)}</span>}
                    </span>
                  ) : (
                    <span className="block text-destructive" data-testid={`refused-${d.device_id}`}>
                      <span className="font-medium">{code("executor.changesets.deviceRefused", d.refused?.code ?? "unknown")}</span>
                      {d.refused?.line ? <span className="ml-2">{t("executor.changesets.dryRun.at", { step: d.refused.step ?? "-", line: d.refused.line })}</span> : null}
                      {d.refused?.class && <span className="ml-2 rounded bg-destructive/10 px-1 font-mono text-xs">{d.refused.class}</span>}
                      {d.refused?.reason && <span className="block font-mono text-xs break-all text-muted-foreground">{d.refused.reason}</span>}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {stale && <p className="text-xs text-muted-foreground">{t("executor.changesets.dryRun.noPreview")}</p>}
      {(preview ?? []).map((g, i) => (
        <section key={i} className="space-y-2 rounded-lg border p-3" data-testid="cs-preview">
          <p className="text-sm font-semibold">{t("executor.changesets.dryRun.devicesOf", { ids: g.device_ids.join(", ") })}</p>
          {g.lines.length > 0 && (
            <div className="space-y-1">
              <p className="text-xs font-medium text-muted-foreground">{t("executor.changesets.dryRun.equivalent")}</p>
              <pre className="overflow-auto rounded-md border bg-neutral-950 px-3 py-2 font-mono text-[12.5px] leading-5 text-neutral-100">
                {g.lines.map((l, k) => (
                  <div key={k} className="break-all whitespace-pre-wrap" data-testid="equivalent-line">
                    {l}
                  </div>
                ))}
              </pre>
            </div>
          )}
          {g.contexts.length > 0 && (
            <details className="text-xs">
              <summary className="cursor-pointer font-medium text-muted-foreground">{t("executor.changesets.dryRun.contexts", { count: g.contexts.length })}</summary>
              <div className="mt-2 space-y-2">
                {g.contexts.map((c, k) => (
                  <pre key={k} className="max-h-48 overflow-auto rounded-md border bg-muted/30 px-3 py-2 font-mono text-[12px] leading-5">
                    {c.current.length === 0 ? `${c.line}\n  ${t("executor.changesets.dryRun.newContext")}` : c.current.join("\n")}
                  </pre>
                ))}
              </div>
            </details>
          )}
          {g.diff !== undefined && (
            <div className="space-y-1" data-testid="restore-diff">
              <p className="text-xs font-medium text-muted-foreground">{t("executor.changesets.dryRun.restoreDiff")}</p>
              {g.diff === "" ? <p className="text-sm text-muted-foreground">{t("executor.session.diff.none")}</p> : <DiffLines lines={g.diff.replace(/\n$/, "").split("\n")} maxHeight="max-h-[45vh]" />}
            </div>
          )}
        </section>
      ))}
    </div>
  );
}
