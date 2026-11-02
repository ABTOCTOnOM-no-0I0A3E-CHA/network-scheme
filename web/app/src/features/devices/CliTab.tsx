import { useState, type FormEvent } from "react";
import { SquareTerminal } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { safeLines, safeText } from "@/lib/text";
import { useDeviceTable } from "./api";
import { useRunShow, useShowCommands, useShowResult, type ShowArgKind, type ShowArgs } from "./backups";
import { queryError } from "./ConfigTab";

const SELECT = "h-9 rounded-md border border-input bg-transparent px-3 text-sm text-foreground dark:bg-input/30";

/** "CLI" tab: a show command from the driver's list with typed arguments; the output is device text shown as plain monospace text. */
export function CliTab({ deviceId }: { deviceId: number }) {
  const { t } = useTranslation();
  const commands = useShowCommands(deviceId);
  const ifaces = useDeviceTable(deviceId, "interfaces", { limit: 1000 });
  const run = useRunShow(deviceId);
  const [key, setKey] = useState("");
  const [iface, setIface] = useState("");
  const [vlan, setVlan] = useState("");
  const [rid, setRid] = useState<number | undefined>();
  const [error, setError] = useState<string | undefined>();
  const result = useShowResult(rid);

  const cmd = commands.data?.find((c) => c.key === key);
  const needs = (k: ShowArgKind) => cmd?.args.includes(k) ?? false;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(undefined);
    if (!cmd) return;
    const args: ShowArgs = {};
    if (needs("interface")) {
      if (!iface) return setError(t("cli.pickInterface"));
      args.interface = iface;
    }
    if (needs("vlan")) {
      const n = /^\d{1,4}$/.test(vlan.trim()) ? Number(vlan.trim()) : 0;
      if (n < 1 || n > 4094) return setError(t("cli.badVlan"));
      args.vlan = n;
    }
    try {
      setRid(await run.mutateAsync({ key: cmd.key, args }));
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      setError(t(err instanceof ApiError ? errorKey({ error: { code: err.code } }) : err instanceof TypeError ? thrownKey(err) : "errors.unknown"));
    }
  };

  if (commands.isPending) return <p className="text-sm text-muted-foreground">{t("card.loading")}</p>;
  if (commands.error)
    return (
      <p role="alert" className="text-sm text-destructive">
        {queryError(t, commands.error)}
      </p>
    );
  if (commands.data.length === 0) return <p className="text-sm text-muted-foreground">{t("cli.none")}</p>;

  const r = result.data;
  const busy = run.isPending || r?.status === "queued" || r?.status === "running";
  return (
    <div className="grid gap-4">
      <form className="flex flex-wrap items-end gap-3" onSubmit={(e) => void submit(e)}>
        <label className="grid gap-1 text-xs text-muted-foreground">
          {t("cli.command")}
          <select className={SELECT} value={key} onChange={(e) => setKey(e.target.value)}>
            <option value="">{t("cli.pick")}</option>
            {commands.data.map((c) => (
              <option key={c.key} value={c.key}>
                {t(`cli.cmd.${c.key}`, { defaultValue: safeText(c.key) })}
              </option>
            ))}
          </select>
        </label>
        {needs("interface") && (
          <label className="grid gap-1 text-xs text-muted-foreground">
            {t("cli.interface")}
            <select className={SELECT} value={iface} onChange={(e) => setIface(e.target.value)}>
              <option value="">{t("cli.pick")}</option>
              {ifaces.data?.items.map((i) => (
                <option key={i.if_index} value={i.name}>
                  {safeText(i.name)}
                </option>
              ))}
            </select>
          </label>
        )}
        {needs("vlan") && (
          <label className="grid gap-1 text-xs text-muted-foreground">
            {t("cli.vlan")}
            <Input className="w-28" inputMode="numeric" value={vlan} onChange={(e) => setVlan(e.target.value)} />
          </label>
        )}
        <Button type="submit" disabled={!cmd || busy}>
          {t("cli.run")}
        </Button>
      </form>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {result.error && (
        <p role="alert" className="text-sm text-destructive">
          {queryError(t, result.error)}
        </p>
      )}
      {/* the terminal pane: dark like a console, always there, so the tab reads as a CLI before the first command */}
      <section aria-label={t("cli.terminal")} className="overflow-hidden rounded-lg border border-zinc-800 bg-zinc-950 text-zinc-100 shadow-inner">
        <div className="flex items-center gap-2 border-b border-zinc-800 bg-zinc-900 px-3 py-1.5 text-xs text-zinc-400">
          <SquareTerminal aria-hidden className="size-3.5" />
          <span>{t("cli.readOnly")}</span>
          {r && (
            <span role="status" className="ml-auto">
              {t(`cli.status.${r.status}`)}
              {r.truncated && ` · ${t("cli.truncated")}`}
            </span>
          )}
        </div>
        {r?.output != null ? (
          <pre data-testid="cli-output" className="max-h-[65vh] min-h-64 overflow-auto p-3 font-mono text-xs leading-5 whitespace-pre">
            {safeLines(r.output)}
          </pre>
        ) : (
          <p className="min-h-64 p-3 font-mono text-xs leading-5 text-zinc-500">{busy ? t("cli.running") : t("cli.idle")}</p>
        )}
      </section>
    </div>
  );
}
