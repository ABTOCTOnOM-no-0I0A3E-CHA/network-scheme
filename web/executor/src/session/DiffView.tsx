import { useTranslation } from "react-i18next";
import type { DeviceDiff } from "./api";

/* Classes of a unified diff line by its first character; the line itself is a text node. */
function tone(l: string): string {
  if (l.startsWith("+++") || l.startsWith("---")) return "text-muted-foreground";
  if (l.startsWith("@@")) return "text-sky-700 dark:text-sky-400";
  if (l.startsWith("+")) return "bg-emerald-500/10 text-emerald-800 dark:text-emerald-300";
  if (l.startsWith("-")) return "bg-red-500/10 text-red-800 dark:text-red-300";
  return "";
}

/* One device's diff (pre-session snapshot against the running configuration, masked by the executor), text only. */
export function DiffView({ diff, title, maxHeight = "max-h-[50vh]" }: { diff: DeviceDiff; title?: string; maxHeight?: string }) {
  const { t } = useTranslation();
  const lines = diff.diff === "" ? [] : diff.diff.replace(/\n$/, "").split("\n");
  return (
    <section className="space-y-2" data-testid={`diff-${diff.device_id}`}>
      {title && <h3 className="text-sm font-semibold">{title}</h3>}
      <p className="font-mono text-xs break-all text-muted-foreground">
        {t("executor.session.diff.hashes", { pre: diff.pre_sha256.slice(0, 16), cur: diff.sha256.slice(0, 16) })}
      </p>
      {diff.too_large && <p className="text-amber-700 dark:text-amber-300">{t("executor.session.diff.tooLarge")}</p>}
      {!diff.too_large && lines.length === 0 && <p className="text-muted-foreground">{t("executor.session.diff.none")}</p>}
      {lines.length > 0 && <DiffLines lines={lines} maxHeight={maxHeight} />}
    </section>
  );
}

/* The lines of a unified diff, each a text node coloured by its first character. */
export function DiffLines({ lines, maxHeight = "max-h-[50vh]" }: { lines: string[]; maxHeight?: string }) {
  return (
    <pre className={`${maxHeight} overflow-auto rounded-md border bg-muted/30 py-2 font-mono text-[12.5px] leading-5`}>
      {lines.map((l, i) => (
        <div key={i} className={`px-3 whitespace-pre-wrap break-all ${tone(l)}`}>
          {l === "" ? " " : l}
        </div>
      ))}
    </pre>
  );
}
