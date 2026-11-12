import { useTranslation } from "react-i18next";

/* Small pieces of the changeset screens. Every value is executor or device text, rendered as text. */

export const input = "mt-1 block h-9 w-full rounded-md border bg-background px-3 text-sm font-normal outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";
export const codeInput = "mt-1 block h-9 w-36 rounded-md border bg-background px-3 font-mono text-base tracking-[0.3em] outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50";
export const section = "space-y-3 rounded-xl border bg-card p-5";

const fmt = new Intl.DateTimeFormat("ru", { dateStyle: "short", timeStyle: "medium" });
export function when(iso: string | Date): string {
  const d = typeof iso === "string" ? new Date(iso) : iso;
  return Number.isNaN(d.getTime()) ? String(iso) : fmt.format(d);
}

const TONE: Record<string, string> = {
  draft: "border-border bg-muted text-muted-foreground",
  dry_run_ok: "border-sky-500/40 bg-sky-500/10 text-sky-800 dark:text-sky-300",
  dry_run_failed: "border-amber-500/50 bg-amber-500/10 text-amber-900 dark:text-amber-300",
  approved: "border-violet-500/40 bg-violet-500/10 text-violet-800 dark:text-violet-300",
  running: "border-blue-500/50 bg-blue-500/15 text-blue-800 dark:text-blue-300",
  done: "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300",
  rolled_back: "border-amber-500/50 bg-amber-500/10 text-amber-900 dark:text-amber-300",
  rollback_failed: "border-destructive/50 bg-destructive/10 text-destructive",
  interrupted: "border-destructive/50 bg-destructive/10 text-destructive",
  discarded: "border-border bg-muted/50 text-muted-foreground line-through",
};

/* A changeset's status as a badge. */
export function StatusBadge({ status }: { status: string }) {
  const { t, i18n } = useTranslation();
  const key = `executor.changesets.status.${status}`;
  return (
    <span data-testid="cs-status" data-status={status} className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${TONE[status] ?? TONE.draft}`}>
      {i18n.exists(key) ? t(key) : status}
    </span>
  );
}

const DEV_TONE: Record<string, string> = {
  pending: "border-dashed border-border text-muted-foreground",
  not_started: "border-dashed border-border text-muted-foreground",
  unknown: "border-dashed border-amber-500/60 text-amber-900 dark:text-amber-300",
  opened: "border-blue-500/60 bg-blue-500/10 text-blue-800 dark:text-blue-300",
  applied: "border-emerald-500/50 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300",
  saved: "border-emerald-600/60 bg-emerald-500/20 text-emerald-900 dark:text-emerald-200",
  failed: "border-destructive/60 bg-destructive/10 text-destructive",
  rolled_back: "border-amber-500/60 bg-amber-500/10 text-amber-900 dark:text-amber-300",
  rollback_failed: "border-destructive bg-destructive/20 text-destructive",
};
export function deviceTone(state: string): string {
  return DEV_TONE[state] ?? DEV_TONE.pending;
}

/* The text of an executor code under prefix, or the code itself (the executor's own word) when there is none. */
export function useCode() {
  const { t, i18n } = useTranslation();
  return (prefix: string, code: string) => {
    const key = `${prefix}.${code}`;
    return i18n.exists(key) ? t(key) : code;
  };
}
