import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { getStatus, type ExecutorStatus } from "./client";
import { failureMessage, type Failure } from "./errors";

/* The executor republishes its state every 30 s; polling faster adds nothing. */
export const POLL_MS = 30_000;
/* A 429 answer without Retry-After still backs off at least this long. */
const MIN_BACKOFF_MS = 5_000;

type View = { last: { status: ExecutorStatus; at: Date } | null; failure: Failure | null; loaded: boolean };

/* Polls GET /x/status. A failed refresh keeps the last good answer, marked stale. */
export function useExecutorStatus(): View & { refresh: () => void } {
  const [view, setView] = useState<View>({ last: null, failure: null, loaded: false });
  /* every change of tick is one request; the timer below and the button both bump it */
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const ac = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    void getStatus(ac.signal).then((r) => {
      if (ac.signal.aborted) return;
      setView((v) => (r.ok ? { last: { status: r.value, at: new Date() }, failure: null, loaded: true } : { last: v.last, failure: r.failure, loaded: true }));
      const wait = !r.ok && r.failure.kind === "http" && r.failure.status === 429 ? Math.max(MIN_BACKOFF_MS, (r.failure.retryAfter ?? 0) * 1000) : POLL_MS;
      timer = setTimeout(() => setTick((n) => n + 1), wait);
    });
    return () => {
      ac.abort();
      clearTimeout(timer);
    };
  }, [tick]);

  return { ...view, refresh: () => setTick((n) => n + 1) };
}

const dot = (ok: boolean) => `size-2 shrink-0 rounded-full ${ok ? "bg-emerald-500" : "bg-destructive"}`;

/* /x/status as a strip of the header: whether the executor is enabled and frozen. Text only; no grants, no per-user data. */
export function StatusWidget() {
  const { t, i18n } = useTranslation();
  const { last, failure, loaded, refresh } = useExecutorStatus();
  const msg = failure && failureMessage(failure);
  return (
    <section aria-live="polite" aria-label={t("executor.status.title")} className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1 text-xs">
      {!loaded && <p className="text-muted-foreground">{t("executor.status.loading")}</p>}
      {loaded && !last && <p className="text-muted-foreground">{t("executor.status.unknown")}</p>}
      {last && (
        <ul className="flex items-center gap-4">
          <li className="flex items-center gap-1.5">
            <span aria-hidden className={dot(last.status.enabled)} />
            <span data-testid="enabled">{t(last.status.enabled ? "executor.status.enabled" : "executor.status.disabled")}</span>
          </li>
          <li className="flex items-center gap-1.5">
            <span aria-hidden className={dot(!last.status.frozen)} />
            <span data-testid="frozen">{t(last.status.frozen ? "executor.status.frozen" : "executor.status.notFrozen")}</span>
          </li>
        </ul>
      )}
      {msg && (
        <p role="alert" className="text-destructive" data-testid="failure">
          {t(msg.key, msg.params)}
        </p>
      )}
      {last && failure && (
        <p className="text-muted-foreground" data-testid="stale">
          {t("executor.status.stale", { time: last.at.toLocaleTimeString(i18n.language) })}
        </p>
      )}
      <Button variant="ghost" size="xs" onClick={refresh}>
        {t("executor.status.retry")}
      </Button>
    </section>
  );
}
