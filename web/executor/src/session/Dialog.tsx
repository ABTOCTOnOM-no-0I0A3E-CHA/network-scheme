import { useEffect, useId, type ReactNode } from "react";

/*
 * A modal of the session screen, without a dialog library: Radix's scroll lock injects a runtime <style> the CSP
 * forbids. No transform, no opacity on the box (IntersectionObserver v2 would report the confirm as not visible): the
 * backdrop is only a translucent background colour. Escape closes it unless busy.
 */
export function Dialog(p: { title: string; onClose?: () => void; busy?: boolean; wide?: boolean; tone?: "danger"; children: ReactNode; testId?: string }) {
  const id = useId();
  const { onClose, busy } = p;
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && onClose && !busy) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose, busy]);
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/55 px-4 py-8">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby={id}
        data-testid={p.testId}
        className={`w-full ${p.wide ? "max-w-4xl" : "max-w-2xl"} rounded-xl border bg-card text-card-foreground shadow-2xl ${p.tone === "danger" ? "border-t-4 border-t-destructive" : ""}`}
      >
        <div className="flex items-center justify-between gap-4 border-b px-5 py-3">
          <h2 id={id} className="text-base font-semibold">
            {p.title}
          </h2>
        </div>
        <div className="space-y-4 px-5 py-4 text-sm">{p.children}</div>
      </div>
    </div>
  );
}

/* A failure or notice line of the session screen. */
export function Alert({ children, tone = "error", testId }: { children: ReactNode; tone?: "error" | "warn" | "info"; testId?: string }) {
  const cls =
    tone === "error"
      ? "border-destructive/40 bg-destructive/10 text-destructive"
      : tone === "warn"
        ? "border-amber-400/60 bg-amber-50 text-amber-900 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-200"
        : "border-border bg-muted/50 text-foreground";
  return (
    <p role={tone === "info" ? "status" : "alert"} data-testid={testId} className={`rounded-md border px-3 py-2 text-sm ${cls}`}>
      {children}
    </p>
  );
}
