import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ChevronDown, ChevronUp, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { ExecutorFrame } from "./ExecutorFrame";

/*
 * The change session's one executor frame (FR-CHG-7), owned by the panel shell: it lives in a dock at the bottom of
 * the screen, above the device windows and below the app's dialogs, and survives navigation in the panel (the shell
 * stays mounted) and closing the device window it was opened from. Moving an iframe in the DOM reloads it, which would
 * drop the session's in-memory token, so the frame never moves: the dock is expanded or collapsed to the executor's
 * compact strip (timer, devices, Diff / Сохранить / Откатить / Завершить), never hidden while a session is open.
 * The frame's fragment only preselects (device ids, a recording); a new one reloads the frame, so it is changed only
 * while no session is open. While the executor shows a dialog (a confirmation), the dock takes the whole viewport
 * and cannot be collapsed: a confirmation is accepted only fully visible (review 4c.6 I1). While a session is open,
 * leaving the page asks first (the devices would stay busy until the session's idle timeout).
 */
export type SessionHost = {
  /* a session is open in the frame (the executor says so through the bridge) */
  sessionOpen: boolean;
  /* opens the frame for a device, or shows the open session */
  open: (deviceId: number) => void;
  /* opens the executor's player for one session of one device (only while no session is open) */
  replay: (session: string, deviceId: number) => boolean;
};

const Ctx = createContext<SessionHost | null>(null);

/* The shell's session host, or null outside the shell (a device card rendered on its own). */
export function useSessionHost(): SessionHost | null {
  return useContext(Ctx);
}

export function SessionHostProvider({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  const [frame, setFrame] = useState<{ hash: string; n: number } | null>(null);
  const [expanded, setExpanded] = useState(true);
  const [sessionOpen, setSessionOpen] = useState(false);
  const [dialog, setDialog] = useState(false);
  useEffect(() => {
    if (!sessionOpen) return;
    const warn = (e: BeforeUnloadEvent) => e.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [sessionOpen]);

  const load = useCallback((hash: string) => {
    setFrame((f) => ({ hash, n: (f?.n ?? 0) + 1 }));
    setExpanded(true);
  }, []);
  const open = useCallback(
    (deviceId: number) => {
      if (sessionOpen) setExpanded(true);
      else load(`device=${deviceId}`);
    },
    [sessionOpen, load],
  );
  const replay = useCallback(
    (session: string, deviceId: number) => {
      if (sessionOpen) {
        setExpanded(true);
        return false;
      }
      load(`replay=${session}&device=${deviceId}`);
      return true;
    },
    [sessionOpen, load],
  );
  const host = useMemo(() => ({ sessionOpen, open, replay }), [sessionOpen, open, replay]);
  const onExpand = useCallback(() => setExpanded(true), []);

  return (
    <Ctx.Provider value={host}>
      {children}
      {frame && (
        <section
          aria-label={t("executor.dock.title")}
          data-testid="session-dock"
          data-full={dialog || undefined}
          className={cn(
            "fixed inset-x-0 bottom-0 z-[45] flex flex-col border-t bg-background shadow-[0_-8px_24px_rgb(0_0_0/0.12)]",
            dialog ? "top-0 h-dvh" : expanded ? "h-[72vh]" : "h-14",
          )}
        >
          {expanded && !dialog && (
            <div className="flex h-9 shrink-0 items-center gap-2 border-b px-3">
              <span className="text-sm font-medium">{t("executor.dock.title")}</span>
              {sessionOpen && <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-xs text-emerald-700 dark:text-emerald-400">{t("executor.dock.open")}</span>}
              <div className="ml-auto flex items-center gap-1">
                <Button type="button" variant="ghost" size="sm" onClick={() => setExpanded(false)}>
                  <ChevronDown aria-hidden />
                  {t("executor.dock.collapse")}
                </Button>
                <Button type="button" variant="ghost" size="icon-sm" aria-label={t("executor.dock.close")} title={sessionOpen ? t("executor.dock.closeOpen") : t("executor.dock.close")}
                  disabled={sessionOpen} onClick={() => setFrame(null)}>
                  <X aria-hidden />
                </Button>
              </div>
            </div>
          )}
          <div className="flex min-h-0 flex-1">
            {!expanded && !dialog && (
              <Button type="button" variant="ghost" className="h-full rounded-none border-r px-3" aria-label={t("executor.dock.expand")} onClick={() => setExpanded(true)}>
                <ChevronUp aria-hidden />
              </Button>
            )}
            {/* keyed by load only: expanding and collapsing never reloads the frame */}
            <ExecutorFrame key={frame.n} title={t("executor.dock.title")} hash={frame.hash} onSession={setSessionOpen} onExpand={onExpand} onDialog={setDialog} className="h-full min-w-0 flex-1 border-0" />
          </div>
        </section>
      )}
      {/* the end of the page can be scrolled clear of the dock */}
      {frame && <div aria-hidden className={expanded ? "h-[72vh]" : "h-14"} />}
    </Ctx.Provider>
  );
}
