import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { FrameContext } from "./frame";
import { StatusWidget } from "./StatusWidget";
import type { ExecutorBridge } from "./bridge";
import type { Poster } from "./client";
import { ConfigsPage } from "./configs/ConfigsPage";
import { DevicesPage } from "./devices/DevicesPage";
import { RecordingsPage } from "./recordings/RecordingsPage";
import { parsePreset } from "./session/api";
import { SessionApp } from "./session/SessionApp";

type View = "session" | "recordings" | "configs" | "devices";
const VIEWS: View[] = ["session", "recordings", "configs", "devices"];

/* The panel's dock shows this page as a strip of this height or less: the session's compact indicator only. */
const COMPACT = "(max-height: 160px)";

function useCompact(): boolean {
  const [c, setC] = useState(() => window.matchMedia(COMPACT).matches);
  useEffect(() => {
    const m = window.matchMedia(COMPACT);
    const on = () => setC(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return c;
}

/*
 * The executor UI: the change session (default), the session recordings, the unmasked configurations and the write
 * device administration. The panel may preselect devices or a recording through the fragment of the frame's URL
 * (parsePreset: prefill only).
 */
export function App({ poster, bridge }: { poster?: Poster; bridge?: Promise<ExecutorBridge | null> }) {
  const { t } = useTranslation();
  const [preset] = useState(() => parsePreset(window.location.hash));
  const [view, setView] = useState<View>(preset.replay ? "recordings" : "session");
  const [replay, setReplay] = useState(preset.replay);
  const [sessionOpen, setSessionOpen] = useState(false);
  const compact = useCompact();

  /* the panel hears only changes: nothing until a session opens (a page without one says only "ready") */
  const told = useRef(false);
  const onOpenChange = useCallback(
    (open: boolean) => {
      setSessionOpen(open);
      if (open === told.current) return;
      told.current = open;
      void bridge?.then((b) => b?.session(open));
    },
    [bridge],
  );
  const expand = useCallback(() => void bridge?.then((b) => b?.expand()), [bridge]);
  /* the panel hears "dialog open" when the first dialog opens and "closed" when the last one closes */
  const dialogs = useRef(0);
  const dialog = useCallback(
    (open: boolean) => {
      const before = dialogs.current;
      dialogs.current = Math.max(0, before + (open ? 1 : -1));
      if ((before === 0) !== (dialogs.current === 0)) void bridge?.then((b) => b?.dialog(open));
    },
    [bridge],
  );
  const frame = useMemo(() => ({ compact, expand, dialog }), [compact, expand, dialog]);

  const session = poster && (
    <SessionApp poster={poster} preset={preset.devices} compact={compact} onOpenChange={onOpenChange} onExpand={expand}
      onRecordings={(s, d) => {
        setReplay(d ? { session: s, device: d } : undefined);
        setView("recordings");
      }} />
  );

  /* one tree in both modes: switching to the compact strip must not remount the session (its token and terminals) */
  return (
    <FrameContext.Provider value={frame}>
      <div className="flex h-screen min-h-0 flex-col bg-background">
        <header className={compact ? "hidden" : "flex h-12 shrink-0 items-center gap-6 border-b px-5"}>
          <h1 className="text-sm font-semibold whitespace-nowrap">{t("executor.title")}</h1>
          <nav role="tablist" aria-label={t("executor.nav.label")} className="flex h-full items-stretch gap-1">
            {VIEWS.map((v) => (
              <button key={v} type="button" role="tab" aria-selected={view === v} data-testid={`nav-${v}`}
                className={`-mb-px flex items-center gap-2 border-b-2 px-3 text-sm ${view === v ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground"}`}
                onClick={() => setView(v)}>
                {t(`executor.nav.${v}`)}
                {v === "session" && sessionOpen && <span aria-label={t("executor.nav.open")} className="size-1.5 rounded-full bg-emerald-500" />}
              </button>
            ))}
          </nav>
          <div className="ml-auto min-w-0">
            <StatusWidget />
          </div>
        </header>
        <main className={compact ? "min-h-0 flex-1" : "min-h-0 flex-1 overflow-auto p-4"}>
          {/* the session stays mounted on the other views: its terminals keep their connections */}
          <div className={view === "session" || compact ? "h-full" : "hidden"}>{session}</div>
          {poster && !compact && view === "recordings" && (
            <div className="mx-auto max-w-5xl">
              <RecordingsPage key={replay ? `${replay.session}/${replay.device}` : "-"} poster={poster} initial={replay} />
            </div>
          )}
          {poster && !compact && view === "configs" && (
            <div className="mx-auto max-w-5xl">
              <ConfigsPage poster={poster} />
            </div>
          )}
          {poster && !compact && view === "devices" && (
            <div className="mx-auto max-w-3xl">
              <DevicesPage poster={poster} />
            </div>
          )}
        </main>
      </div>
    </FrameContext.Provider>
  );
}
