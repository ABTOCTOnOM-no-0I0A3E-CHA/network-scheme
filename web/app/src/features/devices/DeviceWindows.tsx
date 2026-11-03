import { createContext, memo, useCallback, useContext, useEffect, useId, useMemo, useRef, useState, type PointerEvent as RPointerEvent, type ReactNode } from "react";
import { ExternalLink, X } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { safeText } from "@/lib/text";

/*
 * Floating device windows, as in Packet Tracer: opened from the map (or anywhere in the app), dragged by the title bar,
 * resized from the corner, several at once with the focused one on top, always kept inside the viewport. Esc closes the
 * focused window and focus returns to where it was before the window opened.
 */

export type DeviceWindows = { open: (deviceId: number, title?: string) => void; close: (deviceId: number) => void };

const Ctx = createContext<DeviceWindows | null>(null);

/** The app's device window manager; null outside the provider (callers fall back to the device page). */
export const useDeviceWindows = () => useContext(Ctx);

type Win = { id: number; title: string; x: number; y: number; w: number; h: number; opener: Element | null };

const MAX_WINDOWS = 8;
const DEFAULT_W = 860;
const DEFAULT_H = 640;
/* a pointer press this recent opened the window: it opens beside that point */
const POINTER_FRESH_MS = 1500;
const MIN_W = 420;
const MIN_H = 260;
const CASCADE = 28;

const view = () => ({ w: window.innerWidth, h: window.innerHeight });

/** A window rectangle moved and shrunk as needed to lie inside the viewport. */
export function clampWin<T extends { x: number; y: number; w: number; h: number }>(r: T, vp = view()): T {
  const w = Math.max(Math.min(r.w, vp.w - 8), Math.min(MIN_W, vp.w - 8));
  const h = Math.max(Math.min(r.h, vp.h - 8), Math.min(MIN_H, vp.h - 8));
  return { ...r, w, h, x: Math.min(Math.max(r.x, 4), vp.w - w - 4), y: Math.min(Math.max(r.y, 4), vp.h - h - 4) };
}

type Props = {
  children: ReactNode;
  /** The window body for a device (the device card). */
  renderBody: (deviceId: number) => ReactNode;
  /** Live extras of the title bar next to the name (the state badge). */
  renderTitle?: (deviceId: number) => ReactNode;
  /** "Open as a page": leaves the window for the device page. */
  onOpenPage: (deviceId: number) => void;
};

export function DeviceWindowsProvider({ children, renderBody, renderTitle, onOpenPage }: Props) {
  /* windows render in the order they opened (moving DOM nodes would drop focus and scroll); the stacking is kept apart, last on top */
  const [wins, setWins] = useState<Win[]>([]);
  const [order, setOrder] = useState<number[]>([]);
  const winsRef = useRef(wins);
  useEffect(() => {
    winsRef.current = wins;
  });
  /* where the pointer was last pressed, to place a window beside what opened it; a key press since then (Enter in the search) voids it */
  const lastPress = useRef<{ x: number; y: number; t: number } | undefined>(undefined);
  useEffect(() => {
    const onDown = (e: PointerEvent) => {
      /* a press inside a window (its close button) or a dialog (the search palette) is not a place to open beside */
      const inWin = e.target instanceof Element && e.target.closest('dialog, [role="dialog"]');
      lastPress.current = inWin ? undefined : { x: e.clientX, y: e.clientY, t: performance.now() };
    };
    const onKey = () => {
      lastPress.current = undefined;
    };
    window.addEventListener("pointerdown", onDown, true);
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("pointerdown", onDown, true);
      window.removeEventListener("keydown", onKey, true);
    };
  }, []);

  const focus = useCallback((id: number) => setOrder((o) => (o.at(-1) === id ? o : [...o.filter((x) => x !== id), id])), []);

  const open = useCallback(
    (id: number, title?: string) => {
      const opener = document.activeElement;
      if (winsRef.current.some((w) => w.id === id)) {
        focus(id);
        document.querySelector<HTMLElement>(`[data-device-window="${id}"]`)?.focus();
        return;
      }
      const vp = view();
      const ws = winsRef.current;
      const n = ws.length % 6;
      const w = Math.min(DEFAULT_W, vp.w - 48);
      /* most of the screen height: the tabs need the room more than the map behind */
      const h = Math.min(Math.max(DEFAULT_H, Math.round(vp.h * 0.8)), 760, vp.h - 48);
      /* beside the click that opened it (the device on the map), else centred; each further window steps down and right */
      const press = lastPress.current;
      const fresh = press && performance.now() - press.t < POINTER_FRESH_MS ? press : undefined;
      /* right of the click, or left of it when the right has no room, so the window does not cover what was clicked */
      const at = fresh ? { x: fresh.x + 32 + w <= vp.w ? fresh.x + 32 : fresh.x - 32 - w, y: fresh.y - 48 } : { x: (vp.w - w) / 2, y: 72 };
      const next = clampWin({ id, title: safeText(title) || `#${id}`, x: at.x + n * CASCADE, y: at.y + n * CASCADE, w, h, opener }, vp);
      /* past the limit the window lowest in the stack goes */
      const drop = ws.length >= MAX_WINDOWS ? order[0] : undefined;
      const kept = ws.filter((x) => x.id !== drop);
      winsRef.current = [...kept, next];
      setWins(winsRef.current);
      setOrder((o) => [...o.filter((x) => x !== drop), id]);
    },
    [focus, order],
  );

  const close = useCallback((id: number) => {
    const win = winsRef.current.find((w) => w.id === id);
    winsRef.current = winsRef.current.filter((w) => w.id !== id);
    setWins(winsRef.current);
    let rest: number[] = [];
    setOrder((o) => (rest = o.filter((x) => x !== id)));
    /* focus goes back to where it came from, else to the window now on top */
    const back = win?.opener;
    if (back instanceof HTMLElement && back.isConnected && back !== document.body) back.focus();
    else queueMicrotask(() => document.querySelector<HTMLElement>(`[data-device-window="${rest.at(-1)}"]`)?.focus());
  }, []);

  const update = useCallback((id: number, r: Partial<Win>) => setWins((ws) => ws.map((w) => (w.id === id ? clampWin({ ...w, ...r }) : w))), []);

  /* a smaller browser window pulls every window back into view */
  useEffect(() => {
    const onResize = () => setWins((ws) => ws.map((w) => clampWin(w)));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  const api = useMemo(() => ({ open, close }), [open, close]);
  return (
    <Ctx.Provider value={api}>
      {children}
      {wins.map((w) => {
        const i = order.indexOf(w.id);
        return (
          /* below the app's dialogs (z-50), so a step-up prompt from a window shows on top */
          <DeviceWindowFrame key={w.id} win={w} z={30 + i} top={i === order.length - 1} extra={renderTitle?.(w.id)} onFocus={focus} onClose={close} onChange={update} onOpenPage={onOpenPage}>
            <Body id={w.id} render={renderBody} />
          </DeviceWindowFrame>
        );
      })}
    </Ctx.Provider>
  );
}

/* the body re-renders only for its own device, not on every drag tick of its frame */
const Body = memo(
  ({ id, render }: { id: number; render: (id: number) => ReactNode }) => render(id),
  (a, b) => a.id === b.id,
);

type FrameProps = {
  win: Win;
  z: number;
  top: boolean;
  extra?: ReactNode;
  children: ReactNode;
  onFocus: (id: number) => void;
  onClose: (id: number) => void;
  onChange: (id: number, r: Partial<Win>) => void;
  onOpenPage: (id: number) => void;
};

function DeviceWindowFrame({ win, z, top, extra, children, onFocus, onClose, onChange, onOpenPage }: FrameProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const self = useRef<HTMLElement>(null);
  const drag = useRef<{ kind: "move" | "resize"; px: number; py: number; x: number; y: number; w: number; h: number } | undefined>(undefined);

  /* a new window takes the focus */
  useEffect(() => {
    self.current?.focus();
  }, []);

  const begin = (kind: "move" | "resize", e: RPointerEvent) => {
    if (e.button !== 0 || (kind === "move" && (e.target as Element).closest("button, a"))) return;
    e.preventDefault();
    (e.currentTarget as Element).setPointerCapture?.(e.pointerId);
    drag.current = { kind, px: e.clientX, py: e.clientY, x: win.x, y: win.y, w: win.w, h: win.h };
  };
  const move = (e: RPointerEvent) => {
    const d = drag.current;
    if (!d) return;
    const dx = e.clientX - d.px;
    const dy = e.clientY - d.py;
    if (d.kind === "move") onChange(win.id, { x: d.x + dx, y: d.y + dy });
    else onChange(win.id, { w: Math.max(MIN_W, d.w + dx), h: Math.max(MIN_H, d.h + dy) });
  };
  const end = () => {
    drag.current = undefined;
  };

  return (
    <section
      ref={self}
      role="dialog"
      aria-modal="false"
      aria-labelledby={titleId}
      tabIndex={-1}
      data-device-window={win.id}
      data-top={top || undefined}
      className={`fixed flex flex-col overflow-hidden rounded-lg border bg-background shadow-2xl outline-none ${top ? "ring-2 ring-primary/40" : "ring-1 ring-black/5"}`}
      style={{ left: win.x, top: win.y, width: win.w, height: win.h, zIndex: z }}
      onPointerDownCapture={() => onFocus(win.id)}
      onFocusCapture={() => !top && onFocus(win.id)}
      onKeyDown={(e) => {
        /* Esc from a popup portaled out of the window (a select, a menu) is that popup's */
        if (e.key !== "Escape" || e.defaultPrevented || !self.current?.contains(e.target as Node)) return;
        e.stopPropagation();
        onClose(win.id);
      }}
    >
      <header
        className={`flex h-10 shrink-0 cursor-move select-none items-center gap-2 border-b px-3 ${top ? "bg-muted" : "bg-muted/50 text-muted-foreground"}`}
        onPointerDown={(e) => begin("move", e)}
        onPointerMove={move}
        onPointerUp={end}
        onPointerCancel={end}
      >
        <h2 id={titleId} className="min-w-0 truncate text-sm font-semibold" title={win.title}>
          {win.title}
        </h2>
        <div className="flex min-w-0 flex-1 items-center gap-2">{extra}</div>
        <Button size="xs" variant="ghost" onClick={() => onOpenPage(win.id)}>
          <ExternalLink />
          {t("windows.openPage")}
        </Button>
        <Button size="icon-xs" variant="ghost" aria-label={t("windows.close")} title={t("windows.close")} onClick={() => onClose(win.id)}>
          <X />
        </Button>
      </header>
      <div className="min-h-0 flex-1 overflow-auto p-4">{children}</div>
      <div
        aria-hidden="true"
        title={t("windows.resize")}
        className="absolute bottom-0 right-0 size-4 cursor-nwse-resize bg-[linear-gradient(135deg,transparent_50%,var(--color-border)_50%,var(--color-border)_60%,transparent_60%,transparent_70%,var(--color-border)_70%,var(--color-border)_80%,transparent_80%)]"
        onPointerDown={(e) => begin("resize", e)}
        onPointerMove={move}
        onPointerUp={end}
        onPointerCancel={end}
      />
    </section>
  );
}
