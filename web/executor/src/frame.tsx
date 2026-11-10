import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@nms/shared/ui/button";
import { useUnobscured } from "./useUnobscured";

/*
 * What the page knows of the panel's frame around it: whether it shows only the compact strip, and how to ask the
 * panel for room (expand: full dock; dialog: the whole viewport while a confirmation is open). Outside the panel
 * (tests, a top-level page) every call does nothing.
 */
export type Frame = { compact: boolean; expand: () => void; dialog: (open: boolean) => void };
export const FrameContext = createContext<Frame>({ compact: false, expand: () => {}, dialog: () => {} });
export const useFrame = () => useContext(FrameContext);

/*
 * The gate of a confirmation (review 4c.6 I1): useUnobscured on the observed element, plus whether that element is
 * taller than the frame's viewport (then it can never be fully visible, so the confirm would stay dead): the caller
 * shows GateNotice OUTSIDE the observed element, so neither notice changes its height.
 */
export function useConfirmGate() {
  const { ref: observe, unobscured, supported } = useUnobscured();
  const [el, setEl] = useState<Element | null>(null);
  const [tooTall, setTooTall] = useState(false);
  const ref = useCallback(
    (e: Element | null) => {
      observe(e);
      setEl(e);
    },
    [observe],
  );
  useEffect(() => {
    if (!el) return;
    const check = () => setTooTall(el.getBoundingClientRect().height > window.innerHeight);
    check();
    window.addEventListener("resize", check);
    const ro = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(check);
    ro?.observe(el);
    return () => {
      window.removeEventListener("resize", check);
      ro?.disconnect();
    };
  }, [el]);
  /* the latest answer, for the re-check at the click */
  const seen = useRef(false);
  useEffect(() => {
    seen.current = unobscured && !tooTall;
  }, [unobscured, tooTall]);
  /* read at the click, never during render */
  const visibleNow = useCallback(() => seen.current, []);
  return { ref, unobscured: unobscured && !tooTall, supported, tooTall, visibleNow };
}

/* Why a gated confirm is off, outside the observed element: too tall for the frame (with the way out), or covered. */
export function GateNotice({ gate }: { gate: { unobscured: boolean; supported: boolean; tooTall: boolean } }): ReactNode {
  const { t } = useTranslation();
  const { expand } = useFrame();
  if (gate.tooTall) {
    return (
      <div role="alert" data-testid="too-tall" className="flex flex-wrap items-center gap-3 rounded-md border border-amber-400/60 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-950/40 dark:text-amber-200">
        <span className="flex-1">{t("executor.tooTall")}</span>
        <Button type="button" size="sm" variant="outline" onClick={expand}>
          {t("executor.expand")}
        </Button>
      </div>
    );
  }
  if (gate.unobscured) return null;
  return (
    <p role="alert" className="text-sm text-destructive">
      {t(gate.supported ? "executor.obscured" : "executor.visibilityUnsupported")}
    </p>
  );
}
