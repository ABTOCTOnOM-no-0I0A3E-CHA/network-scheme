import { useEffect, useState } from "react";

/*
 * Clickjacking defence. The panel may frame this UI (frame-ancestors), so a compromised panel could lay its own
 * content over the description/diff/H of an action while the TOTP field stays visible. IntersectionObserver v2
 * reports `isVisible` only when nothing covers the target, it is not transformed and not translucent; a
 * confirmation must be refused unless the element is fully on screen and visible. A browser without v2 cannot tell,
 * so it refuses (unobscured stays false forever, `supported` is false) rather than assume.
 */

/* v2 asks the browser to re-check at most this often (the spec requires at least 100 ms with trackVisibility). */
const DELAY_MS = 100;

export function visibilityV2Supported(): boolean {
  return typeof IntersectionObserver !== "undefined" && typeof IntersectionObserverEntry !== "undefined" && "isVisible" in IntersectionObserverEntry.prototype;
}

/* Calls on(true) while el is fully visible and unobscured and on(false) otherwise; returns the stop function. Unsupported: never true. */
export function observeUnobscured(el: Element, on: (unobscured: boolean) => void): () => void {
  on(false);
  if (!visibilityV2Supported()) return () => {};
  const io = new IntersectionObserver(
    (entries) => {
      /* only the latest entry counts */
      const e = entries[entries.length - 1];
      on(e !== undefined && e.isIntersecting && e.intersectionRatio >= 1 && (e as IntersectionObserverEntry & { isVisible?: boolean }).isVisible === true);
    },
    /* trackVisibility/delay are v2 options, absent from the DOM typings */
    { threshold: [1], trackVisibility: true, delay: DELAY_MS } as IntersectionObserverInit,
  );
  io.observe(el);
  return () => io.disconnect();
}

/*
 * true only while the element given to `ref` is fully visible and not covered; false until the first observation,
 * without an element and when v2 is unsupported. `ref` is a callback ref: an element mounted later (after a
 * loading state) or replaced is observed too, the previous one is no longer.
 */
export function useUnobscured(): { ref: (el: Element | null) => void; unobscured: boolean; supported: boolean } {
  const [el, setEl] = useState<Element | null>(null);
  const [unobscured, setUnobscured] = useState(false);
  const supported = visibilityV2Supported();
  useEffect(() => {
    if (!el) return;
    return observeUnobscured(el, setUnobscured);
  }, [el]);
  return { ref: setEl, unobscured: supported && el !== null && unobscured, supported };
}
