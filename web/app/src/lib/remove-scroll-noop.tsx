import type { ReactNode } from "react";

/*
 * Build-time stand-in for react-remove-scroll (see vite.config.ts). The real package
 * injects a runtime <style> element, which the panel CSP (style-src 'self') blocks, and
 * cmdk drags it into the bundle through @radix-ui/react-dialog even though no modal
 * Radix overlay is rendered. Overlays in this app are native or non-modal instead.
 */
export function RemoveScroll({ children }: { children?: ReactNode }) {
  return children;
}
export default RemoveScroll;
