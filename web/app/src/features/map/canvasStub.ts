/*
 * Test helper: jsdom has no canvas, so give Cytoscape a stand-in 2D context, and add the marker element from
 * index.html that stops Cytoscape from injecting a runtime <style> (the panel CSP would block it).
 */
export function installCanvasStub(): void {
  const marker = document.createElement("meta");
  marker.id = "__________cytoscape_stylesheet";
  document.head.append(marker);
  const ctx: unknown = new Proxy(function () {}, {
    get: (_t, k) => (k === "measureText" ? () => ({ width: 0 }) : k === "canvas" ? document.createElement("canvas") : () => ctx),
    set: () => true,
  });
  HTMLCanvasElement.prototype.getContext = (() => ctx) as unknown as typeof HTMLCanvasElement.prototype.getContext;
}
