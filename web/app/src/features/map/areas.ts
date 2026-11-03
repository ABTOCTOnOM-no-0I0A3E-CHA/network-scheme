export type Rect = { x: number; y: number; w: number; h: number };
type Tree = { id: number; parent_id: number | null };

const MAX_DEPTH = 64;

/** Ids of every area below `id` (children, their children, ...). */
export function descendants(areas: readonly Tree[], id: number): Set<number> {
  const out = new Set<number>();
  let frontier = [id];
  for (let d = 0; d < MAX_DEPTH && frontier.length > 0; d++) {
    frontier = areas.filter((a) => a.parent_id !== null && frontier.includes(a.parent_id) && !out.has(a.id) && a.id !== id).map((a) => a.id);
    for (const a of frontier) out.add(a);
  }
  return out;
}

const holds = (outer: Rect, inner: Rect) => inner.x >= outer.x && inner.y >= outer.y && inner.x + inner.w <= outer.x + outer.w && inner.y + inner.h <= outer.y + outer.h;

/**
 * The area a rectangle is dropped into: the smallest one that holds it whole, ignoring `exclude` (the area itself and
 * its descendants, which cannot become its parent). Null when no area holds it: it becomes a top-level area.
 */
export function containerOf(areas: readonly (Tree & Rect)[], r: Rect, exclude: ReadonlySet<number> = new Set()): number | null {
  let best: (Tree & Rect) | undefined;
  for (const a of areas) {
    if (exclude.has(a.id) || !holds(a, r)) continue;
    if (!best || a.w * a.h < best.w * best.h) best = a;
  }
  return best?.id ?? null;
}

/** Whether a point lies in a rectangle (half-open, as the server assigns devices to areas). */
export const insideRect = (r: Rect, p: { x: number; y: number }) => p.x >= r.x && p.x < r.x + r.w && p.y >= r.y && p.y < r.y + r.h;

/** Rectangle spanned by two corners (any order), in model units. */
export function spanRect(a: { x: number; y: number }, b: { x: number; y: number }): Rect {
  return { x: Math.min(a.x, b.x), y: Math.min(a.y, b.y), w: Math.abs(a.x - b.x), h: Math.abs(a.y - b.y) };
}

export type Corner = "nw" | "ne" | "sw" | "se";

/** `orig` with the given corner moved to the point `p`, the opposite corner staying fixed. */
export function resizeRect(orig: Rect, corner: Corner, p: { x: number; y: number }): Rect {
  const fixed = { x: corner.includes("w") ? orig.x + orig.w : orig.x, y: corner.includes("n") ? orig.y + orig.h : orig.y };
  return spanRect(fixed, p);
}

export const roundRect = (r: Rect): Rect => ({ x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.w), h: Math.round(r.h) });
