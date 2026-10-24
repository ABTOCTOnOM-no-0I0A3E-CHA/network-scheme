import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BATCH_MAX, PositionSaver, SAVE_DELAY_MS, type PositionItem } from "./positions";

const item = (id: number, x = 1, y = 2, pinned = true): PositionItem => ({ device_id: id, x, y, pinned });

describe("PositionSaver", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("sends one batch after the quiet period, the last change of a device wins", async () => {
    const sent: PositionItem[][] = [];
    const saved: PositionItem[][] = [];
    const s = new PositionSaver(
      async (b) => void sent.push(b),
      (b) => saved.push(b),
      () => undefined,
    );
    s.queue(item(1, 1, 1));
    await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS - 1);
    s.queue(item(2));
    s.queue(item(1, 9, 9));
    await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS - 1);
    expect(sent).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    expect(sent).toHaveLength(1);
    expect(sent[0]).toEqual([item(1, 9, 9), item(2)]);
    expect(saved).toEqual(sent);
  });

  it("splits more than 5000 items into batches", async () => {
    const sizes: number[] = [];
    const s = new PositionSaver(
      async (b) => void sizes.push(b.length),
      () => undefined,
      () => undefined,
    );
    for (let i = 1; i <= BATCH_MAX + 7; i++) s.queue(item(i));
    await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS);
    expect(sizes).toEqual([BATCH_MAX, 7]);
  });

  it("clamps coordinates to the server range", async () => {
    const sent: PositionItem[][] = [];
    const s = new PositionSaver(
      async (b) => void sent.push(b),
      () => undefined,
      () => undefined,
    );
    s.queue(item(1, 5e9, -5e9));
    await s.flush();
    expect(sent[0][0]).toMatchObject({ x: 1e6, y: -1e6 });
  });

  it("reports a failure and retries the same items with the next change", async () => {
    let fail = true;
    const sent: number[] = [];
    const errors: unknown[] = [];
    const s = new PositionSaver(
      async (b) => {
        sent.push(b.length);
        if (fail) throw new Error("boom");
      },
      () => undefined,
      (e) => errors.push(e),
    );
    s.queue(item(1));
    await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS);
    expect(errors).toHaveLength(1);
    fail = false;
    s.queue(item(2));
    await vi.advanceTimersByTimeAsync(SAVE_DELAY_MS);
    expect(sent).toEqual([1, 2]);
  });
});
