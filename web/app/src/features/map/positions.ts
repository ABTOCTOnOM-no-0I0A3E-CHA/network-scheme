export type PositionItem = { device_id: number; x: number; y: number; pinned: boolean };

/* the server takes at most 5000 items per batch */
export const BATCH_MAX = 5000;
export const SAVE_DELAY_MS = 800;
const COORD_MAX = 1e6;

const clamp = (v: number) => Math.max(-COORD_MAX, Math.min(COORD_MAX, v));

/**
 * Collects position changes and sends them in batches after a quiet period, so a drag session is one request. A later
 * change of the same device replaces the earlier one. Items stay pending until the server accepted them (a failed batch is retried with the next change).
 */
export class PositionSaver {
  private pending = new Map<number, PositionItem>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = false;
  private again = false;

  constructor(
    private send: (items: PositionItem[]) => Promise<void>,
    private onSaved: (items: PositionItem[]) => void,
    private onError: (err: unknown) => void,
    private delayMs = SAVE_DELAY_MS,
  ) {}

  queue(item: PositionItem): void {
    this.pending.set(item.device_id, { ...item, x: clamp(item.x), y: clamp(item.y) });
    this.schedule();
  }

  private schedule(): void {
    clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.flush(), this.delayMs);
  }

  /** Sends everything pending now (chunks of up to 5000); on failure the items stay pending and the error is reported. */
  async flush(): Promise<void> {
    clearTimeout(this.timer);
    if (this.running) {
      this.again = true;
      return;
    }
    this.running = true;
    try {
      do {
        this.again = false;
        const batch = [...this.pending.values()].slice(0, BATCH_MAX);
        if (batch.length === 0) break;
        try {
          await this.send(batch);
        } catch (e) {
          this.onError(e);
          return;
        }
        for (const it of batch) if (this.pending.get(it.device_id) === it) this.pending.delete(it.device_id);
        this.onSaved(batch);
        if (this.pending.size > 0) this.again = true;
      } while (this.again);
    } finally {
      this.running = false;
    }
  }

  dispose(): void {
    clearTimeout(this.timer);
  }
}
