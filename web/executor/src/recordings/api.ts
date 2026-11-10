import { z } from "zod";
import { failureMessage, type Failure, type Message } from "../errors";

/* POST /x/recordings and /x/recordings/replay (cmd/executor/internal/recording): grant audit-read and one change TOTP code each. */
const sessionId = z.string().regex(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);

export const itemSchema = z.object({
  session_id: sessionId,
  device_id: z.number().int().positive(),
  user_id: z.number().int(),
  opened_at: z.string().max(64),
  state: z.enum(["complete", "open", "incomplete"]),
});
export type Item = z.infer<typeof itemSchema>;
export const listAnswer = z.object({ result: z.array(itemSchema).max(1000) });

export const eventSchema = z.object({ t: z.number().nonnegative(), code: z.enum(["i", "o", "m"]), data: z.string() });
export type ReplayEvent = z.infer<typeof eventSchema>;
export const replayAnswer = z.object({
  result: z.object({
    session_id: sessionId,
    device_id: z.number().int(),
    timestamp: z.number().int(),
    title: z.string().max(256),
    events: z.array(eventSchema).max(2_000_000),
  }),
});
export type Replay = z.infer<typeof replayAnswer>["result"];

const REFUSALS = ["recording_tampered", "recording_open", "view_limit", "not_found", "bad_params"];

export function messageOf(f: Failure): Message {
  if (f.kind === "http" && f.status === 422) return { key: REFUSALS.includes(f.code) ? `executor.recordings.refused.${f.code}` : "executor.recordings.refused.other" };
  if (f.kind === "http" && f.status === 403 && f.code !== "origin") return { key: "executor.recordings.refused.denied" };
  if (f.kind === "http" && f.status === 503 && f.code === "replays_busy") return { key: "executor.recordings.refused.replays_busy" };
  return failureMessage(f);
}

/* The text of one event as the read-only terminal shows it: input as typed, output as is, the executor's markers on their own line. */
export function eventText(e: ReplayEvent): string {
  switch (e.code) {
    case "i":
      return "> " + e.data;
    case "o":
      return e.data;
    case "m":
      return `--- ${e.data} ---\n`;
  }
}
