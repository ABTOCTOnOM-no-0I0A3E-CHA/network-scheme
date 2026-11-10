import { z } from "zod";
import type { Poster } from "../client";
import { failureMessage, type Failure, type Message } from "../errors";

/* The actions of cmd/executor/internal/devices. */
export const ACTIONS = { register: "device.register", accept: "device.accept_hostkey", writes: "device.writes" } as const;
export type ActionName = (typeof ACTIONS)[keyof typeof ACTIONS];
export const DRIVERS = ["mes6", "mes10", "esr"] as const;

const text = (n: number) => z.string().max(n);

/* One row of POST /x/devices. Everything is shown as text only. model_gate is shown when the executor ever sends it. */
export const deviceSchema = z.object({
  device_id: z.number().int(),
  address: text(64),
  port: z.number().int(),
  protocol: text(16),
  write_group: text(64),
  write_driver: text(16),
  hostkey_algo: text(64).optional(),
  hostkey_fp: text(128).optional(),
  allow_ssh_rsa_sha1: z.boolean(),
  writes_enabled: z.boolean(),
  backup_via_executor: z.boolean(),
  version: z.number().int(),
  status: text(32),
  model_gate: text(32).optional(),
});
export type Device = z.infer<typeof deviceSchema>;
export const deviceList = z.array(deviceSchema).max(10000);
/* POST /x/devices answers {result: [...]}, like every authorized read (cmd/executor/internal/web/read.go). */
export const deviceListAnswer = z.object({ result: deviceList });

/* What the probe returned: the fields the confirmation will show (and H cover). */
export const shownFields = z.record(text(64), text(512));
export const probeAnswer = z.object({ result: shownFields });

export const challengeSchema = z.object({
  challenge_id: text(64),
  action: z.enum([ACTIONS.register, ACTIONS.accept, ACTIONS.writes]),
  h: z.string().regex(/^[0-9a-f]{64}$/),
  fields: z.array(z.object({ key: text(64), value: text(512) })).max(256),
  expires: text(64),
});
export type Challenge = z.infer<typeof challengeSchema>;
export const doneSchema = z.object({ action: text(64), result: z.unknown() });

export function messageOf(f: Failure): Message {
  if (f.kind === "http" && f.status === 422) return { key: "executor.devices.refused" };
  if (f.kind === "http" && f.status === 503 && f.code === "outcome_unknown") return { key: "executor.devices.outcomeUnknown" };
  return failureMessage(f);
}

export type Outcome<T> = { ok: true; value: T } | { ok: false; msg: Message };

/*
 * Asks the executor to describe an action (a fresh ticket, no code). When `expect` is given (what the probe showed),
 * a description with any other field is refused: the fingerprint read is the one that is confirmed.
 */
export async function issue(poster: Poster, action: ActionName, params: Record<string, unknown>, expect?: Record<string, string>): Promise<Outcome<Challenge>> {
  const r = await poster.post("/x/confirm/issue", { action, params }, challengeSchema);
  if (!r.ok) return { ok: false, msg: messageOf(r.failure) };
  const c = r.value;
  if (c.action !== action) return { ok: false, msg: { key: "executor.devices.mismatch" } };
  if (expect) {
    const got = Object.fromEntries(c.fields.map((f) => [f.key, f.value]));
    const same = c.fields.length === Object.keys(got).length && Object.keys(expect).length === c.fields.length && Object.entries(expect).every(([k, v]) => got[k] === v);
    if (!same) return { ok: false, msg: { key: "executor.devices.mismatch" } };
  }
  return { ok: true, value: c };
}
