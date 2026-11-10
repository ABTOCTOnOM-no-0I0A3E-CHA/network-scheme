import { z } from "zod";
import { failureMessage, type Failure, type Message } from "../errors";

/* POST /x/audit (cmd/executor/internal/auditview, Task 4d.2): grant audit-read and one change TOTP code per page. */
export const PAGE = 50;
export const RESULTS = ["ok", "denied", "error"] as const;

const text = (n: number) => z.string().max(n);

export const rowSchema = z.object({
  id: z.number().int().positive(),
  ts: text(64),
  user_id: z.number().int().nullable(),
  ip: text(64),
  user_agent: text(1024),
  action: text(64),
  object: text(512),
  result: z.enum(RESULTS),
  details: text(8 << 10),
});
export type Row = z.infer<typeof rowSchema>;
export const pageAnswer = z.object({ result: z.object({ rows: z.array(rowSchema).max(100), next: z.number().int().nonnegative() }) });
export type Page = z.infer<typeof pageAnswer>["result"];

export type Filters = { from: string; to: string; user: string; action: string; device: string; result: string };
export const EMPTY: Filters = { from: "", to: "", user: "", action: "", device: "", result: "" };

const ACTION = /^[a-z0-9_.-]{1,64}\*?$/;
const ID = /^\d{1,18}$/;

/* The read's params from the filters, or null when one is malformed (nothing is sent then). Times are local datetime-local values. */
export function params(f: Filters, before: number): Record<string, unknown> | null {
  const p: Record<string, unknown> = { limit: PAGE };
  for (const [k, v] of [["from", f.from], ["to", f.to]] as const) {
    if (v === "") continue;
    const d = new Date(v);
    if (Number.isNaN(d.getTime())) return null;
    p[k] = d.toISOString();
  }
  if (f.user !== "") {
    if (!ID.test(f.user)) return null;
    p.user_id = Number(f.user);
  }
  if (f.device !== "") {
    if (!ID.test(f.device)) return null;
    p.device_id = Number(f.device);
  }
  if (f.action !== "") {
    if (!ACTION.test(f.action)) return null;
    p.action = f.action;
  }
  if (f.result !== "") p.result = f.result;
  if (before > 0) p.before = before;
  return p;
}

const REFUSALS = ["view_limit", "bad_params"];

export function messageOf(f: Failure): Message {
  if (f.kind === "http" && f.status === 422) return { key: REFUSALS.includes(f.code) ? `executor.audit.refused.${f.code}` : "executor.audit.refused.other" };
  if (f.kind === "http" && f.status === 403 && f.code !== "origin") return { key: "executor.audit.refused.denied" };
  return failureMessage(f);
}
