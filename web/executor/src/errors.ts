import { z } from "zod";

/*
 * What the executor (or the gateway in front of it) answered, reduced to what the UI may show. The text comes only
 * from our own dictionary: nothing of the response body is displayed except a validated lock end.
 */
export type Failure =
  | { kind: "http"; status: number; code: string; until?: Date; permanent?: boolean; retryAfter?: number }
  | { kind: "network" }
  | { kind: "bad_response" }
  | { kind: "local"; code: "no_panel" | "no_ticket" | "busy" | "code_reused" };

export type Message = { key: string; params?: Record<string, string | number> };

const errorBody = z.object({
  error: z.object({ code: z.string().max(64), until: z.iso.datetime().optional(), permanent: z.boolean().optional() }),
});

/* Reads an error answer: unknown or unparsable bodies give an empty code (the status alone decides). */
export function parseFailure(status: number, body: unknown, retryAfter: string | null): Failure {
  const p = errorBody.safeParse(body);
  const e = p.success ? p.data.error : undefined;
  const secs = retryAfter !== null && /^\d{1,6}$/.test(retryAfter) ? Number(retryAfter) : undefined;
  return { kind: "http", status, code: e?.code ?? "", until: e?.until ? new Date(e.until) : undefined, permanent: e?.permanent, retryAfter: secs };
}

const when = new Intl.DateTimeFormat("ru", { dateStyle: "short", timeStyle: "medium" });

/* The dictionary key (and parameters) for a failure. 423 locked, 429 limits and 503 disabled/frozen/unavailable have their own texts. */
export function failureMessage(f: Failure): Message {
  switch (f.kind) {
    case "network":
      return { key: "executor.error.unreachable" };
    case "bad_response":
      return { key: "executor.error.bad_response" };
    case "local":
      return { key: `executor.error.${f.code}` };
  }
  switch (f.status) {
    case 423:
      if (f.permanent) return { key: "executor.error.locked_permanent" };
      return f.until && !Number.isNaN(f.until.getTime()) ? { key: "executor.error.locked", params: { until: when.format(f.until) } } : { key: "executor.error.locked_unknown" };
    case 429:
      if (f.code === "too_many_challenges") return { key: "executor.error.too_many_challenges" };
      return f.retryAfter !== undefined ? { key: "executor.error.rate_limited", params: { seconds: f.retryAfter } } : { key: "executor.error.rate_limited_unknown" };
    case 503:
      if (f.code === "executor_disabled" || f.code === "frozen" || f.code === "unavailable") return { key: `executor.error.${f.code}` };
      /* a 503 from the gateway itself: the executor behind it did not answer */
      return { key: "executor.error.unreachable" };
    case 403:
      return { key: f.code === "origin" ? "executor.error.origin" : "executor.error.denied" };
    case 421:
      return { key: "executor.error.misdirected" };
    case 502:
    case 504:
      return { key: "executor.error.unreachable" };
    default:
      return { key: "executor.error.unknown", params: { status: f.status } };
  }
}

/*
 * True when a TOTP code sent with this request may be spent, so the next attempt needs the next code: any answer
 * after the request was sent, and a lost connection (the outcome is unknown). A replayed code is a counted failure.
 */
export function codeSpent(f: Failure): boolean {
  return f.kind === "network" || f.kind === "bad_response" || f.kind === "http";
}
