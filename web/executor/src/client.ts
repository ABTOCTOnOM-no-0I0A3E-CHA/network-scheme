import { z } from "zod";
import { parseFailure, type Failure } from "./errors";
import { BridgeError, type ExecutorBridge } from "./bridge";

/*
 * The only way the UI talks to /x. The executor origin never uses cookies: credentials "omit" on every request. mode
 * "cors" is the default but is spelled out: with it a same-origin POST carries `Origin: <executor origin>` whatever
 * the Referrer-Policy (which is no-referrer), and the executor refuses a POST without it.
 */
const BASE: RequestInit = { credentials: "omit", mode: "cors", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer" };

export type Result<T> = { ok: true; value: T } | { ok: false; failure: Failure };

async function run<T>(path: string, init: RequestInit, schema: z.ZodType<T>): Promise<Result<T>> {
  let res: Response;
  try {
    res = await fetch(path, { ...BASE, ...init });
  } catch {
    return { ok: false, failure: { kind: "network" } };
  }
  const body: unknown = await res.json().catch(() => undefined);
  if (!res.ok) return { ok: false, failure: parseFailure(res.status, body, res.headers.get("Retry-After")) };
  const p = schema.safeParse(body);
  return p.success ? { ok: true, value: p.data } : { ok: false, failure: { kind: "bad_response" } };
}

const statusBody = z.object({ enabled: z.boolean(), frozen: z.boolean() });
export type ExecutorStatus = z.infer<typeof statusBody>;

/* GET /x/status: whether the policy enables the executor and whether it is frozen. No grants (Q14). */
export function getStatus(signal?: AbortSignal): Promise<Result<ExecutorStatus>> {
  return run("/x/status", { method: "GET", signal }, statusBody);
}

export type Poster = {
  /*
   * POSTs the body built from a fresh ticket from the panel (one per request, never reused). Never retries; refuses
   * a second request while one is in flight; refuses a TOTP `code` already sent from this page: a replayed or
   * parallel-submitted code is a counted failure on the server.
   */
  post<T>(path: string, build: (ticket: string) => { code?: string } & Record<string, unknown>, schema: z.ZodType<T>): Promise<Result<T>>;
};

const REMEMBERED_CODES = 16;

export function createPoster(bridge: Pick<ExecutorBridge, "requestTicket">): Poster {
  let inFlight = false;
  const sent: string[] = [];
  return {
    async post(path, build, schema) {
      if (inFlight) return { ok: false, failure: { kind: "local", code: "busy" } };
      inFlight = true;
      try {
        let ticket: string;
        try {
          ticket = await bridge.requestTicket();
        } catch (e) {
          return { ok: false, failure: { kind: "local", code: e instanceof BridgeError ? e.code : "no_ticket" } };
        }
        const body = build(ticket);
        if (body.code !== undefined) {
          if (sent.includes(body.code)) return { ok: false, failure: { kind: "local", code: "code_reused" } };
          sent.push(body.code);
          if (sent.length > REMEMBERED_CODES) sent.shift();
        }
        return await run(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }, schema);
      } finally {
        inFlight = false;
      }
    },
  };
}
