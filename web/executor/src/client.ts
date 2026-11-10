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
   * POSTs body with a fresh ticket from the panel added (one per request, never reused). Never retries; refuses
   * a second request while one is in flight; refuses a TOTP code (`code`, or `totp` on the session routes) already
   * sent from this page before it asks the panel for a ticket: a replayed or parallel-submitted code is a counted
   * failure on the server.
   */
  post<T>(path: string, body: { code?: string; totp?: string; ticket?: never } & Record<string, unknown>, schema: z.ZodType<T>): Promise<Result<T>>;
  /*
   * One fresh ticket for a terminal frame (dangerous_issue, dangerous_confirm), under the same guards as post: one
   * request at a time, and a code given here counts as sent from now on (the frame carrying it is sent next).
   */
  ticket(code?: string): Promise<Result<string>>;
};

const REMEMBERED_CODES = 16;

export function createPoster(bridge: Pick<ExecutorBridge, "requestTicket">): Poster {
  let inFlight = false;
  const sent: string[] = [];
  /* the ticket for a request carrying code, or why there is none; the code is remembered once a ticket is in hand */
  const take = async (code: string | undefined): Promise<Result<string>> => {
    if (code !== undefined && sent.includes(code)) return { ok: false, failure: { kind: "local", code: "code_reused" } };
    let ticket: string;
    try {
      ticket = await bridge.requestTicket();
    } catch (e) {
      return { ok: false, failure: { kind: "local", code: e instanceof BridgeError ? e.code : "no_ticket" } };
    }
    if (code !== undefined) {
      sent.push(code);
      if (sent.length > REMEMBERED_CODES) sent.shift();
    }
    return { ok: true, value: ticket };
  };
  return {
    async post(path, body, schema) {
      if (inFlight) return { ok: false, failure: { kind: "local", code: "busy" } };
      inFlight = true;
      try {
        const t = await take(body.code ?? body.totp);
        if (!t.ok) return t;
        return await run(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...body, ticket: t.value }) }, schema);
      } finally {
        inFlight = false;
      }
    },
    async ticket(code) {
      if (inFlight) return { ok: false, failure: { kind: "local", code: "busy" } };
      inFlight = true;
      try {
        return await take(code);
      } finally {
        inFlight = false;
      }
    },
  };
}

/*
 * POSTs to a route of an open change session with its bearer token (never in the URL, no cookie, no ticket, no
 * code: the token is the session's, held in memory only). The executor locks the session per action.
 */
export function sessionPost<T>(path: string, token: string, body: Record<string, unknown>, schema: z.ZodType<T>): Promise<Result<T>> {
  return run(path, { method: "POST", headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` }, body: JSON.stringify(body) }, schema);
}

/* GET /keys.json of the executor origin (the gateway's own file, not /x): the domain public keys, parsed by the caller. */
export function getKeys(signal?: AbortSignal): Promise<Result<unknown>> {
  return run("/keys.json", { method: "GET", signal }, z.unknown());
}
