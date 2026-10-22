import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "@/api/schema";

let csrfToken: string | undefined;

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const ME_PATH = "/api/auth/me";
/* 401 on these is an expected part of the login flow or is handled by the route guard. */
const UNAUTH_EXEMPT = new Set([ME_PATH, "/api/auth/login", "/api/auth/totp", "/api/auth/enroll", "/api/auth/stepup"]);

let onUnauthorized: (() => void) | undefined;

/** Registers the callback run when any non-login request returns 401 (session lost). */
export function setUnauthorizedHandler(fn: (() => void) | undefined): void {
  onUnauthorized = fn;
}

/** Runs the registered session-lost callback (used where a 401 is exempt from the global handler but means session loss). */
export function notifyUnauthorized(): void {
  onUnauthorized?.();
}

/*
 * Adds X-CSRF-Token to state-changing requests and refreshes the cached token
 * from every successful GET /api/auth/me.
 */
const csrf: Middleware = {
  onRequest({ request }) {
    if (!SAFE_METHODS.has(request.method) && csrfToken) {
      request.headers.set("X-CSRF-Token", csrfToken);
    }
    return request;
  },
  async onResponse({ request, response }) {
    if (response.status === 401 && !UNAUTH_EXEMPT.has(new URL(response.url || request.url).pathname)) {
      onUnauthorized?.();
    }
    if (request.method === "GET" && response.ok && new URL(response.url || request.url).pathname === ME_PATH) {
      const body = (await response.clone().json().catch(() => undefined)) as { csrf_token?: unknown } | undefined;
      csrfToken = typeof body?.csrf_token === "string" ? body.csrf_token : undefined;
    }
    return response;
  },
};

/** Clears the cached CSRF token (on logout or session loss). */
export function clearCsrfToken(): void {
  csrfToken = undefined;
}

/*
 * The paths in openapi.yaml already carry the /api prefix, so baseUrl is the
 * origin root (explicit, so Request can resolve it); a "/api" baseUrl would produce /api/api/....
 */
/** Typed same-origin client for the panel API. */
export const api = createClient<paths>({
  baseUrl: window.location.origin,
  credentials: "same-origin",
  /* resolved per call, so a fetch patched after module load (tests, msw) is honored */
  fetch: (req) => globalThis.fetch(req),
});
api.use(csrf);
