import createClient, { type Middleware } from "openapi-fetch";
import type { paths } from "@/api/schema";

let csrfToken: string | undefined;

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const ME_PATH = "/api/auth/me";

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
export const api = createClient<paths>({ baseUrl: window.location.origin, credentials: "same-origin" });
api.use(csrf);
