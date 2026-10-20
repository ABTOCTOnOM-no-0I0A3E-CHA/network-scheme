const KNOWN = new Set([
  "invalid_credentials",
  "locked",
  "rate_limited",
  "challenge_expired",
  "session_expired",
  "unauthenticated",
  "csrf",
]);

/** Returns the raw `error.code` of an API error body, if any. */
export function errorCode(error: unknown): string | undefined {
  const code = (error as { error?: { code?: unknown } } | undefined)?.error?.code;
  return typeof code === "string" ? code : undefined;
}

/**
 * Maps an API error body to an i18n key under `errors.*`. Only `error.code` is
 * used; the server's `message` is never displayed.
 */
export function errorKey(error: unknown): string {
  const code = errorCode(error);
  return code && KNOWN.has(code) ? `errors.${code}` : "errors.unknown";
}
