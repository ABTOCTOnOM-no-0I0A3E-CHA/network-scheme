const KNOWN = new Set([
  "invalid_credentials",
  "locked",
  "rate_limited",
  "challenge_expired",
  "session_expired",
  "unauthenticated",
  "csrf",
  "gateway_error",
  "bad_request",
  "forbidden",
  "stepup_required",
  "not_found",
  "method_not_allowed",
  "payload_too_large",
  "unsupported_media_type",
  "user_exists",
  "group_exists",
  "group_not_empty",
  "group_cycle",
  "last_admin",
  "invalid_username",
  "weak_password",
  "invalid_role",
  "address_exists",
  "not_pending",
  "stale_key",
  "cidr_too_wide",
  "too_many_points",
  "trap_rule_exists",
  "problem_resolved",
  "template_exists",
  "invalid_trigger",
  "invalid_window",
  "parent_cycle",
  "parent_too_deep",
  "too_many_triggers",
  "too_many_templates",
  "too_many_filters",
  "too_many_windows",
  "internal",
]);

/** Returns the raw `error.code` of an API error body, if any. */
export function errorCode(error: unknown): string | undefined {
  const code = (error as { error?: { code?: unknown } } | undefined)?.error?.code;
  return typeof code === "string" ? code : undefined;
}

/** Maps a thrown failure (fetch rejection = network error, anything else = unknown) to an `errors.*` key. */
export function thrownKey(e: unknown): string {
  return e instanceof TypeError ? "errors.network" : "errors.unknown";
}

/**
 * Maps an API error body to an i18n key under `errors.*`. Only `error.code` is
 * used; the server's `message` is never displayed.
 */
export function errorKey(error: unknown): string {
  const code = errorCode(error);
  return code && KNOWN.has(code) ? `errors.${code}` : "errors.unknown";
}
