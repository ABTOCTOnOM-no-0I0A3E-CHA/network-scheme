import type { TFunction } from "i18next";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { ApiError } from "@/features/common/stepup";

/** Localized message for a failed call: the API error code, a network error or an unknown failure. The server's own text is never shown. */
export function errText(t: TFunction, err: unknown): string {
  return t(err instanceof ApiError ? errorKey({ error: { code: err.code } }) : thrownKey(err));
}
