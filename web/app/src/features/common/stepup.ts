import { errorCode } from "@/features/auth/errors";

/** Failed API call carrying the server's `error.code` (the message is never kept). */
export class ApiError extends Error {
  constructor(
    readonly code: string | undefined,
    readonly status: number,
  ) {
    super(code ?? `http ${status}`);
  }
}

/** Thrown by `withStepUp` when the user dismissed the step-up dialog. */
export class StepUpCancelled extends Error {
  constructor() {
    super("stepup cancelled");
  }
}

/** Result shape of an openapi-fetch call. */
type Result<T> = { data?: T; error?: unknown; response: Response };

/** Returns `data` of a successful call; throws `ApiError` otherwise. */
export function unwrap<T>(r: Result<T>): T {
  if (!r.response.ok) throw new ApiError(errorCode(r.error), r.response.status);
  return r.data as T;
}

type Listener = () => void;
let pending: Promise<boolean> | undefined;
let resolvePending: ((ok: boolean) => void) | undefined;
const listeners = new Set<Listener>();

/** Store for `StepUpDialog`: open while a step-up prompt is waiting for the user. */
export const stepUpStore = {
  subscribe(l: Listener) {
    listeners.add(l);
    return () => void listeners.delete(l);
  },
  isOpen: () => pending !== undefined,
  /** Closes the prompt; `ok` = the server accepted the code. */
  settle(ok: boolean) {
    const r = resolvePending;
    pending = undefined;
    resolvePending = undefined;
    listeners.forEach((l) => l());
    r?.(ok);
  },
};

/* Concurrent requests share one prompt. */
function requestStepUp(): Promise<boolean> {
  if (!pending) {
    pending = new Promise<boolean>((resolve) => {
      resolvePending = resolve;
    });
    listeners.forEach((l) => l());
  }
  return pending;
}

/**
 * Runs `fn`; on `stepup_required` asks for a TOTP code and repeats `fn` exactly
 * once. A dismissed dialog throws `StepUpCancelled` without repeating.
 */
export async function withStepUp<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    if (!(e instanceof ApiError) || e.code !== "stepup_required") throw e;
    if (!(await requestStepUp())) throw new StepUpCancelled();
    return fn();
  }
}
