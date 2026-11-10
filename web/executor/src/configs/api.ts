import { z } from "zod";
import { failureMessage, type Failure, type Message } from "../errors";

/*
 * Unmasked configurations (cmd/executor/internal/unmask, Task 4d.1): POST /x/configs lists a device's versions (grant
 * unmask with write on the device's write group, one change TOTP code); config.view and config.export are described
 * through /x/confirm/issue and confirmed only on their own routes with the next code.
 */
export const ACTION_VIEW = "config.view";
export const ACTION_EXPORT = "config.export";
export type ConfigAction = typeof ACTION_VIEW | typeof ACTION_EXPORT;

/* A configuration is at most 4 MiB (backups.config_version); the answer's text is bounded a little above. */
export const MAX_CONFIG = 5 << 20;

const text = (n: number) => z.string().max(n);

export const versionSchema = z.object({
  version_id: z.number().int().positive(),
  device_id: z.number().int().positive(),
  taken_at: text(64),
  source: text(32),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  size: z.number().int().nonnegative(),
});
export type Version = z.infer<typeof versionSchema>;
export const listAnswer = z.object({ result: z.array(versionSchema).max(1000) });

export const challengeSchema = z.object({
  challenge_id: text(64),
  action: z.enum([ACTION_VIEW, ACTION_EXPORT]),
  h: z.string().regex(/^[0-9a-f]{64}$/),
  fields: z.array(z.object({ key: text(64), value: text(512) })).max(256),
  expires: text(64),
});
export type Challenge = z.infer<typeof challengeSchema>;

export const shownAnswer = z.object({
  result: z.object({
    device_id: z.number().int(),
    version_id: z.number().int(),
    sha256: z.string().regex(/^[0-9a-f]{64}$/),
    taken_at: text(64),
    text: text(MAX_CONFIG),
  }),
});
export type Shown = z.infer<typeof shownAnswer>["result"];

const REFUSALS = ["config_tampered", "view_limit", "changed", "mismatch", "not_found", "not_registered", "bad_params"];

export function messageOf(f: Failure): Message {
  if (f.kind === "http" && f.status === 422) return { key: REFUSALS.includes(f.code) ? `executor.configs.refused.${f.code}` : "executor.configs.refused.other" };
  if (f.kind === "http" && f.status === 403 && f.code !== "origin") return { key: "executor.configs.refused.denied" };
  if (f.kind === "http" && f.status === 503 && f.code === "unmask_busy") return { key: "executor.configs.refused.unmask_busy" };
  return failureMessage(f);
}

/* The challenge must be for this action on exactly this device and version (the executor described it, the UI checks). */
export function matches(c: Challenge, action: ConfigAction, v: Pick<Version, "device_id" | "version_id">): boolean {
  const f = Object.fromEntries(c.fields.map((x) => [x.key, x.value]));
  return c.action === action && f.device_id === String(v.device_id) && f.version_id === String(v.version_id);
}

/*
 * Saves text as a file. The executor bundle makes no blob: URLs (build.test): a data: URL of the text, with the
 * download attribute (the panel's frame allows downloads). Never navigated to, never rendered.
 */
export function saveText(name: string, body: string): void {
  const a = document.createElement("a");
  a.href = "data:text/plain;charset=utf-8," + encodeURIComponent(body);
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}
