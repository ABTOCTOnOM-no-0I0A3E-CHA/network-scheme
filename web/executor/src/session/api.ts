import { z } from "zod";
import { failureMessage, type Failure, type Message } from "../errors";

/*
 * The change session routes (cmd/executor/internal/web/sessions.go, internal/session): POST /x/sessions {ticket, totp,
 * device_ids}, /x/sessions/{id}/{attach,extend} {ticket, totp}; with the bearer token /x/sessions/{id}/close {} and
 * /x/sessions/{id}/{diff,save,commit,form,form-apply}; the rollback is the confirm(H) action session.rollback.
 * Every string here is device or executor text: shown as text only.
 */
export const SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const sessionId = z.string().regex(SESSION_ID);
const sha = z.string().regex(/^[0-9a-f]{64}$/);
const text = (n: number) => z.string().max(n);
export const LINES = ["mes6", "mes10", "esr"] as const;
export type Line = (typeof LINES)[number] | string;

/* address:port and write group from the executor's registry, model and firmware from the device (review 4c.6 I2) */
export const openedDevice = z.object({
  device_id: z.number().int().positive(),
  line: text(16),
  pre_sha256: sha,
  address: text(64),
  write_group: text(128),
  model: text(128),
  firmware: text(128),
});
export type OpenedDevice = z.infer<typeof openedDevice>;
export const openedSchema = z.object({
  session_id: sessionId,
  token: z.string().min(1).max(128).optional(),
  expires: z.iso.datetime({ offset: true }),
  idle_seconds: z.number().int().nonnegative(),
  devices: z.array(openedDevice).min(1).max(64),
});
export type Opened = z.infer<typeof openedSchema>;
export const openedAnswer = z.object({ result: openedSchema });

export const deviceDiff = z.object({
  device_id: z.number().int(),
  line: text(16),
  pre_sha256: sha,
  sha256: sha,
  diff: z.string().max(8 << 20),
  too_large: z.boolean().optional(),
  commit_pending_until: z.iso.datetime({ offset: true }).optional(),
});
export type DeviceDiff = z.infer<typeof deviceDiff>;
export const diffAnswer = z.object({ result: z.array(deviceDiff).max(64) });
export const oneDiffAnswer = z.object({ result: deviceDiff });
export const formLinesAnswer = z.object({ result: z.object({ device_id: z.number().int(), lines: z.array(text(2048)).min(1).max(256) }) });
export const formAppliedAnswer = z.object({ result: z.object({ sent: z.number().int().nonnegative(), diff: deviceDiff }) });
export const closedAnswer = z.object({ result: z.object({ closed: z.literal(true) }) });

/* session.rollback: the challenge and the result of its confirmation ({devices: [{device_id, sha256?, error?}]}). */
export const ROLLBACK = "session.rollback";
export const challengeSchema = z.object({
  challenge_id: text(64),
  action: z.string().max(64),
  h: sha,
  fields: z.array(z.object({ key: text(64), value: text(512) })).max(256),
  expires: text(64),
});
export type Challenge = z.infer<typeof challengeSchema>;
export const rolledBack = z.object({ device_id: z.number().int(), sha256: sha.optional(), error: text(64).optional() });
export type RolledBack = z.infer<typeof rolledBack>;
export const rollbackAnswer = z.object({ action: z.literal(ROLLBACK), result: z.object({ devices: z.array(rolledBack).max(64) }) });

/* The GUI forms of a session (cmd/executor/internal/drivers/form.go): which fields each kind uses. */
export type FormField = "interface" | "description" | "up" | "vlan" | "name";
export const FORMS: Record<string, FormField[]> = {
  "interface-description": ["interface", "description"],
  "interface-state": ["interface", "up"],
  "access-vlan": ["interface", "vlan"],
  "vlan-create": ["vlan"],
  "vlan-name": ["vlan", "name"],
  "vlan-delete": ["vlan"],
};
export type FormValues = { kind: string; interface: string; description: string; up: boolean; vlan: number; name: string };
export const EMPTY_FORM: FormValues = { kind: "interface-description", interface: "", description: "", up: true, vlan: 0, name: "" };

/* Refusal codes of the session and its actions (422) with a text of their own; anything else is a generic refusal. */
export const REFUSALS = [
  "bad_devices", "too_many_devices", "outside_window", "two_person", "writes_disabled", "model_unverified", "no_host_key",
  "host_key_mismatch", "no_credential", "device_busy", "not_exclusive", "line_mismatch", "policy_invalid", "mgmt_unknown",
  "config_changed", "device_failed", "no_session", "recording_failed", "recording_full", "no_device", "not_applicable",
  "nothing_to_confirm", "diff_changed", "health_failed", "snapshot_tampered", "bad_form", "form_not_safe", "changed",
  "commit_timer", "rollback_unavailable", "rollback_failed", "superseded", "commit_pending", "save_mismatch", "rollback_mismatch",
  "no_inverse",
] as const;

/* The text key of a refusal code, or undefined when it has none. */
export function refusalKey(code: string): string | undefined {
  return (REFUSALS as readonly string[]).includes(code) ? `executor.session.refused.${code}` : undefined;
}

/* What a failed session request says: its own refusal texts, the ended session (401/no_session), then the common ones. */
export function sessionMessage(f: Failure): Message {
  if (f.kind === "http" && f.status === 422) return { key: refusalKey(f.code) ?? "executor.session.refused.other" };
  if (f.kind === "http" && f.status === 401) return { key: "executor.session.refused.no_session" };
  if (f.kind === "http" && f.status === 503 && f.code === "outcome_unknown") return { key: "executor.session.outcomeUnknown" };
  return failureMessage(f);
}

/* True when the failure means the session is gone (closed, timed out, interrupted, or another token took it over). */
export function sessionGone(f: Failure): boolean {
  return f.kind === "http" && (f.status === 401 || (f.status === 422 && f.code === "no_session"));
}

/*
 * What the panel may preselect through the URL fragment of the frame (#device=12,14 or #replay=<session>&device=12).
 * Untrusted: only parsed into ids that prefill fields the user still confirms; never a decision.
 */
export type Preset = { devices: number[]; replay?: { session: string; device: number } };
export function parsePreset(hash: string): Preset {
  const p = new URLSearchParams(hash.replace(/^#/, ""));
  const ids = (p.get("device") ?? "").split(",").filter((s) => /^\d{1,18}$/.test(s)).map(Number).filter((n) => n > 0).slice(0, 64);
  const s = p.get("replay") ?? "";
  return { devices: ids, replay: SESSION_ID.test(s) && ids.length === 1 ? { session: s, device: ids[0] } : undefined };
}
