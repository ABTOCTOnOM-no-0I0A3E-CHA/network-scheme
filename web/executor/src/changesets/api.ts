import { z } from "zod";
import { sessionPost, type Result } from "../client";
import { failureMessage, type Failure, type Message } from "../errors";

/*
 * Changesets (cmd/executor/internal/changeset, Phase 5): POST /x/changesets/open {ticket, totp} gives the workspace's
 * bearer token (memory only); POST /x/changesets/{op} with it: list, get (audited), progress, save, discard, dry-run,
 * stop, devices, versions. The approval is the confirm(H) action changeset.approve, confirmed only on
 * POST /x/changesets/{id}/approve/{count} with the typed device count. Every string is executor or device text: shown
 * as text only.
 */
export const CHANGESET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const APPROVE = "changeset.approve";
const id = z.string().regex(CHANGESET_ID);
const sha = z.string().regex(/^[0-9a-f]{64}$/);
const text = (n: number) => z.string().max(n);
const when = z.iso.datetime({ offset: true });

export const STATUSES = ["draft", "dry_run_ok", "dry_run_failed", "approved", "running", "done", "rolled_back", "rollback_failed", "interrupted", "discarded"] as const;
export type Status = (typeof STATUSES)[number];
/* the statuses a draft may be revised, dry-run or discarded in (changeset.editable) */
export const EDITABLE: readonly string[] = ["draft", "dry_run_ok", "dry_run_failed", "approved"];
export const TERMINAL: readonly string[] = ["done", "rolled_back", "rollback_failed", "interrupted", "discarded"];

export const openedAnswer = z.object({
  result: z.object({ token: z.string().min(1).max(128), expires: when, idle_seconds: z.number().int().nonnegative(), user_id: z.number().int(), username: text(128) }),
});
export type Workspace = z.infer<typeof openedAnswer>["result"];

export const itemSchema = z.object({
  changeset_id: id,
  title: text(512),
  kind: z.enum(["lines", "restore"]),
  author_id: z.number().int(),
  author: text(128),
  status: z.enum(STATUSES),
  device_count: z.number().int().nonnegative(),
  revision: z.number().int().positive(),
  updated: when,
});
export type Item = z.infer<typeof itemSchema>;
export const listAnswer = z.object({ result: z.array(itemSchema).max(1000) });

export const formSchema = z.object({ kind: text(64), interface: text(64), description: text(256), up: z.boolean(), vlan: z.number().int(), name: text(64) });
export type FormParams = z.infer<typeof formSchema>;
export const stepSchema = z.object({ line: text(512).optional(), form: formSchema.optional() });
export type Step = z.infer<typeof stepSchema>;
export const restoreSchema = z.object({ device_id: z.number().int().positive(), version_id: z.number().int().positive() });
export const contentSchema = z.object({
  title: text(512),
  device_ids: z.array(z.number().int().positive()).max(1000),
  steps: z.array(stepSchema).max(1000).optional(),
  vars: z.record(z.string().regex(/^\d{1,18}$/), z.record(text(32), text(128))).optional(),
  batch_size: z.number().int(),
  settle_s: z.number().int(),
  restore: z.array(restoreSchema).max(1000).optional(),
});
export type Content = z.infer<typeof contentSchema>;

export const eventSchema = z.object({
  revision: z.number().int(),
  at: when,
  kind: text(64),
  device_id: z.number().int().optional(),
  session_id: text(36).optional(),
  payload: z.unknown(),
});
export type ChangesetEvent = z.infer<typeof eventSchema>;

export const refusalSchema = z.object({ code: text(64), step: z.number().int().optional(), line: z.number().int().optional(), class: text(32).optional(), reason: text(2048).optional() });
export type DeviceRefusal = z.infer<typeof refusalSchema>;
export const deviceResultSchema = z.object({
  device_id: z.number().int(),
  address: text(64),
  write_group: text(128),
  line: text(16),
  pre_sha256: sha.optional(),
  ok: z.boolean(),
  refused: refusalSchema.optional(),
  version_id: z.number().int().optional(),
  version_sha256: sha.optional(),
});
export type DeviceResult = z.infer<typeof deviceResultSchema>;
export const previewSchema = z.object({
  device_ids: z.array(z.number().int()).max(1000),
  lines: z.array(text(2048)).max(5000),
  contexts: z.array(z.object({ line: text(2048), current: z.array(text(4096)).max(200) })).max(1000),
  diff: z.string().max(8 << 20).optional(),
});
export type PreviewGroup = z.infer<typeof previewSchema>;
export const dryRunSchema = z.object({
  running: z.boolean(),
  error: text(64).optional(),
  result: z
    .object({ revision: z.number().int(), ok: z.boolean(), plan_sha256: sha, devices: z.array(deviceResultSchema).max(1000), preview: z.array(previewSchema).max(1000).nullable() })
    .optional(),
});
export type DryRunState = z.infer<typeof dryRunSchema>;
export const runDeviceSchema = z.object({ device_id: z.number().int(), state: text(32), lines_sent: z.number().int(), error: text(256).optional(), session_id: text(36).optional() });
export type RunDevice = z.infer<typeof runDeviceSchema>;
export const runSchema = z.object({ phase: text(32), result: text(32).optional(), reason: text(256).optional(), failed_device_id: z.number().int().optional(), devices: z.array(runDeviceSchema).max(1000).nullable() });
export type RunState = z.infer<typeof runSchema>;

export const detailSchema = itemSchema.extend({
  content: contentSchema,
  events: z.array(eventSchema).max(100_000),
  dry_run: dryRunSchema.optional(),
  run: runSchema.optional(),
});
export type Detail = z.infer<typeof detailSchema>;
export const detailAnswer = z.object({ result: detailSchema });
export const savedAnswer = z.object({ result: z.object({ changeset_id: id, revision: z.number().int().positive() }) });
export const startedAnswer = z.object({ result: z.object({ started: z.literal(true), revision: z.number().int() }) });
export const okAnswer = z.object({ result: z.record(z.string(), z.boolean()) });

export const writableSchema = z.object({ device_id: z.number().int().positive(), address: text(64), write_group: text(128), line: text(16) });
export type Writable = z.infer<typeof writableSchema>;
export const devicesAnswer = z.object({ result: z.array(writableSchema).max(10000) });
export const versionSchema = z.object({ version_id: z.number().int().positive(), taken_at: when, source: text(32), sha256: sha, size: z.number().int().nonnegative() });
export type Version = z.infer<typeof versionSchema>;
export const versionsAnswer = z.object({ result: z.array(versionSchema).max(1000) });

export const challengeSchema = z.object({
  challenge_id: text(64),
  action: z.literal(APPROVE),
  h: sha,
  fields: z.array(z.object({ key: text(64), value: text(512) })).max(256),
  expires: text(64),
});
export type Challenge = z.infer<typeof challengeSchema>;
export const approvedAnswer = z.object({ result: z.object({ status: z.enum(["awaiting_second_person", "running"]), second_person_until: when.optional() }) });

/* The workspace's routes with its token (never a ticket or a code). */
export function op<T>(token: string, name: string, params: Record<string, unknown>, schema: z.ZodType<T>): Promise<Result<T>> {
  return sessionPost(`/x/changesets/${name}`, token, params, schema);
}

/* Refusal codes (422) with a text of their own. */
const REFUSALS = [
  "no_workspace", "too_many_workspaces", "bad_params", "bad_content", "not_found", "not_author", "conflict", "wrong_state", "kind_changed",
  "bad_line", "tampered", "no_grant", "line_unknown", "device_unknown", "writes_disabled", "model_unverified", "no_host_key", "no_credential",
  "restore_unavailable", "dry_run_unavailable", "dry_run_running", "dry_run_limit", "dry_run_required", "dry_run_stale", "changed",
  "device_count", "outside_window", "run_unavailable", "running", "same_person", "author_approval_required", "approval_expired",
  "approval_mismatch", "second_person_required", "h_mismatch", "too_many_approvals",
];

/* What a failed changeset request says: its own refusal texts, the closed workspace (401), then the common ones. */
export function messageOf(f: Failure): Message {
  if (f.kind === "http" && f.status === 401) return { key: "executor.changesets.refused.no_workspace" };
  if (f.kind === "http" && f.status === 422) return { key: REFUSALS.includes(f.code) ? `executor.changesets.refused.${f.code}` : "executor.changesets.refused.other" };
  if (f.kind === "http" && f.status === 503 && f.code === "outcome_unknown") return { key: "executor.session.outcomeUnknown" };
  return failureMessage(f);
}

/* True when the workspace token is no longer valid (idle, expired, or the executor restarted). */
export function workspaceGone(f: Failure): boolean {
  return f.kind === "http" && f.status === 401;
}

/* "{{name}}" placeholders of the line steps, in order of first use (the variables each device needs a value of). */
export function variablesOf(steps: Step[]): string[] {
  const out: string[] = [];
  for (const s of steps) for (const m of (s.line ?? "").matchAll(/\{\{([a-z][a-z0-9_]{0,31})\}\}/g)) if (!out.includes(m[1])) out.push(m[1]);
  return out;
}

/* The devices of a run in order, grouped as the executor runs them: the canary, then batches of batch_size. */
export function stages(devices: number[], batch: number): number[][] {
  if (devices.length === 0) return [];
  const out = [[devices[0]]];
  const b = Math.max(1, batch);
  for (let i = 1; i < devices.length; i += b) out.push(devices.slice(i, i + b));
  return out;
}

/* Device states from the stored events of a revision (the run's memory is gone after a restart, the events are not). */
const EVENT_STATE: Record<string, string> = {
  device_opened: "opened", applied: "applied", failed: "failed", rolled_back: "rolled_back", rollback_failed: "rollback_failed", saved: "saved", save_failed: "applied",
};
export function statesFromEvents(events: ChangesetEvent[], rev: number): Map<number, { state: string; session?: string; error?: string }> {
  const out = new Map<number, { state: string; session?: string; error?: string }>();
  for (const e of events) {
    const st = EVENT_STATE[e.kind];
    if (e.revision !== rev || !st || !e.device_id) continue;
    const p = (e.payload ?? {}) as Record<string, unknown>;
    const prev = out.get(e.device_id);
    out.set(e.device_id, { state: st, session: e.session_id ?? prev?.session, error: typeof p.reason === "string" ? p.reason : prev?.error });
  }
  return out;
}

/* The author's approval waiting for a second person: until when (the newest "approved" event of the revision). */
export function approvedUntil(d: Detail): Date | undefined {
  const e = [...d.events].reverse().find((x) => x.revision === d.revision && x.kind === "approved");
  const u = (e?.payload as { until?: unknown } | undefined)?.until;
  const t = typeof u === "string" ? new Date(u) : undefined;
  return t && !Number.isNaN(t.getTime()) ? t : undefined;
}

/* pre_session versions an interrupted run names ({device id: version id}), for a restore changeset. */
export function interruptedVersions(d: Detail): Record<string, number> {
  const e = [...d.events].reverse().find((x) => x.revision === d.revision && x.kind === "interrupted");
  const v = (e?.payload as { pre_session_versions?: unknown } | undefined)?.pre_session_versions;
  const p = z.record(z.string().regex(/^\d{1,18}$/), z.number().int().positive()).safeParse(v);
  return p.success ? p.data : {};
}

/* The dry-run of the stored event (short keys), when this process holds no result of its own (after a restart). */
const storedPlan = z.object({
  ok: z.boolean(),
  plan_sha256: sha,
  devices: z.array(z.object({ id: z.number().int(), a: text(64), g: text(128), l: text(16), ok: z.boolean(), r: refusalSchema.optional(), v: z.number().int().optional() })).max(1000),
});
export function storedDryRun(d: Detail): { ok: boolean; plan: string; devices: DeviceResult[] } | undefined {
  const e = [...d.events].reverse().find((x) => x.revision === d.revision && x.kind === "dry_run");
  const p = storedPlan.safeParse(e?.payload);
  if (!p.success) return undefined;
  return {
    ok: p.data.ok,
    plan: p.data.plan_sha256,
    devices: p.data.devices.map((x) => ({ device_id: x.id, address: x.a, write_group: x.g, line: x.l, ok: x.ok, refused: x.r, version_id: x.v })),
  };
}

/*
 * What the panel may preselect through the URL fragment: a changeset to open (#changeset=<id>) or a restore of a
 * version (#restore=<device>:<version>). Untrusted: only prefills what the user still checks, saves and confirms.
 */
export type ChangesetPreset = { changeset?: string; restore?: { device: number; version: number } };
export function parseChangesetPreset(hash: string): ChangesetPreset {
  const p = new URLSearchParams(hash.replace(/^#/, ""));
  const c = p.get("changeset") ?? "";
  const r = /^([1-9]\d{0,17}):([1-9]\d{0,17})$/.exec(p.get("restore") ?? "");
  return { changeset: CHANGESET_ID.test(c) ? c : undefined, restore: r ? { device: Number(r[1]), version: Number(r[2]) } : undefined };
}
