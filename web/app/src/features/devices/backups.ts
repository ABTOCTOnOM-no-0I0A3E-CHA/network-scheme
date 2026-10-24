import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";

type S = components["schemas"];
export type BackupVersion = S["BackupVersion"];
export type ShowResult = S["ShowResult"];
export type ShowArgKind = "interface" | "vlan";
export type ShowArgs = { interface?: string; vlan?: number };

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };
/* how often a queued or running show result is re-read */
const SHOW_POLL_MS = 1000;

export const backupKeys = {
  all: (id: number) => ["devices", "backups", id] as const,
  list: (id: number) => ["devices", "backups", id, "list"] as const,
  state: (id: number) => ["devices", "backups", id, "state"] as const,
  version: (id: number, vid: number) => ["devices", "backups", id, "version", vid] as const,
  diff: (id: number, a: number, b: number) => ["devices", "backups", id, "diff", a, b] as const,
  showCommands: (id: number) => ["devices", "show-commands", id] as const,
  show: (rid: number) => ["show", rid] as const,
};

/** Versions of the device, newest first, chained by the opaque cursor. */
export function useBackups(id: number) {
  return useInfiniteQuery({
    queryKey: backupKeys.list(id),
    retry: false,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => unwrap(await api.GET("/api/devices/{id}/backups", { params: { path: { id }, query: { cursor: pageParam } } })),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

/** State of the last backup (needs_write, last error, newest version). */
export function useBackupState(id: number) {
  return useQuery({ queryKey: backupKeys.state(id), retry: false, queryFn: async () => unwrap(await api.GET("/api/devices/{id}/backup-state", { params: { path: { id } } })) });
}

/** One version with its masked text (device data: render as text only). */
export function useBackupVersion(id: number, vid: number | undefined) {
  return useQuery({
    queryKey: backupKeys.version(id, vid ?? 0),
    enabled: vid !== undefined,
    retry: false,
    staleTime: Infinity /* a stored version never changes */,
    queryFn: async () => unwrap(await api.GET("/api/devices/{id}/backups/{vid}", { params: { path: { id, vid: vid ?? 0 } } })),
  });
}

/** Server-side unified diff of the masked texts; `a` is the earlier version. */
export function useBackupDiff(id: number, pair: { a: number; b: number } | undefined) {
  return useQuery({
    queryKey: backupKeys.diff(id, pair?.a ?? 0, pair?.b ?? 0),
    enabled: pair !== undefined,
    retry: false,
    staleTime: Infinity,
    queryFn: async () => unwrap(await api.GET("/api/devices/{id}/backups/diff", { params: { path: { id }, query: { a: pair?.a ?? 0, b: pair?.b ?? 0 } } })),
  });
}

/** Same-origin URL of the masked copy as a text/plain attachment (a plain link works under the CSP). */
export function downloadUrl(id: number, vid: number): string {
  return `/api/devices/${id}/backups/${vid}/download`;
}

/** Queues a manual backup; resolves to the server note ("recent backup exists") if any. */
export function useBackupNow(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => withStepUp(async () => unwrap(await api.POST("/api/devices/{id}/backups", { params: { path: { id }, ...CSRF } }))?.note),
    onSettled: () => qc.invalidateQueries({ queryKey: backupKeys.all(id) }),
  });
}

/** Show commands of the device's driver with the kinds of their arguments. */
export function useShowCommands(id: number) {
  return useQuery({
    queryKey: backupKeys.showCommands(id),
    retry: false,
    queryFn: async () => unwrap(await api.GET("/api/devices/{id}/show-commands", { params: { path: { id } } })).commands,
  });
}

/** Queues a show command; resolves to the result id. */
export function useRunShow(id: number) {
  return useMutation({
    mutationFn: (body: { key: string; args: ShowArgs }) => withStepUp(async () => unwrap(await api.POST("/api/devices/{id}/show", { params: { path: { id }, ...CSRF }, body })).id),
  });
}

/** A show result, re-read every second while it is queued or running. */
export function useShowResult(rid: number | undefined) {
  return useQuery({
    queryKey: backupKeys.show(rid ?? 0),
    enabled: rid !== undefined,
    retry: false,
    queryFn: async () => unwrap(await api.GET("/api/show/{id}", { params: { path: { id: rid ?? 0 } } })),
    refetchInterval: (q) => (q.state.error || q.state.data?.status === "done" || q.state.data?.status === "failed" ? false : SHOW_POLL_MS),
  });
}
