import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { deviceKeys } from "@/features/devices/api";
import { unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";

type S = components["schemas"];
export type Scan = S["Scan"];
export type Discovered = S["Discovered"];

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

/** Client-side bounds of the scan interval in seconds (the API accepts 300 s and up as well). */
export const MIN_SCAN_INTERVAL = 3600;
export const MAX_SCAN_INTERVAL = 2592000;
export const DEFAULT_SCAN_INTERVAL = 86400;

export const discoveryKeys = {
  scans: ["discovery", "scans"] as const,
  inbox: ["discovery", "inbox"] as const,
};

/** Scans of the groups the caller manages. */
export function useScans() {
  return useQuery({ queryKey: discoveryKeys.scans, queryFn: async () => unwrap(await api.GET("/api/discovery/scans")) });
}

/** Pending finds of the caller's scans, newest first. */
export function useInbox() {
  return useQuery({
    queryKey: discoveryKeys.inbox,
    queryFn: async () => unwrap(await api.GET("/api/discovery/inbox", { params: { query: { status: "pending" } } })),
  });
}

export type ScanCreate = { cidr: string; group_id: number; interval_s: number };

/** Schedules a scan; resolves to its id. */
export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: ScanCreate) => withStepUp(async () => unwrap(await api.POST("/api/discovery/scans", { params: CSRF, body })).id),
    onSettled: () => qc.invalidateQueries({ queryKey: discoveryKeys.scans }),
  });
}

/** Changes scan fields; absent fields stay as they are. */
export function useUpdateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...body }: { id: number } & Partial<Pick<Scan, "cidr" | "group_id" | "enabled" | "interval_s">>) =>
      withStepUp(async () => {
        unwrap(await api.PATCH("/api/discovery/scans/{id}", { params: { path: { id }, ...CSRF }, body }));
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: discoveryKeys.scans }),
  });
}

/** Turns a pending find into a device; resolves to the new device id. */
export function useAcceptDiscovered() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, name, group_id }: { id: number; name: string; group_id: number }) =>
      withStepUp(async () => unwrap(await api.POST("/api/discovery/inbox/{id}/accept", { params: { path: { id }, ...CSRF }, body: { name, group_id } })).id),
    onSettled: () => Promise.all([qc.invalidateQueries({ queryKey: discoveryKeys.inbox }), qc.invalidateQueries({ queryKey: deviceKeys.all })]),
  });
}

/** Hides a pending find. */
export function useIgnoreDiscovered() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      withStepUp(async () => {
        unwrap(await api.POST("/api/discovery/inbox/{id}/ignore", { params: { path: { id }, ...CSRF } }));
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: discoveryKeys.inbox }),
  });
}
