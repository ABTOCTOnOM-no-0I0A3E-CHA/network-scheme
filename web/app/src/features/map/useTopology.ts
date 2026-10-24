import { useCallback, useEffect, useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { unwrap, withStepUp } from "@/features/common/stepup";
import { useProblems, type ProblemFilter } from "@/features/problems/api";
import { api } from "@/lib/api";
import type { PositionItem } from "./positions";
import { severityByDevice, type Topology } from "./semanticZoom";

type S = components["schemas"];
export type MapView = S["MapView"];
export type MapAreaKind = S["MapAreaKind"];
export type AreaBody = { parent_id?: number | null; kind: MapAreaKind; name: string; x: number; y: number; w: number; h: number };

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

/* devices change state and links appear in the background: refetched while the map is open (problems also arrive over the WebSocket) */
export const TOPOLOGY_REFRESH_MS = 30_000;

export const topologyKeys = {
  all: ["topology"] as const,
  one: (viewId: number | undefined) => ["topology", viewId ?? null] as const,
  views: ["map", "views"] as const,
};

/** Topology of a view (all visible devices and links when no view is chosen). */
export function useTopology(viewId: number | undefined, enabled = true) {
  return useQuery({
    enabled,
    queryKey: topologyKeys.one(viewId),
    retry: false,
    refetchInterval: TOPOLOGY_REFRESH_MS,
    queryFn: async () => unwrap(await api.GET("/api/topology", { params: { query: { view_id: viewId } } })),
  });
}

export function useViews() {
  return useQuery({ queryKey: topologyKeys.views, retry: false, queryFn: async () => unwrap(await api.GET("/api/map/views")) });
}

const MAX_PROBLEM_PAGES = 10;
const OPEN: ProblemFilter[] = [
  { state: "problem", suppressed: "false" },
  { state: "acknowledged", suppressed: "false" },
];

/* pages through up to 10 pages (1000 problems) of a list */
function useDrain(q: ReturnType<typeof useProblems>): void {
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = q;
  const pages = q.data?.pages.length ?? 0;
  useEffect(() => {
    if (hasNextPage && !isFetchingNextPage && pages < MAX_PROBLEM_PAGES) void fetchNextPage();
  }, [hasNextPage, isFetchingNextPage, fetchNextPage, pages]);
}

/** Worst open-problem severity per device. Refreshes with the problem queries (WebSocket invalidation and the 30 s poll). */
export function useOpenProblemSeverity() {
  const a = useProblems(OPEN[0]);
  const b = useProblems(OPEN[1]);
  useDrain(a);
  useDrain(b);
  const pa = a.data?.pages;
  const pb = b.data?.pages;
  return useMemo(() => severityByDevice([...(pa ?? []), ...(pb ?? [])].flatMap((p) => p.items)), [pa, pb]);
}

/** Replaces the positions of the given devices in a cached topology (so a saved drag does not jump back before the refetch). */
export function patchPositions(t: Topology, items: PositionItem[]): Topology {
  const m = new Map(items.map((i) => [i.device_id, i]));
  return { ...t, nodes: t.nodes.map((n) => (m.has(n.device_id) ? { ...n, x: m.get(n.device_id)!.x, y: m.get(n.device_id)!.y, pinned: m.get(n.device_id)!.pinned } : n)) };
}

/** Stores a batch of positions of a view (map.manage). */
export function useSavePositions(viewId: number | undefined) {
  const qc = useQueryClient();
  return useCallback(
    async (items: PositionItem[]): Promise<void> => {
      if (viewId === undefined) return;
      await withStepUp(async () => void unwrap(await api.PUT("/api/map/views/{id}/positions", { params: { path: { id: viewId }, ...CSRF }, body: { items } })));
      qc.setQueryData<Topology>(topologyKeys.one(viewId), (t) => (t ? patchPositions(t, items) : t));
    },
    [qc, viewId],
  );
}

function useAdminMutation<V>(fn: (v: V) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: V) => withStepUp(async () => void (await fn(v))),
    onSettled: () => qc.invalidateQueries({ queryKey: ["map"] }).then(() => qc.invalidateQueries({ queryKey: topologyKeys.all })),
  });
}

export const useCreateView = () =>
  useAdminMutation(async (body: { name: string; kind: MapView["kind"]; background_id?: number | null }) => unwrap(await api.POST("/api/map/views", { params: CSRF, body })));

export const usePatchView = () =>
  useAdminMutation(async (v: { id: number; body: { name?: string; kind?: MapView["kind"]; background_id?: number | null } }) =>
    unwrap(await api.PATCH("/api/map/views/{id}", { params: { path: { id: v.id }, ...CSRF }, body: v.body })),
  );

export const useDeleteView = () => useAdminMutation(async (id: number) => unwrap(await api.DELETE("/api/map/views/{id}", { params: { path: { id }, ...CSRF } })));

export const useCreateArea = (viewId: number) =>
  useAdminMutation(async (body: AreaBody) => unwrap(await api.POST("/api/map/views/{id}/areas", { params: { path: { id: viewId }, ...CSRF }, body })));

export const usePatchArea = (viewId: number) =>
  useAdminMutation(async (v: { id: number; body: Partial<AreaBody> }) =>
    unwrap(await api.PATCH("/api/map/views/{id}/areas/{area_id}", { params: { path: { id: viewId, area_id: v.id }, ...CSRF }, body: v.body })),
  );

export const useDeleteArea = (viewId: number) =>
  useAdminMutation(async (id: number) => unwrap(await api.DELETE("/api/map/views/{id}/areas/{area_id}", { params: { path: { id: viewId, area_id: id }, ...CSRF } })));

/** Uploads an image; resolves to the new background id. */
export function useUploadBackground() {
  return useMutation({
    mutationFn: (file: File) =>
      withStepUp(async () => {
        const r = unwrap(
          await api.POST("/api/map/backgrounds", {
            params: CSRF,
            body: { file: file as unknown as string },
            bodySerializer: (b) => {
              const fd = new FormData();
              fd.append("file", b.file as unknown as Blob);
              return fd;
            },
          }),
        );
        return r.id;
      }),
  });
}
