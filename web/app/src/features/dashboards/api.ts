import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { unwrap } from "@/features/common/stepup";
import { api } from "@/lib/api";

type S = components["schemas"];
export type Dashboard = S["Dashboard"];
export type DashboardDetail = S["DashboardDetail"];
export type DashboardWidget = S["DashboardWidget"];
export type WidgetType = S["WidgetType"];
export type Role = NonNullable<Dashboard["default_for_role"]>;

/** A widget as saved: id is absent for one added since the last save. */
export type WidgetSave = { id?: number; type: string; x: number; y: number; w: number; h: number; config: Record<string, unknown> };

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

export const dashboardKeys = {
  all: ["dashboards"] as const,
  list: ["dashboards", "list"] as const,
  one: (id: number) => ["dashboards", "one", id] as const,
};

/** The caller's personal dashboards and every shared one. */
export function useDashboards() {
  return useQuery({ queryKey: dashboardKeys.list, queryFn: async () => unwrap(await api.GET("/api/dashboards")) });
}

/** One dashboard with its widgets. */
export function useDashboard(id: number | undefined) {
  return useQuery({
    queryKey: dashboardKeys.one(id ?? 0),
    enabled: id !== undefined,
    queryFn: async () => unwrap(await api.GET("/api/dashboards/{id}", { params: { path: { id: id ?? 0 } } })),
  });
}

/** Creates a dashboard and returns its id. */
export function useCreateDashboard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (body: { name: string; shared?: boolean }) => unwrap(await api.POST("/api/dashboards", { params: CSRF, body })).id,
    onSettled: () => qc.invalidateQueries({ queryKey: dashboardKeys.list }),
  });
}

/** Renames a dashboard or changes the role it is the default of (shared only). */
export function useUpdateDashboard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, ...body }: { id: number; name?: string; default_for_role?: Role | null }) => {
      unwrap(await api.PATCH("/api/dashboards/{id}", { params: { path: { id }, ...CSRF }, body }));
    },
    onSettled: () => qc.invalidateQueries({ queryKey: dashboardKeys.all }),
  });
}

export function useDeleteDashboard() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: number) => {
      unwrap(await api.DELETE("/api/dashboards/{id}", { params: { path: { id }, ...CSRF } }));
    },
    onSettled: () => qc.invalidateQueries({ queryKey: dashboardKeys.all }),
  });
}

/** Saves the whole widget set (layout and settings); the stored dashboard replaces the cached one. */
export function useSaveWidgets(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (widgets: WidgetSave[]) =>
      unwrap(await api.PUT("/api/dashboards/{id}/widgets", { params: { path: { id }, ...CSRF }, body: { widgets: widgets as (WidgetSave & { type: WidgetType })[] } })),
    onSuccess: (d) => qc.setQueryData(dashboardKeys.one(id), d),
  });
}

/* the first role a user holds in this order picks the default dashboard */
const ROLE_ORDER: Role[] = ["admin", "operator", "viewer", "auditor"];

/**
 * The dashboard the home page shows: the requested one when listed, else the shared default of the user's highest role,
 * else the first personal one, else the first shared one.
 */
export function pickDashboard(list: Dashboard[], roles: string[], requested?: number): Dashboard | undefined {
  const asked = list.find((d) => d.id === requested);
  if (asked) return asked;
  for (const r of ROLE_ORDER) {
    if (!roles.includes(r)) continue;
    const d = list.find((x) => x.default_for_role === r);
    if (d) return d;
  }
  return list.find((d) => !d.shared) ?? list[0];
}
