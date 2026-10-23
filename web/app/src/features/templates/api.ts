import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";

type S = components["schemas"];
export type Template = S["Template"];
export type Trigger = S["Trigger"];

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

export const templateKeys = {
  all: ["templates"] as const,
  list: ["templates", "list"] as const,
  triggers: (id: number) => ["templates", "triggers", id] as const,
};

/** Templates visible to the caller. */
export function useTemplates() {
  return useQuery({ queryKey: templateKeys.list, retry: false, queryFn: async () => unwrap(await api.GET("/api/templates")) });
}

/** Triggers of one template. */
export function useTriggers(templateId: number) {
  return useQuery({
    queryKey: templateKeys.triggers(templateId),
    retry: false,
    queryFn: async () => unwrap(await api.GET("/api/templates/{id}/triggers", { params: { path: { id: templateId } } })),
  });
}

export type TemplateCreate = { name: string; driver?: string; group_id?: number; interval_avail_s: number | null; interval_metrics_s: number | null; interval_inventory_s: number | null };
export type TemplatePatch = Partial<Pick<TemplateCreate, "name" | "interval_avail_s" | "interval_metrics_s" | "interval_inventory_s">>;
export type TriggerCreate = Pick<Trigger, "kind" | "params" | "duration_s" | "severity" | "name"> & { enabled: boolean };
export type TriggerPatch = Partial<Pick<Trigger, "params" | "duration_s" | "severity" | "enabled" | "name">>;

/** Every template mutation refreshes the whole templates cache. */
function useTemplateMutation<V>(fn: (v: V) => Promise<unknown>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (v: V) => withStepUp(async () => void (await fn(v))),
    onSettled: () => qc.invalidateQueries({ queryKey: templateKeys.all }),
  });
}

export const useCreateTemplate = () => useTemplateMutation((body: TemplateCreate) => api.POST("/api/templates", { params: CSRF, body }).then(unwrap));
export const useUpdateTemplate = () =>
  useTemplateMutation(({ id, body }: { id: number; body: TemplatePatch }) => api.PATCH("/api/templates/{id}", { params: { path: { id }, ...CSRF }, body }).then(unwrap));
export const useDeleteTemplate = () => useTemplateMutation((id: number) => api.DELETE("/api/templates/{id}", { params: { path: { id }, ...CSRF } }).then(unwrap));
export const useCreateTrigger = () =>
  useTemplateMutation(({ templateId, body }: { templateId: number; body: TriggerCreate }) =>
    api.POST("/api/templates/{id}/triggers", { params: { path: { id: templateId }, ...CSRF }, body }).then(unwrap),
  );
export const useUpdateTrigger = () =>
  useTemplateMutation(({ templateId, id, body }: { templateId: number; id: number; body: TriggerPatch }) =>
    api.PATCH("/api/templates/{id}/triggers/{trigger_id}", { params: { path: { id: templateId, trigger_id: id }, ...CSRF }, body }).then(unwrap),
  );
export const useDeleteTrigger = () =>
  useTemplateMutation(({ templateId, id }: { templateId: number; id: number }) =>
    api.DELETE("/api/templates/{id}/triggers/{trigger_id}", { params: { path: { id: templateId, trigger_id: id }, ...CSRF } }).then(unwrap),
  );
