import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";

type S = components["schemas"];
export type Problem = S["Problem"];
export type ProblemDetail = S["ProblemDetail"];
export type ProblemSummary = S["ProblemSummary"];
export type EventSeverity = S["EventSeverity"];

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

export const SEVERITIES: EventSeverity[] = ["info", "warning", "average", "high", "disaster"];

/** Server-side filter of the list. */
export type ProblemFilter = { state?: Problem["state"]; severityMin?: EventSeverity; deviceId?: number; groupId?: number; suppressed?: "true" | "false" };

export const problemKeys = {
  all: ["problems"] as const,
  list: (f: ProblemFilter) => ["problems", "list", f] as const,
  one: (id: number) => ["problems", "one", id] as const,
};

export const PAGE_LIMIT = 100;

/** Problems, newest first, chained by the opaque cursor; the filters are repeated with every page. */
export function useProblems(f: ProblemFilter) {
  return useInfiniteQuery({
    queryKey: problemKeys.list(f),
    retry: false,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET("/api/problems", {
          params: { query: { state: f.state, severity_min: f.severityMin, device_id: f.deviceId, group_id: f.groupId, suppressed: f.suppressed, cursor: pageParam, limit: PAGE_LIMIT } },
        }),
      ),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

/** One problem with its acknowledgement history. */
export function useProblem(id: number, enabled = true) {
  return useQuery({
    queryKey: problemKeys.one(id),
    enabled,
    retry: false,
    queryFn: async () => unwrap(await api.GET("/api/problems/{id}", { params: { path: { id } } })),
  });
}

/** Mirrors the server rule: 1..1000 characters, not blank, no control characters except \n and \t. */
export function validateComment(c: string): boolean {
  if (c.trim() === "" || [...c].length > 1000) return false;
  /* eslint-disable-next-line no-control-regex */
  return !/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/.test(c);
}

/** Acknowledges a problem with a comment (problems.ack). */
export function useAckProblem() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, comment }: { id: number; comment: string }) =>
      withStepUp(async () => {
        unwrap(await api.POST("/api/problems/{id}/ack", { params: { path: { id }, ...CSRF }, body: { comment } }));
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: problemKeys.all }),
  });
}
