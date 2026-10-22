import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";

type S = components["schemas"];
export type NmsEvent = S["Event"];
export type EventSeverity = S["EventSeverity"];
export type UnidentifiedTrap = S["UnidentifiedTrap"];
export type SystemStatus = S["SystemStatus"];

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

/** Server-side filter of the feed; `from`/`to` are ISO times. */
export type EventQuery = { kind?: "syslog" | "trap"; deviceId?: number; severityMin?: EventSeverity; from: string; to?: string; q?: string };

export const eventKeys = {
  all: ["events"] as const,
  feed: (f: EventQuery) => ["events", "feed", f] as const,
  unidentified: (from: string, to?: string) => ["events", "unidentified", from, to ?? null] as const,
  status: ["system", "status"] as const,
};

export const PAGE_LIMIT = 100;

/** Feed pages chained by the opaque cursor; the filters are repeated with every page. */
export function useEvents(f: EventQuery, enabled = true) {
  return useInfiniteQuery({
    queryKey: eventKeys.feed(f),
    enabled,
    retry: false,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) =>
      unwrap(
        await api.GET("/api/events", {
          params: { query: { kind: f.kind, device_id: f.deviceId, severity_min: f.severityMin, from: f.from, to: f.to, q: f.q || undefined, cursor: pageParam, limit: PAGE_LIMIT } },
        }),
      ),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

/** Traps no rule names, grouped by OID. */
export function useUnidentified(from: string, to?: string) {
  return useInfiniteQuery({
    queryKey: eventKeys.unidentified(from, to),
    retry: false,
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }) => unwrap(await api.GET("/api/events/unidentified", { params: { query: { from, to, cursor: pageParam, limit: PAGE_LIMIT } } })),
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
}

export type TrapRuleCreate = { trap_oid: string; name: string; severity: EventSeverity };

/** Names a trap OID; the unidentified list is refreshed afterwards. */
export function useCreateTrapRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: TrapRuleCreate) =>
      withStepUp(async () => {
        unwrap(await api.POST("/api/trap-rules", { params: CSRF, body }));
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: eventKeys.all }),
  });
}

/** Pollers, eventd, database and queue counters (system.read); refreshed every 15 s. */
export function useSystemStatus() {
  return useQuery({
    queryKey: eventKeys.status,
    retry: false,
    refetchInterval: 15_000,
    queryFn: async () => unwrap(await api.GET("/api/system/status")),
  });
}

export type Varbind = { oid: string; type: string; value: string; truncated: boolean };

/**
 * Normalizes the varbinds of a trap for display. Anything that is not the expected
 * array of objects falls back to a single JSON text row, so nothing is lost or interpreted.
 */
export function parseVarbinds(raw: unknown): Varbind[] | string | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!Array.isArray(raw)) return JSON.stringify(raw, null, 1);
  const out: Varbind[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null) return JSON.stringify(raw, null, 1);
    const o = Object.fromEntries(Object.entries(item).map(([k, v]) => [k.toLowerCase(), v]));
    const str = (v: unknown) => (typeof v === "string" ? v : v === undefined || v === null ? "" : JSON.stringify(v));
    out.push({ oid: str(o.oid), type: str(o.type), value: str(o.value), truncated: o.truncated === true });
  }
  return out;
}
