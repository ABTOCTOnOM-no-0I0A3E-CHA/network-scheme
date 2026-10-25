import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import type { paths } from "@/api/schema";
import { unwrap } from "@/features/common/stepup";
import { api } from "@/lib/api";

export type SearchResults = paths["/api/search"]["get"]["responses"]["200"]["content"]["application/json"];

/** Query bounds of GET /api/search: shorter finds nothing, longer is rejected. */
export const SEARCH_MIN = 2;
export const SEARCH_MAX = 100;
export const SEARCH_DEBOUNCE_MS = 250;

/** value, updated only after it has stayed unchanged for ms. */
export function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const h = setTimeout(() => setV(value), ms);
    return () => clearTimeout(h);
  }, [value, ms]);
  return v;
}

/** Global search over the caller's devices (GET /api/search); idle while the trimmed query is shorter than SEARCH_MIN or enabled is false. */
export function useGlobalSearch(query: string, enabled: boolean) {
  const q = query.trim();
  return useQuery({
    queryKey: ["search", q],
    enabled: enabled && q.length >= SEARCH_MIN,
    placeholderData: keepPreviousData,
    queryFn: async () => unwrap(await api.GET("/api/search", { params: { query: { q } } })),
  });
}
