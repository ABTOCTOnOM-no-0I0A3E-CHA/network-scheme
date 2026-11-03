import { useQuery } from "@tanstack/react-query";
import { loadReadKey } from "@nms/shared/keys";

export const readKeyQueryKey = ["keys", "read"] as const;

/** Read key as a query (public data, safe to cache); invalidate it on `stale_key`. */
export function useReadKey() {
  return useQuery({ queryKey: readKeyQueryKey, queryFn: loadReadKey, staleTime: 5 * 60_000 });
}
