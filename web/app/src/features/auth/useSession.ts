import { queryOptions, useQuery } from "@tanstack/react-query";
import { api, clearCsrfToken } from "@/lib/api";
import { queryClient } from "@/lib/query";

export type Session = { id: number; username: string; roles: { role: string; group_id: number | null }[] };

/** Query for the current session; resolves to null when not logged in (401). */
export const meQuery = queryOptions({
  queryKey: ["auth", "me"],
  queryFn: async (): Promise<Session | null> => {
    const { data, response } = await api.GET("/api/auth/me");
    if (response.status === 401) return null;
    if (!data) throw new Error("me failed");
    return data;
  },
});

/** Current session (null when logged out, undefined while loading). */
export function useSession() {
  return useQuery(meQuery);
}

/** Forces a fresh GET /api/auth/me (also refreshes the CSRF token) and caches it. */
export function refreshSession(): Promise<Session | null> {
  return queryClient.fetchQuery({ ...meQuery, staleTime: 0 });
}

/** Ends the session on the server and drops every client-side trace of it. */
export async function logout(): Promise<void> {
  try {
    /* the typed header is required by the schema; the api middleware overwrites it with the real token */
    await api.POST("/api/auth/logout", { params: { header: { "X-CSRF-Token": "" } } });
  } finally {
    clearCsrfToken();
    queryClient.clear();
  }
}
