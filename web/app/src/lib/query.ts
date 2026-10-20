import { QueryClient } from "@tanstack/react-query";

/** Shared query cache; module-level so route guards and the 401 handler can reach it. */
export const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
});
