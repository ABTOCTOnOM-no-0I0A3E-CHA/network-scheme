import { createRouter, type RouterHistory } from "@tanstack/react-router";
import { setUnauthorizedHandler } from "@/lib/api";
import { queryClient } from "@/lib/query";
import { rootRoute } from "@/routes/__root";
import { devicesRoute } from "@/routes/devices";
import { sectionRoutes, shellRoute } from "@/routes";
import { loginRoute } from "@/routes/login";

const routeTree = rootRoute.addChildren([loginRoute, shellRoute.addChildren([...sectionRoutes, devicesRoute])]);

/** Builds the application router (history is injectable for tests) and wires the global 401 handler. */
export function buildRouter(history?: RouterHistory) {
  const r = createRouter({ routeTree, history });
  setUnauthorizedHandler(() => {
    queryClient.clear();
    void r.navigate({ to: "/login" });
  });
  return r;
}

/** Application router. */
export const router = buildRouter();

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
