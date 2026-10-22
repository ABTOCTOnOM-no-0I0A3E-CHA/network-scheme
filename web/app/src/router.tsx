import { createRouter, type RouterHistory } from "@tanstack/react-router";
import { stepUpStore } from "@/features/common/stepup";
import { setUnauthorizedHandler } from "@/lib/api";
import { queryClient } from "@/lib/query";
import { rootRoute } from "@/routes/__root";
import { discoveryRoute } from "@/routes/discovery";
import { devicesRoute } from "@/routes/devices";
import { deviceRoute } from "@/routes/devices.$id";
import { sectionRoutes, shellRoute } from "@/routes";
import { loginRoute } from "@/routes/login";

const routeTree = rootRoute.addChildren([loginRoute, shellRoute.addChildren([...sectionRoutes, devicesRoute, deviceRoute, discoveryRoute])]);

/** Builds the application router (history is injectable for tests) and wires the global 401 handler. */
export function buildRouter(history?: RouterHistory) {
  const r = createRouter({ routeTree, history });
  setUnauthorizedHandler(() => {
    /* a pending step-up prompt must not outlive the session (it would replay the request under the next login) */
    stepUpStore.settle(false);
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
