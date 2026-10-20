import { createRootRoute, createRoute, createRouter, Outlet } from "@tanstack/react-router";
import { Home } from "@/pages/home";

const rootRoute = createRootRoute({ component: Outlet });
const indexRoute = createRoute({ getParentRoute: () => rootRoute, path: "/", component: Home });

/** Application router; Task 14 adds the login flow and app shell routes. */
export const router = createRouter({ routeTree: rootRoute.addChildren([indexRoute]) });

declare module "@tanstack/react-router" {
  interface Register {
    router: typeof router;
  }
}
