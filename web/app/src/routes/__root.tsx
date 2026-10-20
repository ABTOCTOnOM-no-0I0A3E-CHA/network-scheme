import { createRootRoute, Outlet } from "@tanstack/react-router";

/** Root route: a bare outlet; auth guards live on the login and shell routes. */
export const rootRoute = createRootRoute({ component: Outlet });
