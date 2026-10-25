import { createRoute } from "@tanstack/react-router";
import { DashboardPage } from "@/features/dashboards/DashboardPage";
import { shellRoute } from "./index";

function Page() {
  const { d } = dashboardsRoute.useSearch();
  return <DashboardPage requested={d} />;
}

/** "/" is the dashboards section: ?d= picks a dashboard, otherwise the default one of the user's role is shown. */
export const dashboardsRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/",
  validateSearch: (s: Record<string, unknown>): { d?: number } => {
    const v = Number(s.d);
    return Number.isInteger(v) && v > 0 ? { d: v } : {};
  },
  component: Page,
});
