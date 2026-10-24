import { createRoute } from "@tanstack/react-router";
import { canManageMap } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { MapPage } from "@/features/map/MapPage";
import { shellRoute } from "./index";

function Page() {
  const { data: session } = useSession();
  const { view } = mapRoute.useSearch();
  return <MapPage canManage={canManageMap(session)} initialViewId={view} />;
}

/** Network map at /map. */
export const mapRoute = createRoute({ getParentRoute: () => shellRoute, path: "/map",
  validateSearch: (s: Record<string, unknown>): { view?: number } => {
    const v = Number(s.view);
    return Number.isInteger(v) && v > 0 ? { view: v } : {};
  },
  component: Page,
});
