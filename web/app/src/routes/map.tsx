import { createRoute } from "@tanstack/react-router";
import { canManageMap } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { MapPage } from "@/features/map/MapPage";
import { shellRoute } from "./index";

function Page() {
  const { data: session } = useSession();
  return <MapPage canManage={canManageMap(session)} />;
}

/** Network map at /map. */
export const mapRoute = createRoute({ getParentRoute: () => shellRoute, path: "/map", component: Page });
