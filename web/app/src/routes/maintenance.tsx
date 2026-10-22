import { createRoute } from "@tanstack/react-router";
import { canListGroups, canManageMaintenance } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { MaintenancePage } from "@/features/maintenance/MaintenancePage";
import { shellRoute } from "./index";

function Page() {
  const { data: session } = useSession();
  return <MaintenancePage canManage={canManageMaintenance(session)} canListGroups={canListGroups(session)} />;
}

/** Maintenance windows at /maintenance. */
export const maintenanceRoute = createRoute({ getParentRoute: () => shellRoute, path: "/maintenance", component: Page });
