import { createRoute, useNavigate } from "@tanstack/react-router";
import { canManageDevices } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { DiscoveryPage } from "@/features/discovery/DiscoveryPage";
import { shellRoute } from "./index";

function Page() {
  const navigate = useNavigate();
  const { data: session } = useSession();
  return <DiscoveryPage canManage={canManageDevices(session)} onOpenDevice={(id) => void navigate({ to: "/devices/$id", params: { id: String(id) } })} />;
}

/** Subnet scans and the inbox of finds. */
export const discoveryRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/discovery",
  component: Page,
});
