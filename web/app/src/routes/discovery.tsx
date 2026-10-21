import { createRoute, useNavigate } from "@tanstack/react-router";
import { DiscoveryPage } from "@/features/discovery/DiscoveryPage";
import { shellRoute } from "./index";

function Page() {
  const navigate = useNavigate();
  return <DiscoveryPage onOpenDevice={(id) => void navigate({ to: "/devices/$id", params: { id: String(id) } })} />;
}

/** Subnet scans and the inbox of finds. */
export const discoveryRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/discovery",
  component: Page,
});
