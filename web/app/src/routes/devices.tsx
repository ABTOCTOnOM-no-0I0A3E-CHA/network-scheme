import { createRoute, useNavigate } from "@tanstack/react-router";
import { canManageDevices } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { DeviceList } from "@/features/devices/DeviceList";
import { shellRoute } from "./index";

function DevicesPage() {
  const { q } = devicesRoute.useSearch();
  const navigate = useNavigate();
  const { data: session } = useSession();
  return (
    <DeviceList
      canAdd={canManageDevices(session)}
      search={q ?? ""}
      onOpen={(id) => void navigate({ to: "/devices/$id", params: { id: String(id) } })}
      onSearchChange={(next) => void navigate({ to: "/devices", search: { q: next || undefined }, replace: true })}
    />
  );
}

/** Device list; `?q=` carries the search text (the command palette links here). */
export const devicesRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/devices",
  validateSearch: (s: Record<string, unknown>): { q?: string } => (typeof s.q === "string" && s.q ? { q: s.q } : {}),
  component: DevicesPage,
});
