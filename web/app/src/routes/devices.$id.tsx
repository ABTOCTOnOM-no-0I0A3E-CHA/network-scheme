import { createRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { canListGroups, canManageDevices, canPollDevices } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { DeviceCard } from "@/features/devices/DeviceCard";
import { shellRoute } from "./index";

function DevicePage() {
  const { t } = useTranslation();
  const { id } = deviceRoute.useParams();
  const { data: session } = useSession();
  const n = /^\d{1,15}$/.test(id) ? Number(id) : 0;
  if (n <= 0) return <h1 className="text-xl font-semibold">{t("card.notFound")}</h1>;
  return <DeviceCard id={n} canPoll={canPollDevices(session)} canManage={canManageDevices(session)} canListGroups={canListGroups(session)} />;
}

/** Device card at /devices/<id>. */
export const deviceRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/devices/$id",
  component: DevicePage,
});
