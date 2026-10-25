import { createRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { canAckProblems, canBackupDevices, canListGroups, canManageDevices, canPollDevices, canShowDevices } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { DeviceCard, TABS, type TabId } from "@/features/devices/DeviceCard";
import { shellRoute } from "./index";

function DevicePage() {
  const { t } = useTranslation();
  const { id } = deviceRoute.useParams();
  const { tab, if: ifIndex } = deviceRoute.useSearch();
  const { data: session } = useSession();
  const n = /^\d{1,15}$/.test(id) ? Number(id) : 0;
  if (n <= 0) return <h1 className="text-xl font-semibold">{t("card.notFound")}</h1>;
  return <DeviceCard id={n} canPoll={canPollDevices(session)} canManage={canManageDevices(session)} canAck={canAckProblems(session)} canListGroups={canListGroups(session)} canShow={canShowDevices(session)} canBackup={canBackupDevices(session)} tab={tab} ifIndex={ifIndex} />;
}

/** Device card at /devices/<id>; `?tab=` opens a tab and `?if=` the interface of the graphs tab (the command palette links here). */
export const deviceRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: "/devices/$id",
  validateSearch: (s: Record<string, unknown>): { tab?: TabId; if?: number } => {
    const n = Number(s.if);
    return {
      ...(typeof s.tab === "string" && (TABS as string[]).includes(s.tab) ? { tab: s.tab as TabId } : {}),
      ...(Number.isInteger(n) && n > 0 && n <= 2147483647 ? { if: n } : {}),
    };
  },
  component: DevicePage,
});
