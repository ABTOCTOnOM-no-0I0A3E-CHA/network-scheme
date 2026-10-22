import { createRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { canReadSystem } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { SystemStatus } from "@/features/system/SystemStatus";
import { shellRoute } from "./index";

function SystemPage() {
  const { t } = useTranslation();
  const { data: session } = useSession();
  return (
    <section className="grid gap-4">
      <h1 className="text-xl font-semibold">{t("nav.health")}</h1>
      {canReadSystem(session) ? <SystemStatus /> : <p className="text-sm text-muted-foreground">{t("system.forbidden")}</p>}
    </section>
  );
}

/** System status at /health (system.read). */
export const systemRoute = createRoute({ getParentRoute: () => shellRoute, path: "/health", component: SystemPage });
