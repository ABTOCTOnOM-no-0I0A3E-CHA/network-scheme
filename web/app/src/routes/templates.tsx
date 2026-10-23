import { createRoute } from "@tanstack/react-router";
import { canListGroups, canManageTriggers } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { TemplatesPage } from "@/features/templates/TemplatesPage";
import { shellRoute } from "./index";

function Page() {
  const { data: session } = useSession();
  return <TemplatesPage canManage={canManageTriggers(session)} canListGroups={canListGroups(session)} />;
}

/** Monitoring templates and their triggers at /templates. */
export const templatesRoute = createRoute({ getParentRoute: () => shellRoute, path: "/templates", component: Page });
