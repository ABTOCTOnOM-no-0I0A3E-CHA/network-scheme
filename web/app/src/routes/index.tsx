import { createRoute, redirect } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { meQuery } from "@/features/auth/useSession";
import { AppShell } from "@/features/shell/AppShell";
import { NAV } from "@/features/shell/nav";
import { queryClient } from "@/lib/query";
import { rootRoute } from "./__root";

function Placeholder({ section }: { section: string }) {
  const { t } = useTranslation();
  return (
    <section>
      <h1 className="text-xl font-semibold">{t(`nav.${section}`)}</h1>
      <p className="mt-2 text-muted-foreground">{t("placeholder.soon")}</p>
    </section>
  );
}

/** Pathless layout route: requires a session, otherwise redirects to /login. */
export const shellRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: "shell",
  beforeLoad: async () => {
    if (!(await queryClient.ensureQueryData(meQuery))) throw redirect({ to: "/login" });
  },
  component: AppShell,
});

/** One placeholder route per sidebar section that has no screen yet; "/" is the dashboards section. */
export const sectionRoutes = NAV.filter(({ key }) => !["devices", "discovery", "problems", "templates", "maintenance", "logs", "health"].includes(key)).map(({ key, path }) =>
  createRoute({ getParentRoute: () => shellRoute, path, component: () => <Placeholder section={key} /> }),
);
