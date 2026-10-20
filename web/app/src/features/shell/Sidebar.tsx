import { Link, useRouterState } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import {
  Sidebar as SidebarRoot,
  SidebarContent,
  SidebarGroup,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar";
import { NAV } from "./nav";

/** Main navigation (spec FR-UI-2). */
export function Sidebar() {
  const { t } = useTranslation();
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  return (
    <SidebarRoot>
      <SidebarHeader className="px-4 py-3 text-base font-semibold">{t("app.name")}</SidebarHeader>
      <SidebarContent>
        <SidebarGroup>
          <nav aria-label={t("nav.label")}>
            <SidebarMenu>
              {NAV.map(({ key, path, icon: Icon }) => (
                <SidebarMenuItem key={key}>
                  <SidebarMenuButton asChild isActive={pathname === path}>
                    <Link to={path as "/"}>
                      <Icon />
                      <span>{t(`nav.${key}`)}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              ))}
            </SidebarMenu>
          </nav>
        </SidebarGroup>
      </SidebarContent>
    </SidebarRoot>
  );
}
