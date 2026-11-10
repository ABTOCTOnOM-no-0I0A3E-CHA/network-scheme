import { useEffect, useState } from "react";
import { Outlet, useNavigate } from "@tanstack/react-router";
import { Moon, Search, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { canAckProblems, canBackupDevices, canListGroups, canManageDevices, canPollDevices, canShowDevices } from "@/features/auth/permissions";
import { logout, useSession } from "@/features/auth/useSession";
import { DeviceCard, DeviceStateBadge } from "@/features/devices/DeviceCard";
import { DeviceWindowsProvider } from "@/features/devices/DeviceWindows";
import { StepUpDialog } from "@/features/common/StepUpDialog";
import { SessionHostProvider, useSessionHost } from "@/features/executor/SessionHost";
import { NotificationCenter } from "@/features/notify/NotificationCenter";
import { getTheme, setTheme } from "@/lib/theme";
import { CommandPalette } from "./CommandPalette";
import { Sidebar } from "./Sidebar";
import { UserMenu } from "./UserMenu";

/** Authenticated layout: sidebar, header (search, theme, user menu) and the routed content. */
export function AppShell() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data: session } = useSession();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [theme, setThemeState] = useState(getTheme);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  /* session lost while the shell is mounted (e.g. refetch returned 401) */
  useEffect(() => {
    if (session === null) void navigate({ to: "/login" });
  }, [session, navigate]);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    setThemeState(next);
  };

  const signOut = async () => {
    await logout();
    await navigate({ to: "/login" });
  };

  const deviceBody = (id: number) => (
    <DeviceCard
      id={id}
      canPoll={canPollDevices(session)}
      canManage={canManageDevices(session)}
      canAck={canAckProblems(session)}
      canListGroups={canListGroups(session)}
      canShow={canShowDevices(session)}
      canBackup={canBackupDevices(session)}
      variant="window"
    />
  );

  return (
    /* the change session's frame lives here, above the routes: navigating never tears it down (FR-CHG-7) */
    <SessionHostProvider>
      <DeviceWindowsProvider renderBody={deviceBody} renderTitle={(id) => <DeviceStateBadge id={id} />} onOpenPage={(id) => void navigate({ to: "/devices/$id", params: { id: String(id) } })}>
        <SidebarProvider>
          <Sidebar />
          <SidebarInset>
            <header className="flex h-14 items-center gap-2 border-b px-4">
              <SidebarTrigger />
              <Separator orientation="vertical" className="h-6" />
              <Button variant="outline" className="w-full max-w-xs justify-start text-muted-foreground" onClick={() => setPaletteOpen(true)}>
                <Search />
                <span className="flex-1 text-left">{t("shell.search")}</span>
                <kbd className="text-xs">Ctrl K</kbd>
              </Button>
              <div className="ml-auto flex items-center gap-1">
                <NotificationCenter onOpenProblems={() => void navigate({ to: "/problems" })} />
                <Button variant="ghost" size="icon" aria-label={t("theme.toggle")} onClick={toggleTheme}>
                  {theme === "dark" ? <Sun /> : <Moon />}
                </Button>
                <GuardedUserMenu username={session?.username ?? ""} onLogout={() => void signOut()} />
              </div>
            </header>
            <main className="flex-1 p-6">
              <Outlet />
            </main>
          </SidebarInset>
          <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
          <StepUpDialog />
        </SidebarProvider>
      </DeviceWindowsProvider>
    </SessionHostProvider>
  );
}

/* The user menu; logging out while a change session is open asks first: the session would stay until its idle timeout. */
function GuardedUserMenu({ username, onLogout }: { username: string; onLogout: () => void }) {
  const { t } = useTranslation();
  const host = useSessionHost();
  return <UserMenu username={username} onLogout={() => (!host?.sessionOpen || window.confirm(t("executor.dock.leave"))) && onLogout()} />;
}
