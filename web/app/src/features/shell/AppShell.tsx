import { useEffect, useState } from "react";
import { Outlet, useNavigate } from "@tanstack/react-router";
import { Moon, Search, Sun } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar";
import { logout, useSession } from "@/features/auth/useSession";
import { StepUpDialog } from "@/features/common/StepUpDialog";
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

  return (
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
            <UserMenu username={session?.username ?? ""} onLogout={() => void signOut()} />
          </div>
        </header>
        <main className="flex-1 p-6">
          <Outlet />
        </main>
      </SidebarInset>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
      <StepUpDialog />
    </SidebarProvider>
  );
}
