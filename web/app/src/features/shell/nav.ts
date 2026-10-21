import { Activity, AlertTriangle, DatabaseBackup, FileClock, GitPullRequestArrow, LayoutDashboard, Map, Radar, ScrollText, Server, Settings, type LucideIcon } from "lucide-react";

export type NavItem = { key: string; path: string; icon: LucideIcon };

/** Sidebar sections from spec FR-UI-2; all but the shell itself are placeholders in Phase 0. */
export const NAV: NavItem[] = [
  { key: "dashboards", path: "/", icon: LayoutDashboard },
  { key: "map", path: "/map", icon: Map },
  { key: "devices", path: "/devices", icon: Server },
  { key: "discovery", path: "/discovery", icon: Radar },
  { key: "problems", path: "/problems", icon: AlertTriangle },
  { key: "logs", path: "/logs", icon: ScrollText },
  { key: "backups", path: "/backups", icon: DatabaseBackup },
  { key: "changes", path: "/changes", icon: GitPullRequestArrow },
  { key: "audit", path: "/audit", icon: FileClock },
  { key: "health", path: "/health", icon: Activity },
  { key: "settings", path: "/settings", icon: Settings },
];
