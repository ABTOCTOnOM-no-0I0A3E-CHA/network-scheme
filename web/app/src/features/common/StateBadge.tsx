import { useTranslation } from "react-i18next";
import { cn } from "@/lib/utils";

export type DeviceState = "up" | "partial" | "down" | "unknown";

const TONE: Record<DeviceState, string> = {
  up: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
  partial: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  down: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  unknown: "bg-muted text-muted-foreground",
};

/** Availability badge; `since` (ISO time or null) is shown as a tooltip. */
export function StateBadge({ state, since }: { state: DeviceState; since?: string | null }) {
  const { t, i18n } = useTranslation();
  const title = since ? t("state.since", { date: new Date(since).toLocaleString(i18n.language) }) : undefined;
  return (
    <span title={title} data-state={state} className={cn("inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium", TONE[state])}>
      {t(`state.${state}`)}
    </span>
  );
}
