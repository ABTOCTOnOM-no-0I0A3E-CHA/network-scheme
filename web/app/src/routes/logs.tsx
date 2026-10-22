import { useState } from "react";
import { createRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { canManageEvents } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { EventFeed } from "@/features/events/EventFeed";
import { Unidentified } from "@/features/events/Unidentified";
import { cn } from "@/lib/utils";
import { shellRoute } from "./index";

const TABS = ["feed", "unidentified"] as const;

function LogsPage() {
  const { t } = useTranslation();
  const { data: session } = useSession();
  const [tab, setTab] = useState<(typeof TABS)[number]>("feed");
  return (
    <section className="grid gap-4">
      <h1 className="text-xl font-semibold">{t("nav.logs")}</h1>
      <div role="tablist" aria-label={t("events.tabs")} className="flex flex-wrap gap-1 border-b">
        {TABS.map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            aria-selected={tab === k}
            className={cn("rounded-t-md px-3 py-2 text-sm", tab === k ? "border-b-2 border-primary font-medium" : "text-muted-foreground hover:text-foreground")}
            onClick={() => setTab(k)}
          >
            {t(`events.tab.${k}`)}
          </button>
        ))}
      </div>
      <div role="tabpanel">{tab === "feed" ? <EventFeed /> : <Unidentified canManage={canManageEvents(session)} />}</div>
    </section>
  );
}

/** Syslog and trap feed plus the unidentified traps at /logs. */
export const logsRoute = createRoute({ getParentRoute: () => shellRoute, path: "/logs", component: LogsPage });
