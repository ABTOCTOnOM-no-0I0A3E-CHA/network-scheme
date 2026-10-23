import { Bell } from "lucide-react";
import { Popover } from "radix-ui";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { canListGroups, canReceiveProblems } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import { useGroups } from "@/features/devices/api";
import { SeverityBadge } from "@/features/events/EventFeed";
import { SEVERITIES, problemTitle, type EventSeverity } from "@/features/problems/api";
import { safeText } from "@/lib/text";
import { useProblemFeed } from "./useProblemFeed";

const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";

type Props = {
  /** Opens the problem list. */
  onOpenProblems: () => void;
  /** Replaces the beep (tests). */
  play?: () => void;
};

/** Header bell: unread badge, the latest opened problems and the preferences (sound, minimal severity, groups). */
export function NotificationCenter({ onOpenProblems, play }: Props) {
  const { t, i18n } = useTranslation();
  const { data: session } = useSession();
  const feed = useProblemFeed({ enabled: canReceiveProblems(session), play });
  const groups = useGroups(canListGroups(session));
  const { settings, setSettings } = feed;

  const toggleGroup = (id: number) => setSettings({ groups: settings.groups.includes(id) ? settings.groups.filter((g) => g !== id) : [...settings.groups, id] });

  return (
    <Popover.Root onOpenChange={(o) => o && feed.markRead()}>
      <Popover.Trigger asChild>
        <Button variant="ghost" size="icon" className="relative" aria-label={t("notify.title", { count: feed.unread })}>
          <Bell />
          {feed.unread > 0 && (
            <span data-testid="notify-badge" className="absolute -top-0.5 -right-0.5 min-w-4 rounded-full bg-destructive px-1 text-center text-[10px] leading-4 font-medium text-white">
              {feed.unread > 99 ? "99+" : feed.unread}
            </span>
          )}
        </Button>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content align="end" sideOffset={6} className="z-50 grid w-96 max-w-[calc(100vw-1rem)] gap-3 rounded-md border bg-popover p-3 text-popover-foreground shadow-md">
          <h2 className="text-sm font-semibold">{t("notify.heading")}</h2>
          {feed.items.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("notify.empty")}</p>
          ) : (
            <ul className="grid max-h-64 gap-2 overflow-y-auto">
              {feed.items.map(({ key, problem: p }) => (
                <li key={key} className="grid gap-0.5 text-sm">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={p.severity} />
                    <span className="min-w-0 truncate" title={safeText(problemTitle(t, p))}>
                      {safeText(problemTitle(t, p))}
                    </span>
                  </div>
                  <div className="truncate text-xs text-muted-foreground" title={safeText(p.device_name)}>
                    {safeText(p.device_name)} / {new Date(p.opened_at).toLocaleTimeString(i18n.language)}
                  </div>
                </li>
              ))}
            </ul>
          )}
          <Popover.Close asChild>
            <Button type="button" variant="outline" size="sm" onClick={onOpenProblems}>
              {t("notify.openAll")}
            </Button>
          </Popover.Close>
          <fieldset className="grid gap-2 border-t pt-3 text-sm">
            <legend className="text-xs font-semibold">{t("notify.settings")}</legend>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={settings.sound} onChange={(e) => setSettings({ sound: e.target.checked })} />
              {t("notify.sound")}
            </label>
            <label className="flex flex-wrap items-center gap-2">
              {t("notify.severityMin")}
              <select className={SELECT_CLASS} value={settings.severityMin} onChange={(e) => setSettings({ severityMin: e.target.value as EventSeverity })}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {t(`events.severity.${s}`)}
                  </option>
                ))}
              </select>
            </label>
            {groups.data && groups.data.length > 0 && (
              <div className="grid gap-1">
                <span className="text-xs text-muted-foreground">{t("notify.groups")}</span>
                <div className="grid max-h-28 gap-1 overflow-y-auto">
                  {groups.data.map((g) => (
                    <label key={g.id} className="flex items-center gap-2">
                      <input type="checkbox" checked={settings.groups.includes(g.id)} onChange={() => toggleGroup(g.id)} />
                      <span className="truncate" title={safeText(g.name)}>
                        {safeText(g.name)}
                      </span>
                    </label>
                  ))}
                </div>
              </div>
            )}
          </fieldset>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
