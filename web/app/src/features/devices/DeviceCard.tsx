import { useEffect, useId, useState } from "react";
import { RefreshCw, Pencil, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { StateBadge } from "@/features/common/StateBadge";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { roleIcon } from "@/features/map/icons";
import { safeText } from "@/lib/text";
import type { CredKind } from "@nms/shared/seal";
import { cn } from "@/lib/utils";
import { ProblemList } from "@/features/problems/ProblemList";
import { SessionHistory, SessionTab } from "@/features/executor/SessionTab";
import { useDevice, useDevices, useGroups, usePollDevice, type DeviceDetail, type DeviceTable } from "./api";
import { ChartsTab } from "@/features/charts/ChartsTab";
import { EventFeed } from "@/features/events/EventFeed";
import { BackupsTab } from "./BackupsTab";
import { CliTab } from "./CliTab";
import { ConfigTab } from "./ConfigTab";
import { DataTab } from "./DataTab";
import { DeviceEditForm } from "./DeviceEditForm";
import { lastErrorKey } from "./lastError";
import { PhysicalTab } from "./PhysicalTab";
import { ProfileForm } from "./ProfileForm";
import { useProfiles } from "./profiles";
import { splitTabRef, TABS, type Tab, type TabRef } from "./tabs";

const KINDS: CredKind[] = ["snmp2c", "snmp3", "ssh_read"];

type Props = {
  id: number;
  /** UI hints; the API decides. */
  canPoll: boolean;
  canManage: boolean;
  /** problems.ack hint. */
  canAck?: boolean;
  /** devices.show hint: without it the CLI tab is hidden. */
  canShow?: boolean;
  /** devices.backup hint: without it the manual backup button is hidden. */
  canBackup?: boolean;
  /** Whether group names can be fetched (global admin). */
  canListGroups?: boolean;
  /** Tab to open (from the URL); "Физика" by default. */
  tab?: TabRef;
  /** Interface the graphs tab opens on. */
  ifIndex?: number;
  /** "window": inside a device window, whose title bar already shows the name and state. */
  variant?: "page" | "window";
};

/** Device card: summary header with poll-now, edit form and the FR-UI-DEV tabs. Every device-reported string is rendered as text. */
export function DeviceCard(props: Props) {
  /*
   * keyed by device and requested tab so tab, chart selection, paging and an open edit form never carry over to another device or link;
   * a requested CLI tab also keys on canShow, so the tab resolves again once the session (and its devices.show hint) has loaded
   */
  return <DeviceCardBody key={`${props.id}:${props.tab ?? ""}:${props.ifIndex ?? ""}:${props.tab === "cli" && !!props.canShow}`} {...props} />;
}

function DeviceCardBody({ id, canPoll, canManage, canAck = false, canListGroups = false, canShow = false, canBackup = false, tab: initialTab, ifIndex, variant = "page" }: Props) {
  const { t } = useTranslation();
  const device = useDevice(id);
  const init = splitTabRef(initialTab);
  const [tab, setTab] = useState<Tab>(init.tab !== "cli" || canShow ? init.tab : "physical");
  const [dataTab, setDataTab] = useState<DeviceTable>(init.data);
  const [chartIf, setChartIf] = useState<number | undefined>(ifIndex);
  /* several cards can be open at once (device windows): element ids are per card */
  const uid = useId();

  if (device.isPending) return <p className="text-sm text-muted-foreground">{t("card.loading")}</p>;
  if (device.error) {
    const msg = device.error instanceof ApiError ? t(errorKey({ error: { code: device.error.code } })) : t("errors.unknown");
    return (
      <p role="alert" className="text-sm text-destructive">
        {msg}
      </p>
    );
  }
  if (device.data === null) {
    return (
      <section>
        <h1 className="text-xl font-semibold">{t("card.notFound")}</h1>
      </section>
    );
  }
  const d = device.data;

  return (
    <section className="@container grid gap-4" data-variant={variant}>
      <Header device={d} canPoll={canPoll} canManage={canManage} canListGroups={canListGroups} variant={variant} />
      {/* one row that scrolls sideways when the window is narrow, never a second row */}
      {/* in a window the tab bar stays in view while the tab content scrolls */}
      <div role="tablist" aria-label={t("card.tabs")} className={cn("flex overflow-x-auto border-b", variant === "window" && "sticky -top-4 z-10 bg-background pt-1")}>
        {TABS.filter((k) => k !== "cli" || canShow).map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            id={`${uid}tab-${k}`}
            aria-selected={tab === k}
            aria-controls={`${uid}tab-panel`}
            className={cn(
              "-mb-px shrink-0 border-b-2 px-3 py-2 text-sm whitespace-nowrap transition-colors",
              tab === k ? "border-primary font-medium text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
            )}
            onClick={() => setTab(k)}
          >
            {t(`card.tab.${k}`)}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${uid}tab-panel`} aria-labelledby={`${uid}tab-${tab}`}>
        {/* keyed by tab so state never carries over between tabs */}
        <TabBody
          key={tab}
          tab={tab}
          device={d}
          dataTab={dataTab}
          onDataTab={setDataTab}
          canManage={canManage}
          canAck={canAck}
          canBackup={canBackup}
          chartIf={chartIf}
          onChartIf={setChartIf}
          onShowChart={(i) => {
            setChartIf(i);
            setTab("graphs");
          }}
        />
      </div>
    </section>
  );
}

/** How long ago an ISO time was, as "3 д 4 ч" / "5 ч 12 мин" / "7 мин"; re-renders every minute so an open card stays current. */
function useAgo() {
  const { t } = useTranslation();
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60_000);
    return () => clearInterval(id);
  }, []);
  return (iso: string) => {
    const m = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 60_000));
    const d = Math.floor(m / 1440);
    const h = Math.floor((m % 1440) / 60);
    if (d > 0) return t("card.dur.dh", { d, h });
    if (h > 0) return t("card.dur.hm", { h, m: m % 60 });
    return t("card.dur.m", { m });
  };
}

type HeaderProps = {
  device: DeviceDetail;
  canPoll: boolean;
  canManage: boolean;
  canListGroups: boolean;
  variant: "page" | "window";
};

function Header({ device, canPoll, canManage, canListGroups, variant }: HeaderProps) {
  const { t } = useTranslation();
  const poll = usePollDevice();
  const groups = useGroups(canListGroups);
  const ago = useAgo();
  const [editing, setEditing] = useState(false);
  const [note, setNote] = useState<{ ok: boolean; text: string } | undefined>();
  const groupName = groups.data?.find((g) => g.id === device.group_id)?.name ?? `#${device.group_id}`;

  const pollNow = async () => {
    setNote(undefined);
    try {
      await poll.mutateAsync(device.id);
      setNote({ ok: true, text: t("card.pollQueued") });
    } catch (err) {
      if (err instanceof StepUpCancelled) return;
      const key = err instanceof ApiError ? errorKey({ error: { code: err.code } }) : err instanceof TypeError ? thrownKey(err) : "errors.unknown";
      setNote({ ok: false, text: t(key) });
    }
  };

  const facts: [string, string][] = [
    [t("devices.col.model"), device.model],
    [t("devices.col.firmware"), device.firmware],
    [t("devices.col.role"), device.role ? t(`devices.role.${device.role}`) : ""],
    [t("devices.col.address"), device.snmp_port === 161 ? device.address : `${device.address}:${device.snmp_port}`],
    ...(device.state === "up" && device.state_since ? [[t("card.uptime"), ago(device.state_since)] as [string, string]] : []),
  ];
  const parentId = device.parent_id ?? null;
  const details: [string, string][] = [
    [t("devices.col.group"), groupName],
    [t("devices.col.driver"), device.driver],
    [t("card.edit.intervalAvail"), device.interval_avail_s === null ? t("card.inherit") : t("card.seconds", { n: device.interval_avail_s })],
    [t("card.edit.intervalMetrics"), device.interval_metrics_s === null ? t("card.inherit") : t("card.seconds", { n: device.interval_metrics_s })],
    [t("card.edit.intervalInventory"), device.interval_inventory_s === null ? t("card.inherit") : t("card.seconds", { n: device.interval_inventory_s })],
  ];

  const actions = (
    <div className="flex shrink-0 gap-2">
      {canManage && !editing && (
        <Button type="button" variant="outline" size={variant === "window" ? "sm" : "default"} onClick={() => setEditing(true)}>
          <Pencil aria-hidden />
          {t("card.edit.open")}
        </Button>
      )}
      {canPoll && (
        <Button type="button" size={variant === "window" ? "sm" : "default"} onClick={() => void pollNow()} disabled={poll.isPending}>
          <RefreshCw aria-hidden />
          {t("card.pollNow")}
        </Button>
      )}
    </div>
  );

  return (
    <div className="grid gap-3">
      {variant === "page" && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-3">
            <img src={roleIcon(device.role)} alt="" data-slot="role-icon" className="size-11 shrink-0" />
            <h1 className="min-w-0 text-2xl font-semibold tracking-tight break-words" title={safeText(device.name)}>
              {safeText(device.name)}
            </h1>
            <StateBadge state={device.state} since={device.state_since} />
          </div>
          {actions}
        </div>
      )}
      <div className="rounded-lg border bg-muted/30 px-4 py-3">
        <dl className="grid grid-cols-[repeat(auto-fill,minmax(7.5rem,1fr))] gap-x-5 gap-y-2 text-sm">
          {facts.map(([k, v]) => (
            <div key={k} className="min-w-0">
              <dt className="text-xs text-muted-foreground">{k}</dt>
              <dd className="font-medium break-words" title={safeText(v)}>
                {safeText(v) || "-"}
              </dd>
            </div>
          ))}
        </dl>
      </div>
      {device.last_error && (
        <p
          role="note"
          className="flex items-center gap-2 rounded-md border border-amber-300/60 bg-amber-50 px-3 py-2 text-sm text-amber-900 dark:border-amber-500/30 dark:bg-amber-950/40 dark:text-amber-200"
        >
          <TriangleAlert aria-hidden className="size-4 shrink-0" />
          <span>
            <span className="font-medium">{t("card.lastError")}:</span> {t(lastErrorKey(device.last_error))}
          </span>
        </p>
      )}
      {note && (
        <p role={note.ok ? "status" : "alert"} className={cn("text-sm", note.ok ? "text-muted-foreground" : "text-destructive")}>
          {note.text}
        </p>
      )}
      <div className="flex flex-wrap items-start justify-between gap-2">
        <details className="group min-w-0 flex-1 text-sm">
          <summary className="cursor-pointer text-xs text-muted-foreground select-none hover:text-foreground">{t("card.details")}</summary>
          <dl className="mt-2 grid grid-cols-[repeat(auto-fill,minmax(10rem,1fr))] gap-x-5 gap-y-2">
            {details.map(([k, v]) => (
              <div key={k} className="min-w-0">
                <dt className="text-xs text-muted-foreground">{k}</dt>
                <dd className="break-words" title={safeText(v)}>
                  {safeText(v) || "-"}
                </dd>
              </div>
            ))}
            {parentId !== null && (
              <div className="min-w-0">
                <dt className="text-xs text-muted-foreground">{t("card.edit.parent")}</dt>
                <dd className="break-words">
                  <ParentName id={parentId} />
                </dd>
              </div>
            )}
          </dl>
        </details>
        {variant === "window" && actions}
      </div>
      {editing && <DeviceEditForm key={device.id} device={device} groups={groups.data} onDone={() => setEditing(false)} />}
    </div>
  );
}

/* mounted only for a device that has a parent, so devices without one trigger no extra request */
function ParentName({ id }: { id: number }) {
  const devices = useDevices();
  const name = safeText(devices.data?.find((d) => d.id === id)?.name);
  return <span title={name}>{name || `#${id}`}</span>;
}

type TabBodyProps = {
  tab: Tab;
  device: DeviceDetail;
  dataTab: DeviceTable;
  onDataTab: (t: DeviceTable) => void;
  canManage: boolean;
  canAck: boolean;
  canBackup: boolean;
  chartIf: number | undefined;
  onChartIf: (i: number) => void;
  onShowChart: (i: number) => void;
};

function TabBody({ tab, device, dataTab, onDataTab, canManage, canAck, canBackup, chartIf, onChartIf, onShowChart }: TabBodyProps) {
  const deviceId = device.id;
  switch (tab) {
    case "physical":
      return <PhysicalTab deviceId={deviceId} onShowChart={onShowChart} device={device} />;
    case "config":
      return <ConfigTab deviceId={deviceId} />;
    case "cli":
      return <CliTab deviceId={deviceId} />;
    case "data":
      return <DataTab deviceId={deviceId} table={dataTab} onTable={onDataTab} onShowChart={onShowChart} />;
    case "graphs":
      return <ChartsTab deviceId={deviceId} ifIndex={chartIf} onIfIndex={onChartIf} />;
    case "backups":
      return <BackupsTab deviceId={deviceId} canBackup={canBackup} />;
    case "journal":
      return <JournalTab deviceId={deviceId} canAck={canAck} />;
    case "access":
      return <AccessTab deviceId={deviceId} canManage={canManage} />;
    case "session":
      return <SessionTab deviceId={deviceId} />;
  }
}

/** "Журнал" (FR-UI-DEV-7): the device's problems and events, then its change-session history. */
function JournalTab({ deviceId, canAck }: { deviceId: number; canAck: boolean }) {
  const { t } = useTranslation();
  return (
    <div className="grid gap-6">
      <section className="grid gap-2" aria-label={t("journal.problems")}>
        <h3 className="text-sm font-semibold">{t("journal.problems")}</h3>
        <ProblemList deviceId={deviceId} canAck={canAck} />
      </section>
      <section className="grid gap-2" aria-label={t("journal.events")}>
        <h3 className="text-sm font-semibold">{t("journal.events")}</h3>
        <EventFeed deviceId={deviceId} />
      </section>
      <section className="grid gap-2" aria-label={t("journal.sessions")}>
        <h3 className="text-sm font-semibold">{t("journal.sessions")}</h3>
        <SessionHistory deviceId={deviceId} />
      </section>
    </div>
  );
}

/** "Доступ": status and date of each read credential (never the content) plus the forms to replace them. */
function AccessTab({ deviceId, canManage }: { deviceId: number; canManage: boolean }) {
  const { t, i18n } = useTranslation();
  const profiles = useProfiles(deviceId);
  if (profiles.isPending) return <p className="text-sm text-muted-foreground">{t("card.loading")}</p>;
  if (profiles.error) {
    const msg = profiles.error instanceof ApiError ? t(errorKey({ error: { code: profiles.error.code } })) : t("errors.unknown");
    return (
      <p role="alert" className="text-sm text-destructive">
        {msg}
      </p>
    );
  }
  return (
    <div className="grid gap-4 @4xl:grid-cols-3">
      {KINDS.map((kind) => {
        const profile = profiles.data.find((p) => p.kind === kind);
        return (
          <div key={kind} className="grid content-start gap-3 rounded-lg border p-4">
            {canManage ? (
              <ProfileForm owner={`device:${deviceId}`} kind={kind} profile={profile} />
            ) : (
              <>
                <h3 className="text-sm font-semibold">{t(`profile.title.${kind}`)}</h3>
                <p className="text-sm text-muted-foreground">
                  {t(`profile.status.${profile?.status ?? "none"}`)}
                  {profile && ` - ${t("profile.updated", { date: new Date(profile.updated_at).toLocaleString(i18n.language) })}`}
                </p>
              </>
            )}
          </div>
        );
      })}
    </div>
  );
}

/** State badge of a device for the title bar of its window; nothing until the device has loaded. */
export function DeviceStateBadge({ id }: { id: number }) {
  const device = useDevice(id);
  return device.data ? <StateBadge state={device.data.state} since={device.data.state_since} /> : null;
}
