import { useState, type ReactNode } from "react";
import { LineChart } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey, thrownKey } from "@/features/auth/errors";
import { StateBadge } from "@/features/common/StateBadge";
import { ApiError, StepUpCancelled } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import type { CredKind } from "@/lib/seal";
import { cn } from "@/lib/utils";
import { ProblemList } from "@/features/problems/ProblemList";
import { useDevice, useDevices, useGroups, usePollDevice, type DeviceDetail, type DeviceTable } from "./api";
import { ChartsTab } from "@/features/charts/ChartsTab";
import { EventFeed } from "@/features/events/EventFeed";
import { DeviceEditForm } from "./DeviceEditForm";
import { InventoryTable, Text, type Column } from "./InventoryTable";
import { ProfileForm } from "./ProfileForm";
import { useProfiles } from "./profiles";

type TabId = DeviceTable | "graphs" | "profiles" | "journal" | "problems";
const TABS: TabId[] = ["interfaces", "graphs", "arp", "mac", "vlans", "lldp", "entities", "routes", "problems", "journal", "profiles"];
const KINDS: CredKind[] = ["snmp2c", "snmp3", "ssh_read"];

type Props = {
  id: number;
  /** UI hints; the API decides. */
  canPoll: boolean;
  canManage: boolean;
  /** problems.ack hint. */
  canAck?: boolean;
  /** Whether group names can be fetched (global admin). */
  canListGroups?: boolean;
};

/** Device card: summary header with poll-now, edit form and inventory tabs. Every device-reported string is rendered as text. */
export function DeviceCard(props: Props) {
  /* keyed by device so tab, chart selection, paging and an open edit form never carry over to another device */
  return <DeviceCardBody key={props.id} {...props} />;
}

function DeviceCardBody({ id, canPoll, canManage, canAck = false, canListGroups = false }: Props) {
  const { t } = useTranslation();
  const device = useDevice(id);
  const [tab, setTab] = useState<TabId>("interfaces");
  const [chartIf, setChartIf] = useState<number | undefined>();

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

  return (
    <section className="grid gap-4">
      <Header device={device.data} canPoll={canPoll} canManage={canManage} canListGroups={canListGroups} />
      <div role="tablist" aria-label={t("card.tabs")} className="flex flex-wrap gap-1 border-b">
        {TABS.map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            id={`tab-${k}`}
            aria-selected={tab === k}
            aria-controls="tab-panel"
            className={cn("rounded-t-md px-3 py-2 text-sm", tab === k ? "border-b-2 border-primary font-medium" : "text-muted-foreground hover:text-foreground")}
            onClick={() => setTab(k)}
          >
            {t(`card.tab.${k}`)}
          </button>
        ))}
      </div>
      <div role="tabpanel" id="tab-panel" aria-labelledby={`tab-${tab}`}>
        {/* keyed by tab so paging state never carries over between tables */}
        <TabBody
          key={tab}
          tab={tab}
          deviceId={device.data.id}
          canManage={canManage}
          canAck={canAck}
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

function Header({ device, canPoll, canManage, canListGroups }: { device: DeviceDetail; canPoll: boolean; canManage: boolean; canListGroups: boolean }) {
  const { t } = useTranslation();
  const poll = usePollDevice();
  const groups = useGroups(canListGroups);
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
    [t("devices.col.address"), `${device.address}:${device.snmp_port}`],
    [t("devices.col.group"), groupName],
    [t("devices.col.model"), device.model],
    [t("devices.col.firmware"), device.firmware],
    [t("devices.col.driver"), device.driver],
  ];
  const parentId = device.parent_id ?? null;
  const intervals: [string, number | null][] = [
    [t("card.edit.intervalAvail"), device.interval_avail_s],
    [t("card.edit.intervalMetrics"), device.interval_metrics_s],
    [t("card.edit.intervalInventory"), device.interval_inventory_s],
  ];

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-3">
          <h1 className="min-w-0 text-xl font-semibold break-words" title={safeText(device.name)}>
            {safeText(device.name)}
          </h1>
          <StateBadge state={device.state} since={device.state_since} />
        </div>
        <div className="flex gap-2">
          {canManage && !editing && (
            <Button type="button" variant="outline" onClick={() => setEditing(true)}>
              {t("card.edit.open")}
            </Button>
          )}
          {canPoll && (
            <Button type="button" onClick={() => void pollNow()} disabled={poll.isPending}>
              {t("card.pollNow")}
            </Button>
          )}
        </div>
      </div>
      {device.last_error && (
        <p className="truncate text-sm text-amber-700 dark:text-amber-400" title={safeText(device.last_error)}>
          <span className="font-medium">{t("card.lastError")}:</span> {safeText(device.last_error)}
        </p>
      )}
      {note && (
        <p role={note.ok ? "status" : "alert"} className={cn("text-sm", note.ok ? "text-muted-foreground" : "text-destructive")}>
          {note.text}
        </p>
      )}
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(12rem,1fr))] gap-x-6 gap-y-2 text-sm">
        {facts.map(([k, v]) => (
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
        {intervals.map(([k, v]) => (
          <div key={k} className="min-w-0">
            <dt className="text-xs text-muted-foreground">{k}</dt>
            <dd>{v === null ? t("card.inherit") : t("card.seconds", { n: v })}</dd>
          </div>
        ))}
      </dl>
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
  tab: TabId;
  deviceId: number;
  canManage: boolean;
  canAck: boolean;
  chartIf: number | undefined;
  onChartIf: (i: number) => void;
  onShowChart: (i: number) => void;
};

function TabBody({ tab, deviceId, canManage, canAck, chartIf, onChartIf, onShowChart }: TabBodyProps) {
  const { t, i18n } = useTranslation();
  const num = (n: number) => <span className="tabular-nums">{n}</span>;
  const col = <R,>(cid: string, cell: (r: R) => ReactNode): Column<R> => ({ id: cid, header: t(`card.col.${cid}`), cell });
  const seen = (r: { seen_at: string }) => r.seen_at;

  switch (tab) {
    case "graphs":
      return <ChartsTab deviceId={deviceId} ifIndex={chartIf} onIfIndex={onChartIf} />;
    case "problems":
      return <ProblemList deviceId={deviceId} canAck={canAck} />;
    case "journal":
      return <EventFeed deviceId={deviceId} />;
    case "profiles":
      return <ProfilesTab deviceId={deviceId} canManage={canManage} />;
    case "interfaces":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="interfaces"
          seenAt={seen}
          columns={[
            col("ifIndex", (r: { if_index: number }) => num(r.if_index)),
            col("name", (r: { name: string }) => <Text value={r.name} />),
            col("alias", (r: { alias: string }) => <Text value={r.alias} />),
            col("speed", (r: { speed_bps: number }) => t("card.bps", { n: r.speed_bps.toLocaleString(i18n.language) })),
            col("oper", (r: { oper_up: boolean }) => (r.oper_up ? t("card.up") : t("card.down"))),
            col("chart", (r: { if_index: number; name: string }) => (
              <Button type="button" variant="outline" size="sm" aria-label={t("card.chartBtn", { name: safeText(r.name) })} onClick={() => onShowChart(r.if_index)}>
                <LineChart aria-hidden />
              </Button>
            )),
          ]}
        />
      );
    case "arp":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="arp"
          seenAt={seen}
          columns={[
            col("ip", (r: { ip: string }) => <Text value={r.ip} mono />),
            col("mac", (r: { mac: string }) => <Text value={r.mac} mono />),
            col("ifIndex", (r: { if_index: number }) => num(r.if_index)),
          ]}
        />
      );
    case "mac":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="mac"
          seenAt={seen}
          columns={[
            col("mac", (r: { mac: string }) => <Text value={r.mac} mono />),
            col("vlan", (r: { vlan: number }) => (r.vlan === 0 ? "-" : num(r.vlan))),
            col("ifIndex", (r: { if_index: number }) => num(r.if_index)),
          ]}
        />
      );
    case "vlans":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="vlans"
          seenAt={seen}
          columns={[col("vlan", (r: { vlan_id: number }) => num(r.vlan_id)), col("name", (r: { name: string }) => <Text value={r.name} />)]}
        />
      );
    case "lldp":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="lldp"
          seenAt={seen}
          columns={[
            col("localIf", (r: { local_if_index: number }) => num(r.local_if_index)),
            col("chassis", (r: { chassis_id: string }) => <Text value={r.chassis_id} mono />),
            col("port", (r: { port_id: string }) => <Text value={r.port_id} />),
            col("sysName", (r: { sys_name: string }) => <Text value={r.sys_name} />),
            col("mgmt", (r: { mgmt_addr: string | null }) => <Text value={r.mgmt_addr} mono />),
          ]}
        />
      );
    case "entities":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="entities"
          seenAt={seen}
          columns={[
            col("entIndex", (r: { ent_index: number }) => num(r.ent_index)),
            col("class", (r: { class: string }) => <Text value={r.class} />),
            col("name", (r: { name: string }) => <Text value={r.name} />),
            col("model", (r: { model: string }) => <Text value={r.model} />),
            col("serial", (r: { serial: string }) => <Text value={r.serial} mono />),
          ]}
        />
      );
    case "routes":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="routes"
          seenAt={seen}
          columns={[
            col("dest", (r: { dest: string }) => <Text value={r.dest} mono />),
            col("nextHop", (r: { next_hop: string | null }) => <Text value={r.next_hop} mono />),
            col("ifIndex", (r: { if_index: number }) => num(r.if_index)),
            col("proto", (r: { proto: string }) => <Text value={r.proto} />),
          ]}
        />
      );
  }
}

/** Status and date of each read credential (never the content) plus the forms to replace them. */
function ProfilesTab({ deviceId, canManage }: { deviceId: number; canManage: boolean }) {
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
    <div className="grid gap-4 lg:grid-cols-3">
      {KINDS.map((kind) => {
        const profile = profiles.data.find((p) => p.kind === kind);
        return (
          <div key={kind} className="grid content-start gap-3 rounded-md border p-4">
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
