import { useId, type ReactNode } from "react";
import { LineChart } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { formatBps } from "@/features/charts/series";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import type { DeviceTable } from "./api";
import { InventoryTable, Text, type Column } from "./InventoryTable";
import { DATA_TABS } from "./tabs";

type Props = { deviceId: number; table: DeviceTable; onTable: (t: DeviceTable) => void; onShowChart: (ifIndex: number) => void };

/** "Данные": the inventory tables of the device (FR-UI-DEV-4), one sub-tab each. */
export function DataTab({ deviceId, table, onTable, onShowChart }: Props) {
  const { t } = useTranslation();
  const uid = useId();
  return (
    <div className="grid gap-3">
      <div role="tablist" aria-label={t("card.tab.data")} className="flex gap-1 overflow-x-auto rounded-lg bg-muted p-1">
        {DATA_TABS.map((k) => (
          <button
            key={k}
            type="button"
            role="tab"
            id={`${uid}${k}`}
            aria-selected={table === k}
            aria-controls={`${uid}panel`}
            className={cn(
              "shrink-0 rounded-md px-3 py-1 text-sm whitespace-nowrap transition-colors",
              table === k ? "bg-background font-medium text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
            )}
            onClick={() => onTable(k)}
          >
            {t(`card.tab.${k}`)}
          </button>
        ))}
      </div>
      <div role="tabpanel" id={`${uid}panel`} aria-labelledby={`${uid}${table}`}>
        {/* keyed by table so paging state never carries over between tables */}
        <Table key={table} deviceId={deviceId} table={table} onShowChart={onShowChart} />
      </div>
    </div>
  );
}

function Table({ deviceId, table, onShowChart }: { deviceId: number; table: DeviceTable; onShowChart: (ifIndex: number) => void }) {
  const { t, i18n } = useTranslation();
  const units = ["bps", "kbps", "mbps", "gbps", "tbps"].map((k) => t(`chart.unit.${k}`));
  const num = (n: number) => <span className="tabular-nums">{n}</span>;
  const col = <R,>(cid: string, cell: (r: R) => ReactNode): Column<R> => ({ id: cid, header: t(`card.col.${cid}`), cell });
  const seen = (r: { seen_at: string }) => r.seen_at;

  switch (table) {
    case "interfaces":
      return (
        <InventoryTable
          deviceId={deviceId}
          table="interfaces"
          seenAt={seen}
          filters={[
            { id: "up", label: t("card.up"), test: (r) => r.oper_up },
            { id: "down", label: t("card.down"), test: (r) => !r.oper_up },
          ]}
          columns={[
            col("ifIndex", (r: { if_index: number }) => num(r.if_index)),
            col("name", (r: { name: string }) => <Text value={r.name} />),
            col("alias", (r: { alias: string }) => <Text value={r.alias} />),
            /* "1 Гбит/с" rather than "1 000 000 000 бит/с"; the exact figure stays in the tooltip */
            col("speed", (r: { speed_bps: number }) => (
              <span className="whitespace-nowrap" title={t("card.bps", { n: r.speed_bps.toLocaleString(i18n.language) })}>
                {r.speed_bps > 0 ? formatBps(r.speed_bps, units, i18n.language) : "-"}
              </span>
            )),
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
  }
}
