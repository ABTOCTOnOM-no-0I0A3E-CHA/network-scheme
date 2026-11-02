import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey } from "@/features/auth/errors";
import { formatBps } from "@/features/charts/series";
import { ApiError } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import type { DeviceState } from "@/features/common/StateBadge";
import { EmptyState } from "@/features/common/EmptyState";
import { useDeviceTable, useIfMetrics, type TableRows } from "./api";
import { FrontPanel } from "./FrontPanel";

type Iface = TableRows["interfaces"];
type Kind = "rj45" | "sfp";
const KINDS: Kind[] = ["rj45", "sfp"];
/* the window of traffic read for the hover hint */
const TRAFFIC_WINDOW_MS = 15 * 60 * 1000;

/* natural order: numeric runs compare as numbers, so gi1/0/2 sorts before gi1/0/10 */
const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** Physical ports grouped by kind (RJ-45 first, then SFP), each in natural name order; other interfaces are not ports. */
export function frontPanel(rows: Iface[]): Record<Kind, Iface[]> {
  const out: Record<Kind, Iface[]> = { rj45: [], sfp: [] };
  for (const r of rows) if (r.port_kind === "rj45" || r.port_kind === "sfp") out[r.port_kind].push(r);
  for (const k of KINDS) out[k].sort((a, b) => collator.compare(a.name, b.name) || a.if_index - b.if_index);
  return out;
}

type Props = {
  deviceId: number;
  onShowChart: (ifIndex: number) => void;
  /** Faceplate print: model, driver (for the brand text) and state (for the system LEDs). */
  device?: { model: string; driver: string; state: DeviceState };
};

/* the brand printed on the faceplate, as text: only for drivers of a known vendor */
const brandOf = (driver: string | undefined) => (driver?.startsWith("eltex") ? "ELTEX" : undefined);

/** "Физика" tab: front panel built from the interface inventory; hover shows speed, VLAN and traffic, a click opens the port card. */
export function PhysicalTab({ deviceId, onShowChart, device }: Props) {
  const { t } = useTranslation();
  const ifaces = useDeviceTable(deviceId, "interfaces", { limit: 1000 });
  const macs = useDeviceTable(deviceId, "mac", { limit: 1000 });
  const lldp = useDeviceTable(deviceId, "lldp", { limit: 1000 });
  const [hover, setHover] = useState<number | undefined>();
  const [open, setOpen] = useState<number | undefined>();

  const rows = ifaces.data?.items;
  const panel = useMemo(() => frontPanel(rows ?? []), [rows]);
  /* VLANs a port carries, as far as the forwarding table shows them */
  const vlans = useMemo(() => {
    const m = new Map<number, number[]>();
    for (const e of macs.data?.items ?? []) {
      if (e.vlan === 0) continue;
      const l = m.get(e.if_index) ?? [];
      if (!l.includes(e.vlan)) m.set(e.if_index, [...l, e.vlan].sort((a, b) => a - b));
    }
    return m;
  }, [macs.data]);

  if (ifaces.isPending) return <p className="text-sm text-muted-foreground">{t("card.loading")}</p>;
  if (ifaces.error) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {t(ifaces.error instanceof ApiError ? errorKey({ error: { code: ifaces.error.code } }) : "errors.unknown")}
      </p>
    );
  }
  const all = rows ?? [];
  const others = all.length - panel.rj45.length - panel.sfp.length;
  const up = panel.rj45.filter((r) => r.oper_up).length + panel.sfp.filter((r) => r.oper_up).length;
  const byIndex = (i: number | undefined) => all.find((r) => r.if_index === i);
  const hovered = byIndex(hover);
  const opened = byIndex(open);

  return (
    <div className="grid gap-3" data-slot="front-panel">
      {panel.rj45.length + panel.sfp.length === 0 ? (
        <EmptyState title={t("phys.noPorts")} hint={t("phys.noPortsHint")} />
      ) : (
        <>
          <div className="flex justify-center overflow-x-auto rounded-xl border bg-gradient-to-b from-muted/40 to-muted px-3 py-4 dark:from-muted/20 dark:to-muted/60">
            <FrontPanel
              rj45={panel.rj45}
              sfp={panel.sfp}
              model={device?.model ?? ""}
              brand={brandOf(device?.driver)}
              state={device?.state}
              hover={hover}
              selected={open}
              onHover={setHover}
              onSelect={(i) => setOpen(open === i ? undefined : i)}
            />
          </div>
          <div className="grid gap-1 text-xs text-muted-foreground">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
              <Legend tone="bg-emerald-400" label={t("phys.legend.link")} />
              <Legend tone="bg-amber-400" label={t("phys.legend.slow")} />
              <Legend tone="bg-zinc-500" label={t("phys.legend.noLink")} />
            </div>
            <span>{t("phys.summary", { up, total: panel.rj45.length + panel.sfp.length, rj45: panel.rj45.length, sfp: panel.sfp.length, other: others })}</span>
          </div>
        </>
      )}
      <div aria-live="polite" className="min-h-10 rounded-md border bg-muted/30 px-3 py-2 text-sm" data-testid="port-hint">
        {hovered ? <PortHint deviceId={deviceId} port={hovered} vlans={vlans.get(hovered.if_index)} /> : <span className="text-muted-foreground">{t("phys.hoverHint")}</span>}
      </div>
      {opened && (
        <PortCard
          port={opened}
          vlans={vlans.get(opened.if_index)}
          macCount={macs.data?.items.filter((e) => e.if_index === opened.if_index).length}
          neighbors={lldp.data?.items.filter((n) => n.local_if_index === opened.if_index) ?? []}
          onClose={() => setOpen(undefined)}
          onShowChart={() => onShowChart(opened.if_index)}
        />
      )}
    </div>
  );
}

function Legend({ tone, label }: { tone: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span aria-hidden="true" className={cn("inline-block h-1.5 w-3 rounded-sm", tone)} />
      {label}
    </span>
  );
}

function useSpeed() {
  const { t, i18n } = useTranslation();
  const units = ["bps", "kbps", "mbps", "gbps", "tbps"].map((k) => t(`chart.unit.${k}`));
  return (bps: number) => (bps > 0 ? formatBps(bps, units, i18n.language) : t("phys.unknown"));
}

function vlanText(vlans: number[] | undefined, none: string): string {
  return vlans?.length ? vlans.join(", ") : none;
}

/* mounted only while a port is hovered or focused, so the traffic read happens on demand */
function PortHint({ deviceId, port, vlans }: { deviceId: number; port: Iface; vlans: number[] | undefined }) {
  const { t } = useTranslation();
  const speed = useSpeed();
  const [range] = useState(() => {
    /* whole minutes, so hovering the port again within a minute reuses the cached read */
    const to = new Date(Math.floor(Date.now() / 60_000) * 60_000);
    return { from: new Date(to.getTime() - TRAFFIC_WINDOW_MS), to };
  });
  const m = useIfMetrics(deviceId, port.if_index, range, 60_000);
  const last = m.data?.points.at(-1);
  return (
    <span className="flex flex-wrap gap-x-4 gap-y-1">
      <span className="font-medium break-all">{safeText(port.name)}</span>
      <span>
        {t("phys.speed")}: {speed(port.speed_bps)}
      </span>
      <span>
        {t("phys.vlan")}: {vlanText(vlans, t("phys.unknown"))}
      </span>
      <span>
        {t("phys.traffic")}: {last ? t("phys.inOut", { in: speed(last.in_bps), out: speed(last.out_bps) }) : m.isPending ? t("card.loading") : t("phys.unknown")}
      </span>
    </span>
  );
}

type CardProps = {
  port: Iface;
  vlans: number[] | undefined;
  macCount: number | undefined;
  neighbors: TableRows["lldp"][];
  onClose: () => void;
  onShowChart: () => void;
};

/** Card of one port: inventory facts, VLANs and MACs seen on it, LLDP neighbours. */
function PortCard({ port, vlans, macCount, neighbors, onClose, onShowChart }: CardProps) {
  const { t, i18n } = useTranslation();
  const speed = useSpeed();
  const facts: [string, string][] = [
    [t("card.col.ifIndex"), String(port.if_index)],
    [t("card.col.alias"), safeText(port.alias) || "-"],
    [t("phys.kindLabel"), t(`phys.kindName.${port.port_kind}`)],
    [t("phys.speed"), speed(port.speed_bps)],
    [t("card.col.oper"), t(port.oper_up ? "card.up" : "card.down")],
    [t("phys.vlan"), vlanText(vlans, t("phys.unknown"))],
    [t("phys.macs"), macCount === undefined ? t("phys.unknown") : String(macCount)],
    [t("card.col.seenAt"), new Date(port.seen_at).toLocaleString(i18n.language)],
  ];
  return (
    <section aria-label={t("phys.card", { name: safeText(port.name) })} className="grid gap-3 rounded-md border p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="min-w-0 font-semibold break-all">{safeText(port.name)}</h3>
        <div className="flex gap-2">
          <Button type="button" size="sm" variant="outline" onClick={onShowChart}>
            {t("card.col.chart")}
          </Button>
          <Button type="button" size="sm" variant="ghost" onClick={onClose}>
            {t("phys.close")}
          </Button>
        </div>
      </div>
      <dl className="grid grid-cols-[repeat(auto-fit,minmax(10rem,1fr))] gap-x-6 gap-y-2 text-sm">
        {facts.map(([k, v]) => (
          <div key={k} className="min-w-0">
            <dt className="text-xs text-muted-foreground">{k}</dt>
            <dd className="break-words">{v}</dd>
          </div>
        ))}
      </dl>
      {neighbors.length > 0 && (
        <div className="grid gap-1 text-sm">
          <span className="text-xs text-muted-foreground">{t("phys.neighbors")}</span>
          {neighbors.map((n, i) => (
            <span key={i} className="break-all">
              {safeText(n.sys_name) || safeText(n.chassis_id)} - {safeText(n.port_id)}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}
