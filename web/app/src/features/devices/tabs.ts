import type { DeviceTable } from "./api";

/** Tabs of the device window and page, in the order of FR-UI-DEV; "physical" is the default. */
export const TABS = ["physical", "config", "cli", "data", "graphs", "backups", "journal", "access"] as const;
export type Tab = (typeof TABS)[number];

/** Sub-tabs of "Данные": the inventory tables. */
export const DATA_TABS: readonly DeviceTable[] = ["interfaces", "arp", "mac", "vlans", "lldp", "routes", "entities"];

/** A deep link target: a tab, or "data/<table>" for one table of "Данные". */
export type TabRef = Exclude<Tab, "data"> | "data" | `data/${DeviceTable}`;

/* ids of the tabs before the FR-UI-DEV layout, still found in bookmarks and links */
const LEGACY: Record<string, TabRef> = {
  profiles: "access",
  problems: "journal",
  ...Object.fromEntries(DATA_TABS.map((d) => [d, `data/${d}` as TabRef])),
};

/** The tab reference a `?tab=` value names (current or legacy id), or undefined for anything else. */
export function parseTabRef(v: unknown): TabRef | undefined {
  if (typeof v !== "string") return undefined;
  if ((TABS as readonly string[]).includes(v)) return v as TabRef;
  if (v.startsWith("data/") && (DATA_TABS as readonly string[]).includes(v.slice(5))) return v as TabRef;
  return Object.hasOwn(LEGACY, v) ? LEGACY[v] : undefined;
}

/** Splits a reference into the tab and the "Данные" sub-tab (interfaces when none is named). */
export function splitTabRef(ref: TabRef | undefined): { tab: Tab; data: DeviceTable } {
  if (!ref) return { tab: "physical", data: "interfaces" };
  if (ref.startsWith("data/")) return { tab: "data", data: ref.slice(5) as DeviceTable };
  return { tab: ref as Tab, data: "interfaces" };
}
