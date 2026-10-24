import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { components } from "@/api/schema";
import { pickStep, coarserStep } from "@/features/charts/series";
import { ApiError, unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";

type S = components["schemas"];
export type Device = S["Device"];
export type DeviceDetail = S["DeviceDetail"];
export type Group = S["Group"];
export type IfPoint = S["IfPoint"];
export type SysPoint = S["SysPoint"];

/* the typed header is required by the schema; the api middleware overwrites it with the real token */
const CSRF = { header: { "X-CSRF-Token": "" } };

export type DeviceFilter = { groupId?: number; state?: Device["state"]; search?: string };

/** Inventory tables of a device and the row type of each. */
export type TableRows = {
  interfaces: S["InventoryInterface"];
  arp: S["InventoryARPEntry"];
  mac: S["InventoryMACEntry"];
  vlans: S["InventoryVLAN"];
  lldp: S["InventoryLLDPNeighbor"];
  entities: S["InventoryEntity"];
  routes: S["InventoryRoute"];
};
export type DeviceTable = keyof TableRows;
export type TablePage<T> = { items: T[]; next_offset: number | null };
export type PageParams = { limit?: number; offset?: number };

export const deviceKeys = {
  all: ["devices"] as const,
  list: ["devices", "list"] as const,
  one: (id: number) => ["devices", "one", id] as const,
  table: (id: number, table: DeviceTable, page: PageParams) => ["devices", "table", id, table, page.limit ?? null, page.offset ?? 0] as const,
  metrics: (id: number, ifIndex: number, from: string, to: string, step?: number) => ["devices", "metrics", id, ifIndex, from, to, step ?? null] as const,
  sys: (id: number, from: string, to: string, step?: number) => ["devices", "sys", id, from, to, step ?? null] as const,
  groups: ["groups"] as const,
};

/** Applies the client-side filter (the API has no server-side one). */
export function filterDevices(devices: Device[], f: DeviceFilter): Device[] {
  const q = f.search?.trim().toLowerCase();
  return devices.filter(
    (d) =>
      (f.groupId === undefined || d.group_id === f.groupId) &&
      (f.state === undefined || d.state === f.state) &&
      (!q || d.name.toLowerCase().includes(q) || d.address.toLowerCase().includes(q)),
  );
}

/** Devices visible to the caller, narrowed by `filter`. */
export function useDevices(filter: DeviceFilter = {}) {
  const { groupId, state, search } = filter;
  return useQuery({
    queryKey: deviceKeys.list,
    queryFn: async () => unwrap(await api.GET("/api/devices")),
    select: (all) => filterDevices(all, { groupId, state, search }),
  });
}

/** One device; resolves to null on 404 (missing or outside the caller's groups). */
export function useDevice(id: number) {
  return useQuery({
    queryKey: deviceKeys.one(id),
    retry: false,
    queryFn: async (): Promise<DeviceDetail | null> => {
      const r = await api.GET("/api/devices/{id}", { params: { path: { id } } });
      if (r.response.status === 404) return null;
      return unwrap(r);
    },
  });
}

/* One typed call per table; a generic path would lose the response types. */
const TABLE_FETCH: { [T in DeviceTable]: (id: number, q: PageParams) => Promise<TablePage<TableRows[T]>> } = {
  interfaces: async (id, q) => unwrap(await api.GET("/api/devices/{id}/interfaces", { params: { path: { id }, query: q } })),
  arp: async (id, q) => unwrap(await api.GET("/api/devices/{id}/arp", { params: { path: { id }, query: q } })),
  mac: async (id, q) => unwrap(await api.GET("/api/devices/{id}/mac", { params: { path: { id }, query: q } })),
  vlans: async (id, q) => unwrap(await api.GET("/api/devices/{id}/vlans", { params: { path: { id }, query: q } })),
  lldp: async (id, q) => unwrap(await api.GET("/api/devices/{id}/lldp", { params: { path: { id }, query: q } })),
  entities: async (id, q) => unwrap(await api.GET("/api/devices/{id}/entities", { params: { path: { id }, query: q } })),
  routes: async (id, q) => unwrap(await api.GET("/api/devices/{id}/routes", { params: { path: { id }, query: q } })),
};

/** One page of an inventory table; the previous page stays visible while the next loads. */
export function useDeviceTable<T extends DeviceTable>(id: number, table: T, page: PageParams = {}) {
  return useQuery({
    queryKey: deviceKeys.table(id, table, page),
    queryFn: () => TABLE_FETCH[table](id, page) as Promise<TablePage<TableRows[T]>>,
    placeholderData: keepPreviousData,
  });
}

/** Every row of an inventory table, page by page, stopping after `cap` rows (for exports). */
export async function fetchAllRows<T extends DeviceTable>(id: number, table: T, cap: number): Promise<{ rows: TableRows[T][]; capped: boolean }> {
  const rows: TableRows[T][] = [];
  let offset: number | null = 0;
  while (offset !== null && rows.length < cap) {
    const page = (await TABLE_FETCH[table](id, { limit: 1000, offset })) as TablePage<TableRows[T]>;
    rows.push(...page.items);
    offset = page.next_offset;
  }
  return { rows: rows.slice(0, cap), capped: offset !== null || rows.length > cap };
}

export type MetricsRange = { from: Date; to: Date; step?: number };

/**
 * Rate series of one interface over `range`. Without `range.step` the step is
 * picked to stay under the point limit; on `too_many_points` the step is
 * doubled and the request repeated once.
 */
export function useIfMetrics(id: number, ifIndex: number, range: MetricsRange) {
  const from = range.from.toISOString();
  const to = range.to.toISOString();
  return useQuery({
    queryKey: deviceKeys.metrics(id, ifIndex, from, to, range.step),
    retry: false,
    queryFn: async () => {
      const fetchOnce = async (step: number) =>
        unwrap(await api.GET("/api/devices/{id}/metrics/if", { params: { path: { id }, query: { if_index: ifIndex, from, to, step } } }));
      const step = range.step ?? pickStep(range.from, range.to);
      try {
        return await fetchOnce(step);
      } catch (e) {
        if (e instanceof ApiError && e.code === "too_many_points") return fetchOnce(coarserStep(step));
        throw e;
      }
    },
  });
}

/** CPU, memory and temperature series of the device over `range`; the step is picked like useIfMetrics. */
export function useSysMetrics(id: number, range: MetricsRange) {
  const from = range.from.toISOString();
  const to = range.to.toISOString();
  return useQuery({
    queryKey: deviceKeys.sys(id, from, to, range.step),
    retry: false,
    queryFn: async () => {
      const fetchOnce = async (step: number) => unwrap(await api.GET("/api/devices/{id}/metrics/sys", { params: { path: { id }, query: { from, to, step } } }));
      const step = range.step ?? pickStep(range.from, range.to);
      try {
        return await fetchOnce(step);
      } catch (e) {
        if (e instanceof ApiError && e.code === "too_many_points") return fetchOnce(coarserStep(step));
        throw e;
      }
    },
  });
}

/** Device groups (needs groups.manage; others get a 403 error). Pass `false` to skip the request for those who may not list them. */
export function useGroups(enabled = true) {
  return useQuery({
    queryKey: deviceKeys.groups,
    enabled,
    queryFn: async () => unwrap(await api.GET("/api/groups")),
  });
}

export type DeviceCreate = { name: string; address: string; group_id: number; snmp_port?: number };
export type DevicePatch = Partial<Pick<DeviceDetail, "name" | "address" | "snmp_port" | "group_id" | "interval_avail_s" | "interval_metrics_s" | "interval_inventory_s" | "parent_id">>;

/** Adds a device; resolves to its id. */
export function useCreateDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DeviceCreate) => withStepUp(async () => unwrap(await api.POST("/api/devices", { params: CSRF, body })).id),
    onSettled: () => qc.invalidateQueries({ queryKey: deviceKeys.all }),
  });
}

/** Changes device fields; absent fields stay as they are. */
export function useUpdateDevice(id: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (body: DevicePatch) =>
      withStepUp(async () => {
        unwrap(await api.PATCH("/api/devices/{id}", { params: { path: { id }, ...CSRF }, body }));
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: deviceKeys.all }),
  });
}

/** Deletes a device and its credentials (step-up). */
export function useDeleteDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      withStepUp(async () => {
        unwrap(await api.DELETE("/api/devices/{id}", { params: { path: { id }, ...CSRF } }));
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: deviceKeys.all }),
  });
}

/** Queues an immediate full poll. */
export function usePollDevice() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      withStepUp(async () => {
        unwrap(await api.POST("/api/devices/{id}/poll", { params: { path: { id }, ...CSRF } }));
      }),
    onSettled: (_d, _e, id) => qc.invalidateQueries({ queryKey: deviceKeys.one(id) }),
  });
}
