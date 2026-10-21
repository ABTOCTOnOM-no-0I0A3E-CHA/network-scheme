import { useMemo, useRef, useState } from "react";
import { createColumnHelper, flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Plus } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { errorKey } from "@/features/auth/errors";
import { StateBadge } from "@/features/common/StateBadge";
import { ApiError } from "@/features/common/stepup";
import { cn } from "@/lib/utils";
import { AddDeviceDialog } from "./AddDeviceDialog";
import { filterDevices, useDevices, useGroups, type Device } from "./api";

const ROW_HEIGHT = 44;
const NO_DEVICES: Device[] = [];
const MIN_WIDTH = "min-w-[70rem]";
const GRID =
  "grid grid-cols-[7rem_minmax(8rem,1.2fr)_minmax(8rem,1fr)_minmax(7rem,1fr)_minmax(7rem,1fr)_minmax(6rem,0.8fr)_minmax(10rem,1.2fr)_minmax(9rem,1fr)] items-center gap-3 px-3";
const SELECT_CLASS = "h-9 rounded-md border border-input bg-transparent px-3 text-sm dark:bg-input/30";
const STATES: Device["state"][] = ["up", "partial", "down", "unknown"];

type Props = {
  /** Whether the add button is offered (a UI hint; the API decides). */
  canAdd: boolean;
  search: string;
  onSearchChange: (search: string) => void;
  /** Opens the device card; names are plain text when absent. */
  onOpen?: (id: number) => void;
};

/** Device inventory: filters, virtualized table and the add-device dialog. All device fields are rendered as text. */
export function DeviceList({ canAdd, search, onSearchChange, onOpen }: Props) {
  const { t } = useTranslation();
  const [groupId, setGroupId] = useState<number | undefined>();
  const [state, setState] = useState<Device["state"] | undefined>();
  const [adding, setAdding] = useState(false);
  const all = useDevices();
  const filtered = useMemo(() => filterDevices(all.data ?? NO_DEVICES, { groupId, state, search }), [all.data, groupId, state, search]);
  const devices = { isPending: all.isPending, error: all.error, data: all.data && filtered };
  const groups = useGroups();
  const groupNames = useMemo(() => new Map(groups.data?.map((g) => [g.id, g.name])), [groups.data]);

  const columns = useMemo(() => {
    const h = createColumnHelper<Device>();
    return [
      h.accessor("state", { id: "state", header: () => t("devices.col.state"), cell: (c) => <StateBadge state={c.getValue()} since={c.row.original.state_since} /> }),
      h.accessor("name", { id: "name", header: () => t("devices.col.name"), cell: (c) =>
          onOpen ? (
            <button type="button" title={c.getValue()} className="truncate text-left font-medium underline-offset-2 hover:underline" onClick={() => onOpen(c.row.original.id)}>
              {c.getValue()}
            </button>
          ) : (
            <span className="truncate font-medium">{c.getValue()}</span>
          ),
      }),
      h.accessor("address", { id: "address", header: () => t("devices.col.address"), cell: (c) => <span className="truncate font-mono text-xs">{c.getValue()}</span> }),
      h.accessor("group_id", {
        id: "group",
        header: () => t("devices.col.group"),
        cell: (c) => <span className="truncate">{groupNames.get(c.getValue()) ?? `#${c.getValue()}`}</span>,
      }),
      h.accessor("model", { id: "model", header: () => t("devices.col.model"), cell: (c) => <span className="truncate">{c.getValue()}</span> }),
      h.accessor("firmware", { id: "firmware", header: () => t("devices.col.firmware"), cell: (c) => <span className="truncate">{c.getValue()}</span> }),
      h.accessor("driver", {
        id: "driver",
        header: () => t("devices.col.driver"),
        cell: (c) => (
          <span className="flex flex-wrap items-center gap-1">
            <span className="truncate">{c.getValue()}</span>
            {c.getValue().startsWith("eltex") && (
              <span className="rounded bg-amber-100 px-1.5 py-0.5 text-[10px] text-amber-800 dark:bg-amber-950 dark:text-amber-300">{t("devices.unverified")}</span>
            )}
          </span>
        ),
      }),
      h.accessor("insecure_protocols", {
        id: "security",
        header: () => t("devices.col.security"),
        cell: (c) =>
          c.getValue() ? (
            <span title={t("devices.insecureHint")} className="rounded bg-red-100 px-1.5 py-0.5 text-xs text-red-800 dark:bg-red-950 dark:text-red-300">
              {t("devices.insecure")}
            </span>
          ) : null,
      }),
    ];
  }, [t, groupNames, onOpen]);

  /* the compiler skips memoizing this component, which is what TanStack Table needs */
  // eslint-disable-next-line react-hooks/incompatible-library
  const table = useReactTable({ data: devices.data ?? NO_DEVICES, columns, getCoreRowModel: getCoreRowModel() });
  const tableRows = table.getRowModel().rows;
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({ count: tableRows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_HEIGHT, overscan: 8 });

  /* the group filter needs groups.manage; users without it simply do not get the control */
  const groupList = groups.data;
  const loadError = devices.error instanceof ApiError ? t(errorKey({ error: { code: devices.error.code } })) : devices.error ? t("errors.unknown") : undefined;

  return (
    <section className="grid gap-4">
      <div className="flex items-center justify-between gap-2">
        <h1 className="text-xl font-semibold">{t("devices.title")}</h1>
        {canAdd && (
          <Button onClick={() => setAdding(true)}>
            <Plus />
            {t("devices.add")}
          </Button>
        )}
      </div>
      <div className="flex flex-wrap gap-2">
        <Input className="max-w-xs" type="search" aria-label={t("devices.search")} placeholder={t("devices.search")} value={search} onChange={(e) => onSearchChange(e.target.value)} />
        <select
          aria-label={t("devices.filter.state")}
          className={SELECT_CLASS}
          value={state ?? ""}
          onChange={(e) => setState((e.target.value || undefined) as Device["state"] | undefined)}
        >
          <option value="">{t("devices.filter.allStates")}</option>
          {STATES.map((s) => (
            <option key={s} value={s}>
              {t(`state.${s}`)}
            </option>
          ))}
        </select>
        {groupList && (
          <select
            aria-label={t("devices.filter.group")}
            className={SELECT_CLASS}
            value={groupId ?? ""}
            onChange={(e) => setGroupId(e.target.value ? Number(e.target.value) : undefined)}
          >
            <option value="">{t("devices.filter.allGroups")}</option>
            {groupList.map((g) => (
              <option key={g.id} value={g.id}>
                {g.name}
              </option>
            ))}
          </select>
        )}
      </div>
      {loadError && (
        <p role="alert" className="text-sm text-destructive">
          {loadError}
        </p>
      )}
      <div role="table" aria-label={t("devices.table")} aria-rowcount={tableRows.length + 1} className="overflow-x-auto rounded-md border">
        <div className={MIN_WIDTH}>
          {table.getHeaderGroups().map((hg) => (
            <div key={hg.id} role="row" className={cn(GRID, "h-10 border-b bg-muted/50 text-xs font-medium text-muted-foreground")}>
              {hg.headers.map((hd) => (
                <div key={hd.id} role="columnheader">
                  {hd.isPlaceholder ? null : flexRender(hd.column.columnDef.header, hd.getContext())}
                </div>
              ))}
            </div>
          ))}
          <div ref={scrollRef} className="h-[65vh] overflow-y-auto" data-testid="device-scroll">
            <div className="relative w-full" style={{ height: virtual.getTotalSize() }}>
              {virtual.getVirtualItems().map((v) => {
                const row = tableRows[v.index];
                return (
                  <div
                    key={row.id}
                    role="row"
                    aria-rowindex={v.index + 2}
                    className={cn(GRID, "absolute top-0 left-0 w-full border-b text-sm")}
                    style={{ height: v.size, transform: `translateY(${v.start}px)` }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <div key={cell.id} role="cell" className="flex min-w-0 items-center">
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </div>
                    ))}
                  </div>
                );
              })}
            </div>
            {devices.isPending && <p className="p-4 text-sm text-muted-foreground">{t("devices.loading")}</p>}
            {!devices.isPending && !loadError && tableRows.length === 0 && <p className="p-4 text-sm text-muted-foreground">{t("devices.empty")}</p>}
          </div>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">{t("devices.count", { shown: tableRows.length, total: all.data?.length ?? 0 })}</p>
      {canAdd && <AddDeviceDialog open={adding} onOpenChange={setAdding} groups={groupList} />}
    </section>
  );
}
