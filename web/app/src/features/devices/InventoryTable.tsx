import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { errorKey } from "@/features/auth/errors";
import { ApiError, StepUpCancelled, unwrap, withStepUp } from "@/features/common/stepup";
import { api } from "@/lib/api";
import { safeText } from "@/lib/text";
import { useDeviceTable, type DeviceTable, type TableRows } from "./api";

export const PAGE_SIZE = 50;

/** Same-origin URL of the server-side CSV export of a table, with the search and the named filter of the view. */
function exportUrl(deviceId: number, table: DeviceTable, search: string, filterId: string): string {
  const q = new URLSearchParams();
  if (search) q.set("q", search);
  if (filterId) q.set("filter", filterId);
  const qs = q.toString();
  return `/api/devices/${deviceId}/export/${table}${qs ? `?${qs}` : ""}`;
}

/** A named row filter offered next to the search box. */
export type RowFilter<R> = { id: string; label: string; test: (row: R) => boolean };

/** Whether any field of the row contains the (lower-cased) query. */
export function rowMatches(row: object, q: string): boolean {
  return !q || Object.values(row).some((v) => v !== null && v !== undefined && String(v).toLowerCase().includes(q));
}

export type Column<R> = { id: string; header: string; cell: (row: R) => ReactNode };

/** Device-reported text: wraps anywhere, keeps the full value in the tooltip. */
export function Text({ value, mono }: { value: string | null | undefined; mono?: boolean }) {
  const s = safeText(value);
  return (
    <span title={s} className={`block max-w-[28rem] break-words ${mono ? "font-mono text-xs" : ""}`}>
      {s}
    </span>
  );
}

type Props<T extends DeviceTable> = {
  deviceId: number;
  table: T;
  columns: Column<TableRows[T]>[];
  seenAt: (row: TableRows[T]) => string;
  filters?: RowFilter<TableRows[T]>[];
};

/**
 * One inventory table with next/previous paging over `next_offset`, search and
 * filters over the page, and a CSV export of the whole table (same search and
 * filter) built, capped and audited by the server. The export needs a fresh
 * step-up: the shared step-up prompt is shown first, then the browser
 * downloads the file through a same-origin link.
 */
export function InventoryTable<T extends DeviceTable>({ deviceId, table, columns, seenAt, filters = [] }: Props<T>) {
  const { t, i18n } = useTranslation();
  const [search, setSearch] = useState("");
  const [filterId, setFilterId] = useState("");
  const [exportError, setExportError] = useState<string | undefined>();
  const [exporting, setExporting] = useState(false);
  const q0 = search.trim().toLowerCase();
  const filter = filters.find((f) => f.id === filterId);
  const keep = (r: TableRows[T]) => rowMatches(r, q0) && (!filter || filter.test(r));
  /* offsets of the pages already visited; the last one is the current page */
  const [offsets, setOffsets] = useState<number[]>([0]);
  const offset = offsets[offsets.length - 1];
  const q = useDeviceTable(deviceId, table, { limit: PAGE_SIZE, offset });
  const next = q.data?.next_offset ?? null;
  const error = q.error instanceof ApiError ? t(errorKey({ error: { code: q.error.code } })) : q.error ? t("errors.unknown") : undefined;
  const visible = q.data?.items.filter(keep);

  const exportCsv = async () => {
    setExportError(undefined);
    setExporting(true);
    try {
      await withStepUp(async () => unwrap(await api.GET("/api/auth/stepup-status")));
      const a = document.createElement("a");
      a.href = exportUrl(deviceId, table, search.trim(), filterId);
      a.download = "";
      document.body.append(a);
      a.click();
      a.remove();
    } catch (e) {
      if (!(e instanceof StepUpCancelled)) setExportError(t(e instanceof ApiError ? errorKey({ error: { code: e.code } }) : "errors.unknown"));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="grid gap-1 text-xs text-muted-foreground">
          {t("data.search")}
          <Input className="w-64" type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t("data.searchHint")} />
        </label>
        {filters.length > 0 && (
          <label className="grid gap-1 text-xs text-muted-foreground">
            {t("data.filter")}
            <select
              className="h-9 rounded-md border border-input bg-transparent px-3 text-sm text-foreground dark:bg-input/30"
              value={filterId}
              onChange={(e) => setFilterId(e.target.value)}
            >
              <option value="">{t("data.all")}</option>
              {filters.map((f) => (
                <option key={f.id} value={f.id}>
                  {f.label}
                </option>
              ))}
            </select>
          </label>
        )}
        <Button type="button" variant="outline" size="sm" disabled={exporting} onClick={() => void exportCsv()}>
          {t("data.csv")}
        </Button>
      </div>
      {exportError && (
        <p role="alert" className="text-sm text-destructive">
          {exportError}
        </p>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <div className="overflow-x-auto rounded-md border">
        <table className="w-full min-w-[40rem] text-left text-sm" aria-label={t(`card.tab.${table}`)}>
          <thead className="bg-muted/50 text-xs text-muted-foreground">
            <tr>
              {columns.map((c) => (
                <th key={c.id} scope="col" className="px-3 py-2 font-medium">
                  {c.header}
                </th>
              ))}
              <th scope="col" className="px-3 py-2 font-medium">
                {t("card.col.seenAt")}
              </th>
            </tr>
          </thead>
          <tbody>
            {visible?.map((row, i) => (
              <tr key={offset + i} className="border-t align-top">
                {columns.map((c) => (
                  <td key={c.id} className="px-3 py-2">
                    {c.cell(row)}
                  </td>
                ))}
                <td className="px-3 py-2 whitespace-nowrap text-xs text-muted-foreground">{new Date(seenAt(row)).toLocaleString(i18n.language)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {q.isPending && <p className="p-3 text-sm text-muted-foreground">{t("card.loading")}</p>}
        {visible && visible.length === 0 && <p className="p-3 text-sm text-muted-foreground">{t(q.data?.items.length ? "data.noMatch" : "card.noRows")}</p>}
      </div>
      <div className="flex items-center gap-2">
        <Button type="button" variant="outline" size="sm" disabled={offsets.length < 2} onClick={() => setOffsets((o) => o.slice(0, -1))}>
          {t("card.prev")}
        </Button>
        <Button type="button" variant="outline" size="sm" disabled={next === null || q.isPlaceholderData} onClick={() => next !== null && setOffsets((o) => [...o, next])}>
          {t("card.next")}
        </Button>
        <span className="text-xs text-muted-foreground">{t("card.page", { n: offsets.length })}</span>
      </div>
    </div>
  );
}
