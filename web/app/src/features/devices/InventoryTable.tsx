import { useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { errorKey } from "@/features/auth/errors";
import { ApiError } from "@/features/common/stepup";
import { safeText } from "@/lib/text";
import { useDeviceTable, type DeviceTable, type TableRows } from "./api";

export const PAGE_SIZE = 50;

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

type Props<T extends DeviceTable> = { deviceId: number; table: T; columns: Column<TableRows[T]>[]; seenAt: (row: TableRows[T]) => string };

/** One inventory table with next/previous paging over `next_offset`. */
export function InventoryTable<T extends DeviceTable>({ deviceId, table, columns, seenAt }: Props<T>) {
  const { t, i18n } = useTranslation();
  /* offsets of the pages already visited; the last one is the current page */
  const [offsets, setOffsets] = useState<number[]>([0]);
  const offset = offsets[offsets.length - 1];
  const q = useDeviceTable(deviceId, table, { limit: PAGE_SIZE, offset });
  const next = q.data?.next_offset ?? null;
  const error = q.error instanceof ApiError ? t(errorKey({ error: { code: q.error.code } })) : q.error ? t("errors.unknown") : undefined;

  return (
    <div className="grid gap-3">
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
            {q.data?.items.map((row, i) => (
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
        {q.data && q.data.items.length === 0 && <p className="p-3 text-sm text-muted-foreground">{t("card.noRows")}</p>}
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
