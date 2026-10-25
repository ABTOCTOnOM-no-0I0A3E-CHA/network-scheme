import type { ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { safeText } from "@/lib/text";

/** A device name (device data, shown as text) that opens the device window. */
export function DeviceName({ id, name }: { id: number; name: string }) {
  const navigate = useNavigate();
  return (
    <button type="button" className="truncate text-left hover:underline" onClick={() => void navigate({ to: "/devices/$id", params: { id: String(id) } })}>
      {safeText(name) || `#${id}`}
    </button>
  );
}

/** The muted line a widget shows when it has nothing to list. */
export function Empty({ children }: { children?: ReactNode }) {
  const { t } = useTranslation();
  return <p className="text-sm text-muted-foreground">{children ?? t("widgets.empty")}</p>;
}

/** A compact table of a widget: one row per item, the first column grows. */
export function Rows({ children }: { children: ReactNode }) {
  return (
    <table className="w-full table-fixed text-sm">
      <tbody className="[&_td]:py-0.5 [&_td:first-child]:w-auto [&_td:not(:first-child)]:w-24 [&_td:not(:first-child)]:text-right [&_td:not(:first-child)]:tabular-nums">
        {children}
      </tbody>
    </table>
  );
}
