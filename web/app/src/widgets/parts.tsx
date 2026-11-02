import type { ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Server } from "lucide-react";
import { useTranslation } from "react-i18next";
import { useDeviceWindows } from "@/features/devices/DeviceWindows";
import { safeText } from "@/lib/text";

/* opens the device window where the app has them, else the device page */
function useOpenDevice() {
  const navigate = useNavigate();
  const windows = useDeviceWindows();
  return (id: number, name: string) => (windows ? windows.open(id, name) : void navigate({ to: "/devices/$id", params: { id: String(id) } }));
}

/** A device name (device data, shown as text) that opens the device window. */
export function DeviceName({ id, name }: { id: number; name: string }) {
  const open = useOpenDevice();
  return (
    <button type="button" className="truncate text-left hover:underline" onClick={() => open(id, name)}>
      {safeText(name) || `#${id}`}
    </button>
  );
}

/** A device as a compact chip (device data, shown as text) that opens the device window. */
export function DeviceChip({ id, name }: { id: number; name: string }) {
  const open = useOpenDevice();
  const label = safeText(name) || `#${id}`;
  return (
    <button
      type="button"
      title={label}
      className="inline-flex max-w-[12rem] min-w-0 shrink-0 items-center gap-1 rounded-full border bg-background px-2 py-px font-medium text-foreground shadow-xs transition-colors hover:border-primary/50 hover:bg-accent focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none"
      onClick={() => open(id, name)}
    >
      <Server aria-hidden="true" className="size-3 shrink-0 text-muted-foreground" />
      <span className="truncate">{label}</span>
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
