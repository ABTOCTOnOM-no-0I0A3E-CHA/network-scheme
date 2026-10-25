import { useEffect, useRef, useState, type ReactNode } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { canReadDevices } from "@/features/auth/permissions";
import { useSession } from "@/features/auth/useSession";
import type { TabId } from "@/features/devices/DeviceCard";
import { safeText } from "@/lib/text";
import { NAV, navVisible } from "./nav";
import { SEARCH_DEBOUNCE_MS, SEARCH_MAX, SEARCH_MIN, useDebounced, useGlobalSearch } from "./search";

/** One result row: the label and detail are rendered as text only. */
function Item({ value, label, detail, onGo }: { value: string; label: ReactNode; detail?: ReactNode; onGo: () => void }) {
  return (
    <CommandItem value={value} onSelect={onGo}>
      <span className="truncate">{label}</span>
      {detail && <span className="ml-auto truncate font-mono text-xs text-muted-foreground">{detail}</span>}
    </CommandItem>
  );
}

function More({ show }: { show: boolean }) {
  const { t } = useTranslation();
  return show ? <p className="px-2 py-1 text-xs text-muted-foreground">{t("palette.more")}</p> : null;
}

function PaletteBody({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data: session } = useSession();
  const [query, setQuery] = useState("");
  const debounced = useDebounced(query, SEARCH_DEBOUNCE_MS);
  const search = useGlobalSearch(debounced, canReadDevices(session));
  /* results of an earlier query stay visible while the next one loads, but never once the input is shorter than a query */
  const r = query.trim().length >= SEARCH_MIN ? search.data : undefined;
  const pending = query.trim().length >= SEARCH_MIN && (query !== debounced || search.isFetching);

  const goSection = (path: string) => {
    onDone();
    void navigate({ to: path as "/" });
  };
  const goDevice = (id: number, tab?: TabId, ifIndex?: number) => {
    onDone();
    void navigate({ to: "/devices/$id", params: { id: String(id) }, search: { tab, if: ifIndex } });
  };

  const needle = query.trim().toLocaleLowerCase();
  const sections = needle ? NAV.filter(({ key }) => navVisible(key, session) && t(`nav.${key}`).toLocaleLowerCase().includes(needle)) : [];

  return (
    /* results are filtered by the server, not by cmdk; at most 50 per type are rendered */
    <Command shouldFilter={false}>
      <CommandInput autoFocus maxLength={SEARCH_MAX} placeholder={t("palette.placeholder")} value={query} onValueChange={setQuery} />
      <CommandList>
        <CommandEmpty>{t(search.isError && query.trim() ? "palette.error" : pending ? "palette.searching" : "palette.empty")}</CommandEmpty>
        {sections.length > 0 && (
          <CommandGroup heading={t("palette.sections")}>
            {sections.map(({ key, path }) => (
              <Item key={key} value={`section:${key}`} label={t(`nav.${key}`)} onGo={() => goSection(path)} />
            ))}
          </CommandGroup>
        )}
        {!!r?.devices.items.length && (
          <CommandGroup heading={t("palette.devices")}>
            {r.devices.items.map((d) => (
              <Item key={d.id} value={`device:${d.id}`} label={safeText(d.name)} detail={safeText(d.address)} onGo={() => goDevice(d.id)} />
            ))}
            <More show={r.devices.more} />
          </CommandGroup>
        )}
        {!!r?.ips.items.length && (
          <CommandGroup heading={t("palette.ips")}>
            {r.ips.items.map((a) => (
              <Item
                key={`${a.device_id}:${a.ip}:${a.if_index}`}
                value={`ip:${a.device_id}:${a.ip}:${a.if_index}`}
                label={safeText(a.ip)}
                detail={`${safeText(a.mac)} · ${safeText(a.device_name)}${a.port_name ? ` · ${safeText(a.port_name)}` : ""}`}
                onGo={() => goDevice(a.device_id, "arp")}
              />
            ))}
            <More show={r.ips.more} />
          </CommandGroup>
        )}
        {!!r?.macs.items.length && (
          <CommandGroup heading={t("palette.macs")}>
            {r.macs.items.map((m) => {
              const where = m.source === "fdb" ? t("palette.vlan", { vlan: m.vlan ?? 0 }) : safeText(m.ip);
              return (
                <Item
                  key={`${m.source}:${m.device_id}:${m.mac}:${m.vlan ?? m.ip}`}
                  value={`mac:${m.source}:${m.device_id}:${m.mac}:${m.vlan ?? m.ip}`}
                  label={safeText(m.mac)}
                  detail={`${t(`palette.source.${m.source}`)} · ${where} · ${safeText(m.device_name)}${m.port_name ? ` · ${safeText(m.port_name)}` : ""}`}
                  onGo={() => goDevice(m.device_id, m.source === "fdb" ? "mac" : "arp")}
                />
              );
            })}
            <More show={r.macs.more} />
          </CommandGroup>
        )}
        {!!r?.ports.items.length && (
          <CommandGroup heading={t("palette.ports")}>
            {r.ports.items.map((p) => (
              <Item
                key={`${p.device_id}:${p.if_index}`}
                value={`port:${p.device_id}:${p.if_index}`}
                label={`${safeText(p.name)}${p.alias ? ` (${safeText(p.alias)})` : ""}`}
                detail={safeText(p.device_name)}
                onGo={() => goDevice(p.device_id, "graphs", p.if_index)}
              />
            ))}
            <More show={r.ports.more} />
          </CommandGroup>
        )}
      </CommandList>
    </Command>
  );
}

/**
 * Command palette in a native modal <dialog>. A Radix Dialog would pull in
 * react-remove-scroll, whose runtime <style> injection the panel CSP blocks;
 * the native element needs no scroll-lock library and traps focus itself.
 * It searches panel sections (locally) and, through GET /api/search, devices,
 * ARP addresses, MACs and ports; results open the device on the matching tab.
 */
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const { t } = useTranslation();
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) {
      /* jsdom lacks showModal(); the fallback keeps unit tests meaningful */
      if (typeof d.showModal === "function") d.showModal();
      else d.setAttribute("open", "");
      /* React's autoFocus ran while the dialog was still closed; showModal() then focuses the dialog itself */
      d.querySelector("input")?.focus();
    } else if (!open && d.open) {
      if (typeof d.close === "function") d.close();
      else d.removeAttribute("open");
    }
  }, [open]);

  return (
    <dialog
      ref={ref}
      aria-label={t("palette.title")}
      className="m-auto mt-[15vh] w-full max-w-lg overflow-hidden rounded-lg border bg-popover p-0 text-popover-foreground shadow-lg backdrop:bg-black/50"
      onCancel={(e) => {
        /* Escape: update state synchronously and let the effect close the dialog.
           The native close event arrives a task later, so relying on it lets a quick
           Ctrl+K toggle the still-true state back to false. */
        e.preventDefault();
        onOpenChange(false);
      }}
      onClose={() => {
        /* A close event queued before a quick reopen must not close the reopened dialog. */
        if (!ref.current?.open) onOpenChange(false);
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onOpenChange(false);
      }}
    >
      {open && <PaletteBody onDone={() => onOpenChange(false)} />}
    </dialog>
  );
}
