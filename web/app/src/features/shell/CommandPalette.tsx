import { useEffect, useRef, useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { useDevices } from "@/features/devices/api";

const MAX_RESULTS = 20;

/* Devices matching the query by name or address; nothing is requested or listed until something is typed. */
function DeviceResults({ query, onDone }: { query: string; onDone: () => void }) {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { data } = useDevices({ search: query });
  if (!query.trim() || !data?.length) return null;
  return (
    <CommandGroup heading={t("palette.devices")}>
      {data.slice(0, MAX_RESULTS).map((d) => (
        <CommandItem
          key={d.id}
          value={String(d.id)}
          onSelect={() => {
            onDone();
            void navigate({ to: "/devices", search: { q: d.name } });
          }}
        >
          <span className="truncate">{d.name}</span>
          <span className="ml-auto font-mono text-xs text-muted-foreground">{d.address}</span>
        </CommandItem>
      ))}
    </CommandGroup>
  );
}

function PaletteBody({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  return (
    /* results are filtered by the device query itself, not by cmdk, so thousands of devices are never rendered */
    <Command shouldFilter={false}>
      <CommandInput autoFocus placeholder={t("palette.placeholder")} value={query} onValueChange={setQuery} />
      <CommandList>
        <CommandEmpty>{t("palette.empty")}</CommandEmpty>
        <DeviceResults query={query} onDone={onDone} />
      </CommandList>
    </Command>
  );
}

/**
 * Command palette in a native modal <dialog>. A Radix Dialog would pull in
 * react-remove-scroll, whose runtime <style> injection the panel CSP blocks;
 * the native element needs no scroll-lock library and traps focus itself.
 * It searches devices by name or address.
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
