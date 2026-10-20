import { useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Command, CommandEmpty, CommandInput, CommandList } from "@/components/ui/command";

/**
 * Command palette in a native modal <dialog>. A Radix Dialog would pull in
 * react-remove-scroll, whose runtime <style> injection the panel CSP blocks;
 * the native element needs no scroll-lock library and traps focus itself.
 * Phase 0 has no commands, so it always shows the empty state.
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
      onClose={() => onOpenChange(false)}
      onClick={(e) => {
        if (e.target === e.currentTarget) onOpenChange(false);
      }}
    >
      {open && (
        <Command>
          <CommandInput autoFocus placeholder={t("palette.placeholder")} />
          <CommandList>
            <CommandEmpty>{t("palette.empty")}</CommandEmpty>
          </CommandList>
        </Command>
      )}
    </dialog>
  );
}
