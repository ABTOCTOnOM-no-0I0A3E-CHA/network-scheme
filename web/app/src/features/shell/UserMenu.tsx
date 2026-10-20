import { useEffect, useRef, useState } from "react";
import { LogOut, User } from "lucide-react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

/**
 * Minimal user menu. Radix DropdownMenu is avoided: its Menu primitive imports
 * react-remove-scroll, whose runtime <style> injection the panel CSP blocks.
 */
export function UserMenu({ username, onLogout }: { username: string; onLogout: () => void }) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const down = (e: MouseEvent) => {
      if (!root.current?.contains(e.target as Node)) setOpen(false);
    };
    const key = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", down);
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("mousedown", down);
      document.removeEventListener("keydown", key);
    };
  }, [open]);

  return (
    <div ref={root} className="relative">
      <Button variant="ghost" size="sm" aria-haspopup="menu" aria-expanded={open} aria-label={t("shell.userMenu")} onClick={() => setOpen(!open)}>
        <User />
        <span className="hidden sm:inline">{username}</span>
      </Button>
      {open && (
        <div role="menu" className="absolute right-0 z-50 mt-1 min-w-40 rounded-md border bg-popover p-1 text-popover-foreground shadow-md">
          <button
            type="button"
            role="menuitem"
            className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground"
            onClick={() => {
              setOpen(false);
              onLogout();
            }}
          >
            <LogOut className="size-4" />
            {t("shell.logout")}
          </button>
        </div>
      )}
    </div>
  );
}
