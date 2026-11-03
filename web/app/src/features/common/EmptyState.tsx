import { Inbox, type LucideIcon } from "lucide-react";

/** A friendly empty state: an icon, a short title and a hint on what fills it. */
export function EmptyState({ title, hint, icon: Icon = Inbox }: { title: string; hint?: string; icon?: LucideIcon }) {
  return (
    <div className="flex flex-col items-center gap-1 rounded-lg border border-dashed px-4 py-8 text-center">
      <Icon aria-hidden="true" className="mb-1 size-6 text-muted-foreground/70" />
      <p className="text-sm font-medium">{title}</p>
      {hint && <p className="max-w-md text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}
