import { useTranslation } from "react-i18next";
import type { components } from "@/api/schema";
import { StateBadge } from "@/features/common/StateBadge";
import { safeText } from "@/lib/text";
import { cn } from "@/lib/utils";
import { roleIcon } from "./icons";

type Node = components["schemas"]["TopologyNode"];

const CARD_W = 240;

/**
 * The card shown while the pointer is over a device: name, address, model, role, state and open problems. Placed next to
 * the device and kept inside the map box. Device strings are rendered as text only.
 */
export function MapHoverCard({ node, problems, x, y, r, box }: { node: Node; problems: number; x: number; y: number; r: number; box: { w: number; h: number } }) {
  const { t } = useTranslation();
  const gap = r + 10;
  const left = x + gap + CARD_W > box.w ? Math.max(4, x - gap - CARD_W) : x + gap;
  const top = Math.max(4, Math.min(y - 30, box.h - 170));
  const row = (label: string, value: string) => (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="truncate">{value}</dd>
    </>
  );
  return (
    <div role="tooltip" data-testid="map-hover-card" className="pointer-events-none absolute z-20 rounded-lg border bg-popover p-3 text-xs text-popover-foreground shadow-lg" style={{ left, top, width: CARD_W }}>
      <div className="mb-2 flex items-center gap-2">
        <img src={roleIcon(node.role)} alt="" className="h-7 w-8 shrink-0" />
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold">{safeText(node.name)}</div>
          <div className="truncate font-mono text-muted-foreground">{safeText(node.address)}</div>
        </div>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        {row(t("map.card.model"), safeText(node.model) || "—")}
        {row(t("map.card.role"), node.role ? t(`devices.role.${node.role}`) : "—")}
        <dt className="text-muted-foreground">{t("map.card.state")}</dt>
        <dd>
          <StateBadge state={node.state} />
        </dd>
        <dt className="text-muted-foreground">{t("map.card.problems")}</dt>
        <dd className={cn("font-medium tabular-nums", problems > 0 ? "text-destructive" : "text-muted-foreground")}>{problems}</dd>
      </dl>
    </div>
  );
}
