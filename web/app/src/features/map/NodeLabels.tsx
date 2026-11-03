import type { Ref } from "react";
import { LABEL_W } from "./style";

export type LabelItem = { eid: string; name: string; address: string };

/**
 * Device labels as HTML under the pictograms: the name on a soft chip and the address in smaller type. The layer lives in
 * model coordinates; the map moves it with the canvas (one transform) and places each label when its device moves.
 * Strings are made safe by the caller and only ever set as text.
 */
export function NodeLabels({ items, world, register }: { items: LabelItem[]; world: Ref<HTMLDivElement>; register: (eid: string, el: HTMLDivElement | null) => void }) {
  return (
    <div ref={world} className="pointer-events-none absolute left-0 top-0 origin-top-left" data-testid="node-labels">
      {items.map((i) => (
        <div key={i.eid} ref={(el) => register(i.eid, el)} data-label={i.eid} className="absolute left-0 top-0 flex justify-center" style={{ width: LABEL_W }}>
          <div className="flex max-w-full flex-col items-center rounded-md bg-background/90 px-1.5 py-px shadow-sm ring-1 ring-border/70">
            <span className="max-w-full truncate text-[11px] font-semibold leading-4 text-foreground">{i.name}</span>
            {i.address && <span className="max-w-full truncate font-mono text-[9.5px] leading-3 text-muted-foreground">{i.address}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}
