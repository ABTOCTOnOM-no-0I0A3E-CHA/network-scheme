import { useMemo } from "react";
import ReactGridLayout, { useContainerWidth, type Layout } from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import { getWidget } from "@/widgets/registry";
import { DRAG_HANDLE, WidgetFrame, type GridItem } from "./WidgetFrame";

/** Grid of the server (internal/httpapi/dashboards_handlers.go): 12 columns. */
export const COLS = 12;
const ROW_HEIGHT = 40;
/* below this width the grid is unusable: widgets are stacked in reading order and the dashboard is not editable */
export const STACK_BELOW = 768;

type Props = {
  items: GridItem[];
  editing: boolean;
  onLayout: (layout: Layout) => void;
  onSettings: (key: string) => void;
  onRemove: (key: string) => void;
};

/** The widgets of a dashboard on react-grid-layout; dragging (by the handle) and resizing only in edit mode. */
export function DashboardGrid({ items, editing, onLayout, onSettings, onRemove }: Props) {
  const { width, containerRef } = useContainerWidth();
  const layout = useMemo<Layout>(
    () =>
      items.map((it) => {
        const s = getWidget(it.type)?.size;
        return { i: it.key, x: it.x, y: it.y, w: it.w, h: it.h, minW: s?.minW, minH: s?.minH, maxW: COLS, maxH: 48 };
      }),
    [items],
  );
  const frame = (it: GridItem) => <WidgetFrame item={it} editing={editing} onSettings={() => onSettings(it.key)} onRemove={() => onRemove(it.key)} />;
  const stacked = width > 0 && width < STACK_BELOW;

  return (
    <div ref={containerRef} data-testid="dashboard-grid">
      {stacked ? (
        <div className="grid gap-3">
          {[...items]
            .sort((a, b) => a.y - b.y || a.x - b.x)
            .map((it) => (
              <div key={it.key} style={{ height: it.h * ROW_HEIGHT }}>
                {frame(it)}
              </div>
            ))}
        </div>
      ) : (
        <ReactGridLayout
          width={Math.max(width, STACK_BELOW)}
          layout={layout}
          gridConfig={{ cols: COLS, rowHeight: ROW_HEIGHT, margin: [12, 12], containerPadding: [0, 0], maxRows: 1000 }}
          dragConfig={{ enabled: editing, handle: `.${DRAG_HANDLE}`, bounded: true }}
          resizeConfig={{ enabled: editing }}
          onLayoutChange={(l) => editing && onLayout(l)}
        >
          {items.map((it) => (
            <div key={it.key}>{frame(it)}</div>
          ))}
        </ReactGridLayout>
      )}
    </div>
  );
}
