import { z } from "zod";
import { MiniMap } from "./MiniMap";
import { titleField, type WidgetDef } from "./registry";
import { id, title } from "./schema";

const schema = z.strictObject({ title, view_id: id.optional() });
type Config = z.infer<typeof schema>;

/** The compact network map of a view (the first one by default); it loads its own data and draws its own header. */
export const miniMapWidget: WidgetDef<Config> = {
  type: "mini_map",
  title: "widgets.miniMap.title",
  description: "widgets.miniMap.description",
  configSchema: schema,
  defaultConfig: {},
  size: { w: 6, h: 8, minW: 3, minH: 5 },
  fields: [titleField(), { key: "view_id", kind: "view", label: "widgets.field.view" }],
  frameless: true,
  render: (_data, c) => <MiniMap viewId={c.view_id} fill className="h-full" />,
};
