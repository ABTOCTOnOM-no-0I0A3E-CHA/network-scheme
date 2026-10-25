import type { ReactNode } from "react";
import type { z } from "zod";

/**
 * One editable setting of a widget, rendered by the generic settings dialog. `label` is an i18n key;
 * `device` and `view` pick a visible device or a map view by id.
 */
export type WidgetField =
  | { key: string; kind: "text"; label: string; maxLength: number }
  | { key: string; kind: "number"; label: string; min: number; max: number }
  | { key: string; kind: "select"; label: string; options: { value: string; label: string }[] }
  | { key: string; kind: "device"; label: string }
  | { key: string; kind: "view"; label: string };

/** What a widget loads for a config: a TanStack query (it must call scoped panel endpoints only). */
export type WidgetDataQuery<D> = { queryKey: readonly unknown[]; queryFn: () => Promise<D>; refetchInterval?: number };

/**
 * The widget contract (FR-DASH-4). `type` is the stored type: the server accepts a closed set of types and checks every
 * config against its own copy of the schema, so `configSchema` must accept exactly what the server accepts. `render`
 * gets the result of `dataQuery` (undefined without one: the widget then loads its own data) and must show device data
 * as text only.
 */
export type WidgetDef<C, D = undefined> = {
  type: string;
  /** i18n keys of the catalog entry and of the default title. */
  title: string;
  description: string;
  configSchema: z.ZodType<C>;
  /**
   * Config of a newly added widget. It passes `configSchema` unless the widget needs a choice first (a device): such a
   * widget shows a hint to open its settings, and the dashboard cannot be saved until it is configured.
   */
  defaultConfig: Partial<C>;
  /** Size on the 12-column grid when added; min* bound resizing. */
  size: { w: number; h: number; minW?: number; minH?: number };
  fields?: WidgetField[];
  /** The widget draws its own header (the frame shows only the edit controls). */
  frameless?: boolean;
  dataQuery?: (config: C) => WidgetDataQuery<D>;
  render: (data: D, config: C) => ReactNode;
};

/** A registered widget with its types erased (the registry checks configs with the widget's own schema). */
export type AnyWidget = WidgetDef<Record<string, unknown>, unknown>;

const registry = new Map<string, AnyWidget>();

/** Adds a widget to the catalog; a type registered twice is a programming error. */
export function registerWidget<C, D>(def: WidgetDef<C, D>): void {
  if (registry.has(def.type)) throw new Error(`widget ${def.type} is already registered`);
  registry.set(def.type, def as unknown as AnyWidget);
}

/** The widget of a stored type, if this build knows it. */
export function getWidget(type: string): AnyWidget | undefined {
  return registry.get(type);
}

/** Every registered widget in registration order (the catalog). */
export function listWidgets(): AnyWidget[] {
  return [...registry.values()];
}

/** Test hook: removes a widget registered by a test. */
export function unregisterWidget(type: string): void {
  registry.delete(type);
}

/** Optional title of every widget config: at most 100 characters, no control characters (as the server). */
export function titleField(): WidgetField {
  return { key: "title", kind: "text", label: "widgets.field.title", maxLength: 100 };
}
