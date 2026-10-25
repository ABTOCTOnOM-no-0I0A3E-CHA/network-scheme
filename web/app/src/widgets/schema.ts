import { z } from "zod";

/* Pieces of the widget config schemas, mirroring internal/httpapi/dashboards_handlers.go. */

/* zod runs jitless (CSP: no eval): set by src/lib/zod-jitless.ts, imported first by main.tsx and vitest.setup.ts. */

/* eslint-disable-next-line no-control-regex */
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** Optional title: up to 100 characters (code points), no control characters. */
export const title = z
  .string()
  .refine((s) => [...s].length <= 100 && !CONTROL.test(s))
  .optional();

/** Optional row count 1..max. */
export const limit = (max: number) => z.number().int().min(1).max(max).optional();

export const severityMin = z.enum(["info", "warning", "average", "high", "disaster"]).optional();

/** A positive database id. */
export const id = z.number().int().min(1);
