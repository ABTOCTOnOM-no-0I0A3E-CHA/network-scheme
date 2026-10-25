import { z } from "zod";

/* Pieces of the widget config schemas, mirroring internal/httpapi/dashboards_handlers.go. */

/*
 * The CSP forbids eval. Without jitless, the first object schema makes zod probe `new Function`, which the browser reports
 * as a securitypolicyviolation even though zod catches the error. Every widget imports this module before building its schema.
 */
z.config({ jitless: true });

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
