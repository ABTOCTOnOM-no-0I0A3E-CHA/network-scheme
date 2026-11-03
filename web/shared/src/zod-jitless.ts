import { z } from "zod";

/*
 * The CSP forbids eval. Without jitless, the first object schema makes zod probe `new Function`, which the browser reports
 * as a securitypolicyviolation even though zod catches the error. main.tsx imports this module first (and vitest.setup.ts
 * in tests), so it runs before any module builds a schema, whatever the import order elsewhere.
 */
z.config({ jitless: true });
