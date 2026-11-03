import path from "node:path";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
      "@nms/shared": path.resolve(import.meta.dirname, "../shared/src"),
    },
  },
  build: {
    /* CSP forbids inline scripts/styles and data: scripts; keep every asset a separate file under /assets/ */
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.test.{ts,tsx}", "../shared/src/**/*.test.ts"],
    testTimeout: 60000,
  },
});
