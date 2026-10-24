import path from "node:path";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(import.meta.dirname, "src"),
      /* CSP: the real package injects a runtime <style>; see the stub for details */
      "react-remove-scroll": path.resolve(import.meta.dirname, "src/lib/remove-scroll-noop.tsx"),
    },
  },
  build: {
    /* CSP forbids inline scripts/styles and data: scripts; keep every asset a separate file */
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
  },
  /* the layout worker is a separate bundled file under /assets/ (CSP: script-src covers workers) */
  worker: { format: "es" },
  server: { proxy: { "/api": "http://localhost:8080" } },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.test.{ts,tsx}", "scripts/**/*.test.ts"],
    testTimeout: 60000,
  },
});
