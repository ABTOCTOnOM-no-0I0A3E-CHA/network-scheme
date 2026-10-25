/* first: zod must be jitless before any module builds a schema */
import "@/lib/zod-jitless";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import "./i18n";
import "./index.css";
import { applyTheme } from "@/lib/theme";
import { queryClient } from "@/lib/query";
import { router } from "./router";

/* The theme class is applied by the bundled script (CSP forbids an inline anti-flash script). */
applyTheme();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
