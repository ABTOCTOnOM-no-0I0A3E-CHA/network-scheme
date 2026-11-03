/* first: zod must be jitless before any module builds a schema */
import "@nms/shared/zod-jitless";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./i18n";
import "./index.css";
import { App } from "./App";
import { startBridge } from "./bootstrap";

/* No panel theme crosses origins: follow the OS preference (applied by the bundled script; the CSP forbids an inline one). */
document.documentElement.classList.toggle("dark", window.matchMedia("(prefers-color-scheme: dark)").matches);

void startBridge();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
