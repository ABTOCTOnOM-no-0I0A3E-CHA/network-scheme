/* first: zod must be jitless before any module builds a schema */
import "@nms/shared/zod-jitless";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./i18n";
import "./index.css";
import { App } from "./App";
import { startBridge } from "./bootstrap";
import { BridgeError } from "./bridge";
import { createPoster } from "./client";

/* No panel theme crosses origins: follow the OS preference (applied by the bundled script; the CSP forbids an inline one). */
document.documentElement.classList.toggle("dark", window.matchMedia("(prefers-color-scheme: dark)").matches);

const bridge = startBridge();
/* every request asks the panel for its own ticket through the bridge; none without a bridge */
const poster = createPoster({
  async requestTicket() {
    const b = await bridge;
    if (!b) throw new BridgeError("no_panel");
    return b.requestTicket();
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App poster={poster} />
  </StrictMode>,
);
