import { loadOrigins } from "@nms/shared/origins";
import { createExecutorBridge, type ExecutorBridge } from "./bridge";

/*
 * Starts the postMessage bridge to the panel from the origins the gateway publishes. Nothing starts unless this page
 * really is served from the published executor origin: a copy of the bundle elsewhere gets no bridge.
 */
export async function startBridge(self: Window = window): Promise<ExecutorBridge | null> {
  try {
    const o = await loadOrigins();
    if (o.executor !== self.location.origin) return null;
    const bridge = createExecutorBridge({ panelOrigin: o.panel, self });
    bridge.ready();
    return bridge;
  } catch {
    return null;
  }
}
