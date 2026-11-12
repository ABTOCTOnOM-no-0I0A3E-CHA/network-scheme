import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { createChannel, statusMessage, ticketMessage, type Channel, type TicketMessage } from "@nms/shared/bridge";
import { loadOrigins } from "@nms/shared/origins";
import { api } from "@/lib/api";

/*
 * The executor UI (origin :8443) in an iframe. The executor origin comes from the gateway's /origins.json, never from
 * the build. sandbox="allow-scripts allow-same-origin allow-downloads" is the tightest set that works: the executor
 * page needs scripts,
 * and it needs its own origin (without allow-same-origin the frame gets an opaque origin: the executor refuses its
 * requests, whose Origin is then "null", and the CSP 'self' matches nothing). Both flags together are only unsafe
 * when the framed page shares the origin of the embedder; it never does here (a different port is a different
 * origin). allow-downloads lets the executor save an unmasked configuration it exported (4d.1: its own code, a data:
 * URL of the text it fetched; device data is rendered as text only and never runs). Everything else stays off: no
 * forms, popups, modals, top navigation, pointer lock.
 *
 * The executor asks, per request, for one fresh session ticket (`ticket_needed`); the panel gets it from
 * POST /api/executor/ticket with its own session and hands it over by postMessage to the executor origin only.
 * The panel keeps no ticket.
 */
export function ExecutorFrame({ title, className, hash, onSession, onExpand, onDialog }: {
  title: string;
  className?: string;
  /* what the executor page may preselect (device ids, a recording): its own fragment, which it only uses to prefill */
  hash?: string;
  /* the executor says whether a change session is open in it, or asks to be shown at full size */
  onSession?: (open: boolean) => void;
  onExpand?: () => void;
  /* a dialog (a confirmation) opened or closed in the executor page */
  onDialog?: (open: boolean) => void;
}) {
  const { t } = useTranslation();
  const frame = useRef<HTMLIFrameElement>(null);
  const cbs = useRef({ onSession, onExpand, onDialog });
  useEffect(() => {
    cbs.current = { onSession, onExpand, onDialog };
  }, [onSession, onExpand, onDialog]);
  const origins = useQuery({ queryKey: ["origins"], queryFn: loadOrigins, staleTime: 5 * 60_000 });
  /* the published panel origin must be the one this page runs on, else the configuration is not ours */
  const o = origins.data?.panel === window.location.origin ? origins.data : undefined;

  useEffect(() => {
    if (!o) return;
    /* one ticket request at a time: the executor never has two outstanding */
    let asking = false;
    const ch: Channel<TicketMessage> = createChannel({
      peerOrigin: o.executor,
      peer: () => frame.current?.contentWindow ?? null,
      incoming: statusMessage,
      outgoing: ticketMessage,
      onMessage(m) {
        if (m.state === "ready") {
          /* a (re)loaded page has no session and no dialog: whatever the panel knew of the old one is gone */
          cbs.current.onSession?.(false);
          return cbs.current.onDialog?.(false);
        }
        if (m.state === "session") return cbs.current.onSession?.(m.open);
        if (m.state === "dialog") return cbs.current.onDialog?.(m.open);
        if (m.state === "expand") return cbs.current.onExpand?.();
        if (m.state !== "ticket_needed" || asking) return;
        asking = true;
        const id = m.id;
        void api
          .POST("/api/executor/ticket", { params: { header: { "X-CSRF-Token": "" } } })
          .then(({ data }) => {
            /* no answer to a failed request: the executor times out and tells the user */
            if (data) ch.send({ v: 1, type: "ticket", id, ticket: data.ticket });
          })
          .catch(() => {})
          .finally(() => (asking = false));
      },
    });
    return () => ch.close();
  }, [o]);

  if (origins.isPending) return <p className="text-sm text-muted-foreground">{t("executor.frame.loading")}</p>;
  if (!o) {
    return (
      <p role="alert" className="text-sm text-destructive">
        {t("executor.frame.unavailable")}
      </p>
    );
  }
  return <iframe ref={frame} title={title} src={`${o.executor}/${hash ? `#${hash}` : ""}`} sandbox="allow-scripts allow-same-origin allow-downloads" referrerPolicy="no-referrer" allow="" className={className ?? "h-full w-full border-0"} />;
}
