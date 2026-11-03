import { useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { createChannel, statusMessage, ticketMessage, type Channel, type TicketMessage } from "@nms/shared/bridge";
import { loadOrigins } from "@nms/shared/origins";
import { api } from "@/lib/api";

/*
 * The executor UI (origin :8443) in an iframe. The executor origin comes from the gateway's /origins.json, never from
 * the build. sandbox="allow-scripts allow-same-origin" is the tightest set that works: the executor page needs scripts,
 * and it needs its own origin (without allow-same-origin the frame gets an opaque origin: the executor refuses its
 * requests, whose Origin is then "null", and the CSP 'self' matches nothing). Both flags together are only unsafe
 * when the framed page shares the origin of the embedder; it never does here (a different port is a different
 * origin). Everything else stays off: no forms, popups, modals, downloads, top navigation, pointer lock.
 *
 * The executor asks, per request, for one fresh session ticket (`ticket_needed`); the panel gets it from
 * POST /api/executor/ticket with its own session and hands it over by postMessage to the executor origin only.
 * The panel keeps no ticket.
 */
export function ExecutorFrame({ title, className }: { title: string; className?: string }) {
  const { t } = useTranslation();
  const frame = useRef<HTMLIFrameElement>(null);
  const origins = useQuery({ queryKey: ["origins"], queryFn: loadOrigins, staleTime: 5 * 60_000 });
  /* the published panel origin must be the one this page runs on, else the configuration is not ours */
  const o = origins.data?.panel === window.location.origin ? origins.data : undefined;

  useEffect(() => {
    if (!o) return;
    const ch: Channel<TicketMessage> = createChannel({
      peerOrigin: o.executor,
      peer: () => frame.current?.contentWindow ?? null,
      incoming: statusMessage,
      outgoing: ticketMessage,
      onMessage(m) {
        if (m.state !== "ticket_needed") return;
        const id = m.id;
        void api.POST("/api/executor/ticket", { params: { header: { "X-CSRF-Token": "" } } }).then(({ data }) => {
          /* no answer to a failed request: the executor times out and tells the user */
          if (data) ch.send({ v: 1, type: "ticket", id, ticket: data.ticket });
        });
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
  return <iframe ref={frame} title={title} src={`${o.executor}/`} sandbox="allow-scripts allow-same-origin" referrerPolicy="no-referrer" allow="" className={className ?? "h-full w-full border-0"} />;
}
