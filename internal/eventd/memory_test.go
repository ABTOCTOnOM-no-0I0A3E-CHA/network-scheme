package eventd

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

/*
A stalled consumer (the handler never returns, as with a blocked writer behind
a full queue) cannot make the UDP hand-over hold more than udpHandBytes: the
socket is flooded with maximum-size datagrams and the heap must stay near the
bound, the rest being counted as dropped.
*/
func TestUDPHandOverBoundsMemory(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
		pkt  int
	}{
		{"trap", maxTrapPacket, 60_000},
		{"syslog", 8<<10 + 1, 8 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			h.device("127.0.0.1")
			srv := newServer(h.cfg, Deps{Pool: h.pool, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Enqueuer: noEnq{}, Priv: h.priv, Pub: h.pub})
			if err := srv.reloadAll(context.Background(), true, false); err != nil {
				t.Fatal(err)
			}
			c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			gate := make(chan struct{})
			var rx sync.WaitGroup
			srv.pumpUDP(&rx, c, tc.size, func(_ netip.Addr, _ netip.AddrPort, _ []byte) { <-gate })
			t.Cleanup(func() { close(gate); _ = c.Close(); rx.Wait() })

			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			out, err := net.DialUDP("udp", nil, c.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close() //nolint:errcheck // test socket
			payload := make([]byte, tc.pkt)
			const sent = 4000 /* 4000 x 60 KB = 240 MB offered */
			for range sent {
				if _, err := out.Write(payload); err != nil {
					t.Fatal(err)
				}
				time.Sleep(20 * time.Microsecond)
			}
			time.Sleep(500 * time.Millisecond)
			runtime.GC()
			runtime.ReadMemStats(&after)
			grown := int64(after.HeapAlloc) - int64(before.HeapAlloc)
			if limit := int64(udpHandBytes) + udpHandBytes/4; grown > limit {
				t.Errorf("heap grew by %d bytes, hand-over bound %d", grown, limit)
			}
			if srv.st.received.Load() == 0 {
				t.Fatal("nothing was received")
			}
			t.Logf("received %d, dropped %d, heap growth %d KiB", srv.st.received.Load(), srv.st.dropped.Load(), grown>>10)
		})
	}
}
