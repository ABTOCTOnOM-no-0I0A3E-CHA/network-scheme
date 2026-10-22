package eventd

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

/*
NFR-PERF-2: 5 000 events/s from 500 sources for 30 s, all stored, nothing
dropped or folded. Real UDP sockets with 500 distinct source addresses
(127.1.x.y); each source sends 10 messages per second.
*/
func TestThroughput5000PerSecondFrom500Sources(t *testing.T) {
	const (
		sources  = 500
		perSec   = 10
		duration = 30 * time.Second
	)
	if testing.Short() {
		t.Skip("30 s load test")
	}
	h := newHarness(t)
	if _, err := h.pg.Exec(context.Background(), `INSERT INTO core.device (name, address, group_id)
		SELECT 'load-'||g, ('127.1.'||(g/250)||'.'||(g%250+1))::inet, $2 FROM generate_series(0, $1 - 1) g`, sources, h.group); err != nil {
		t.Fatal(err)
	}
	h.start()

	conns := make([]*net.UDPConn, sources)
	for i := range conns {
		conns[i] = udpFrom(t, fmt.Sprintf("127.1.%d.%d", i/250, i%250+1), h.addrs.SyslogUDP)
	}
	var sent atomic.Int64
	var maxDepth atomic.Int64
	stopSample := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopSample:
				return
			case <-time.After(250 * time.Millisecond):
				if d := int64(h.depth()); d > maxDepth.Load() {
					maxDepth.Store(d)
				}
			}
		}
	}()

	start := time.Now()
	deadline := start.Add(duration)
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Go(func() {
			tick := time.NewTicker(time.Second / perSec)
			defer tick.Stop()
			time.Sleep(time.Duration(i) * time.Second / perSec / sources) /* spread the phases */
			for n := 0; time.Now().Before(deadline); n++ {
				<-tick.C
				if _, err := fmt.Fprintf(c, "<14>Oct 22 10:00:00 sw%d LINK: load message %d", i, n); err == nil {
					sent.Add(1)
				}
			}
		})
	}
	wg.Wait()
	sendTime := time.Since(start)
	drainStart := time.Now()
	total := int(sent.Load())
	eventually(t, 90*time.Second, "all events stored", func() bool { return h.count(`SELECT count(*) FROM events.syslog`) >= total })
	close(stopSample)
	h.stop()

	stored := h.count(`SELECT count(*) FROM events.syslog`)
	dropped, folded := h.stat("dropped"), h.stat("rate_limited")
	t.Logf("NFR-PERF-2: sent %d in %v (%.0f/s) from %d sources; stored %d, dropped %d, rate-limited %d; max queue depth %d; drained %v after the last send",
		total, sendTime.Round(time.Millisecond), float64(total)/sendTime.Seconds(), sources, stored, dropped, folded, maxDepth.Load(), time.Since(drainStart).Round(time.Millisecond))
	if float64(total)/sendTime.Seconds() < 4500 {
		t.Errorf("the generator only reached %.0f/s", float64(total)/sendTime.Seconds())
	}
	if dropped != 0 || folded != 0 || stored != total {
		t.Errorf("stored %d of %d, dropped %d, rate-limited %d", stored, total, dropped, folded)
	}
}
