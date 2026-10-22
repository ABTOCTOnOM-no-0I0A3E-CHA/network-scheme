// Package metricsrc adapts a metrics.MetricStore to the trigger engine's SampleSource.
package metricsrc

import (
	"context"
	"time"

	"github.com/beekamai/network-scheme/internal/metrics"
	"github.com/beekamai/network-scheme/internal/triggers"
)

// Source is a triggers.SampleSource over a metric store.
type Source struct{ Store metrics.MetricStore }

var _ triggers.SampleSource = Source{}

// SysSince implements triggers.SampleSource.
func (s Source) SysSince(ctx context.Context, from, to time.Time, limit int) ([]triggers.SysSample, error) {
	pts, err := s.Store.SysSince(ctx, from, to, limit)
	if err != nil {
		return nil, err
	}
	out := make([]triggers.SysSample, len(pts))
	for i, p := range pts {
		out[i] = triggers.SysSample{DeviceID: p.DeviceID, TS: p.TS, CPUPct: p.CPUPct, MemUsedPct: p.MemUsedPct, TempC: p.TempC}
	}
	return out, nil
}

// IfSince implements triggers.SampleSource.
func (s Source) IfSince(ctx context.Context, from, to time.Time, f triggers.IfFilter, limit int) ([]triggers.IfSample, error) {
	pts, err := s.Store.IfSince(ctx, from, to, metrics.IfFilter{DeviceIDs: f.DeviceIDs, DownOrDeviceIDs: f.DownOrDeviceIDs}, limit)
	if err != nil {
		return nil, err
	}
	out := make([]triggers.IfSample, len(pts))
	for i, p := range pts {
		out[i] = triggers.IfSample{DeviceID: p.DeviceID, IfIndex: p.IfIndex, TS: p.TS, InBps: p.InBps, OutBps: p.OutBps,
			InErrPS: p.InErrPS, OutErrPS: p.OutErrPS, OperUp: p.OperUp, SpeedBps: p.SpeedBps}
	}
	return out, nil
}

// IfUpSince implements triggers.SampleSource.
func (s Source) IfUpSince(ctx context.Context, from, to time.Time) ([]triggers.IfKey, error) {
	pairs, err := s.Store.IfUpSince(ctx, from, to)
	if err != nil {
		return nil, err
	}
	out := make([]triggers.IfKey, len(pairs))
	for i, p := range pairs {
		out[i] = triggers.IfKey{DeviceID: p[0], IfIndex: int(p[1])}
	}
	return out, nil
}
