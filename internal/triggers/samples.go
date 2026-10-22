package triggers

import (
	"context"
	"time"
)

/*
The engine reads samples through this narrow interface instead of importing
internal/metrics: that package (poller-side rate calculation) depends on the
device drivers, and the engine must not be able to reach anything that talks
to devices. internal/triggers/metricsrc adapts a metrics.MetricStore.
*/

/* Paging and range sizes (variables only so that tests can shrink them). */
var (
	samplePage  = 200_000 /* rows per sample read */
	samplePages = 10      /* pages per round */
	seqRange    = 200_000 /* event rows per range */
	maxRanges   = 4       /* ranges per stream and cycle */
)

// IfSample is one raw interface sample.
type IfSample struct {
	DeviceID          int64
	IfIndex           int
	TS                time.Time
	InBps, OutBps     float64
	InErrPS, OutErrPS *float64
	OperUp            bool
	SpeedBps          int64
}

// SysSample is one raw system sample; nil means not reported.
type SysSample struct {
	DeviceID                  int64
	TS                        time.Time
	CPUPct, MemUsedPct, TempC *float64
}

/*
IfFilter narrows IfSince. DeviceIDs restricts the result to those devices;
when DownOrDeviceIDs is non-nil, only samples with oper_up = false are
returned, plus every sample of the DownOrDeviceIDs devices.
*/
type IfFilter struct {
	DeviceIDs       []int64
	DownOrDeviceIDs []int64
}

// IfKey names an interface.
type IfKey struct {
	DeviceID int64
	IfIndex  int
	FirstUp  time.Time /* earliest oper-up sample in the window */
}

// SampleSource reads the samples written in (from, to], oldest first, at most limit.
type SampleSource interface {
	SysSince(ctx context.Context, from, to time.Time, limit int) ([]SysSample, error)
	IfSince(ctx context.Context, from, to time.Time, f IfFilter, limit int) ([]IfSample, error)
	/* IfUpSince lists the interfaces that reported oper-up in (from, to] with the time of the first such sample. */
	IfUpSince(ctx context.Context, from, to time.Time) ([]IfKey, error)
}
