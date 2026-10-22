package metrics

import (
	"math"
	"sync"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers"
)

/*
RateCalc turns raw interface counters into rates from two adjacent samples of
the same device. It keeps the previous sample per (device, ifIndex) and is safe
for concurrent use.

A point is skipped (no rate, the new sample becomes the baseline) when:
  - the device's SysUpTime went back (reboot): every interface of the device;
    a zero SysUpTime is unknown and never counts as a reboot;
  - more than three poll intervals passed since the baseline, or no time passed;
  - the interface switched between 32-bit and 64-bit counters;
  - a 64-bit octet counter decreased;
  - a 32-bit octet counter decreased and the wrap-around rate (modulo 2^32) is
    not below the interface speed x 1.1 or the speed is unknown.

Error and discard rates are nil when either sample lacks the counter or the
counter decreased (a cleared counter is far more likely than a 32-bit wrap).
*/
type RateCalc struct {
	mu       sync.Mutex
	interval func(deviceID int64) time.Duration
	devs     map[int64]*devState
}

type devState struct {
	uptime time.Duration
	ifs    map[int]ifPrev
}

type ifPrev struct {
	at time.Time
	c  drivers.IfCounters
}

/*
NewRateCalc returns a calculator; interval reports the device's current poll
interval (a non-positive interval makes every point a gap).
*/
func NewRateCalc(interval func(deviceID int64) time.Duration) *RateCalc {
	return &RateCalc{interval: interval, devs: map[int64]*devState{}}
}

/* Rates returns one point per interface that has a usable baseline, in sample order. */
func (r *RateCalc) Rates(deviceID int64, s drivers.Sample, at time.Time) []IfPoint {
	r.mu.Lock()
	defer r.mu.Unlock()

	maxGap := 3 * r.interval(deviceID)
	prev := r.devs[deviceID]
	/* A zero sysUpTime means "not read": no reboot check, the last known uptime is kept. */
	uptime := s.SysUpTime
	if uptime == 0 && prev != nil {
		uptime = prev.uptime
	}
	reboot := prev != nil && s.SysUpTime != 0 && s.SysUpTime < prev.uptime
	next := &devState{uptime: uptime, ifs: make(map[int]ifPrev, len(s.Interfaces))}

	var out []IfPoint
	for _, c := range s.Interfaces {
		next.ifs[c.Index] = ifPrev{at: at, c: c}
		if prev == nil || reboot {
			continue
		}
		if p, ok := prev.ifs[c.Index]; ok {
			if pt, ok := ifRate(p, c, at, maxGap); ok {
				pt.DeviceID = deviceID
				out = append(out, pt)
			}
		}
	}
	/* An interface missing from one poll keeps its baseline while it is still usable. */
	if prev != nil && !reboot {
		for idx, p := range prev.ifs {
			if _, ok := next.ifs[idx]; !ok && at.Sub(p.at) <= maxGap {
				next.ifs[idx] = p
			}
		}
	}
	r.devs[deviceID] = next
	return out
}

/* Forget drops the state of a device (deleted or no longer polled). */
func (r *RateCalc) Forget(deviceID int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.devs, deviceID)
}

func ifRate(p ifPrev, c drivers.IfCounters, at time.Time, maxGap time.Duration) (IfPoint, bool) {
	dt := at.Sub(p.at)
	if dt <= 0 || dt > maxGap || c.HC != p.c.HC {
		return IfPoint{}, false
	}
	sec := dt.Seconds()
	in, ok := octetRate(p.c.InOctets, c.InOctets, c.HC, c.SpeedBps, sec)
	if !ok {
		return IfPoint{}, false
	}
	outBps, ok := octetRate(p.c.OutOctets, c.OutOctets, c.HC, c.SpeedBps, sec)
	if !ok {
		return IfPoint{}, false
	}
	speed := int64(math.MaxInt64)
	if c.SpeedBps < math.MaxInt64 {
		speed = int64(c.SpeedBps)
	}
	return IfPoint{
		IfIndex: c.Index, TS: at,
		InBps: in, OutBps: outBps, InBpsMax: in, OutBpsMax: outBps,
		InErrPS:   perSec(p.c.InErrors, c.InErrors, sec),
		OutErrPS:  perSec(p.c.OutErrors, c.OutErrors, sec),
		InDiscPS:  perSec(p.c.InDiscards, c.InDiscards, sec),
		OutDiscPS: perSec(p.c.OutDiscards, c.OutDiscards, sec),
		OperUp:    c.OperUp, SpeedBps: speed,
	}, true
}

/* octetRate returns bits per second between two octet counter readings. */
func octetRate(prev, cur uint64, hc bool, speedBps uint64, sec float64) (float64, bool) {
	if cur >= prev {
		return float64(cur-prev) * 8 / sec, true
	}
	if hc || prev > math.MaxUint32 || cur > math.MaxUint32 {
		return 0, false
	}
	bps := float64(cur+(1<<32)-prev) * 8 / sec
	if speedBps == 0 || bps >= float64(speedBps)*1.1 {
		return 0, false
	}
	return bps, true
}

func perSec(prev, cur *uint64, sec float64) *float64 {
	if prev == nil || cur == nil || *cur < *prev {
		return nil
	}
	v := float64(*cur-*prev) / sec
	return &v
}
