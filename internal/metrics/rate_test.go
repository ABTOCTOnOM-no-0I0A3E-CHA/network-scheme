package metrics

import (
	"math"
	"testing"
	"time"

	"github.com/beekamai/network-scheme/internal/drivers"
)

const pollEvery = time.Minute

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func u64(v uint64) *uint64 { return &v }

func newCalc() *RateCalc {
	return NewRateCalc(func(int64) time.Duration { return pollEvery })
}

func sample(uptime time.Duration, ifs ...drivers.IfCounters) drivers.Sample {
	return drivers.Sample{SysUpTime: uptime, Interfaces: ifs}
}

func ifc(idx int, in, out uint64, hc bool) drivers.IfCounters {
	return drivers.IfCounters{Index: idx, OperUp: true, SpeedBps: 1_000_000_000,
		InOctets: in, OutOctets: out, HC: hc}
}

func TestRateNormal(t *testing.T) {
	rc := newCalc()
	a := ifc(1, 1000, 5000, true)
	a.InErrors, a.OutErrors, a.InDiscards = u64(10), u64(0), u64(7)
	if pts := rc.Rates(7, sample(time.Hour, a), t0); len(pts) != 0 {
		t.Fatalf("first sample must only set the baseline, got %+v", pts)
	}
	b := ifc(1, 1000+7_500_000, 5000+750_000, true)
	b.InErrors, b.OutErrors, b.InDiscards, b.OutDiscards = u64(70), u64(0), u64(7), u64(3)
	pts := rc.Rates(7, sample(time.Hour+pollEvery, b), t0.Add(pollEvery))
	if len(pts) != 1 {
		t.Fatalf("points = %+v", pts)
	}
	p := pts[0]
	if p.DeviceID != 7 || p.IfIndex != 1 || !p.TS.Equal(t0.Add(pollEvery)) || !p.OperUp || p.SpeedBps != 1_000_000_000 {
		t.Errorf("point header = %+v", p)
	}
	if p.InBps != 1_000_000 || p.OutBps != 100_000 || p.InBpsMax != p.InBps || p.OutBpsMax != p.OutBps {
		t.Errorf("bps = %v/%v (max %v/%v)", p.InBps, p.OutBps, p.InBpsMax, p.OutBpsMax)
	}
	if p.InErrPS == nil || *p.InErrPS != 1 || p.OutErrPS == nil || *p.OutErrPS != 0 ||
		p.InDiscPS == nil || *p.InDiscPS != 0 {
		t.Errorf("error/discard rates = %v %v %v", p.InErrPS, p.OutErrPS, p.InDiscPS)
	}
	/* OutDiscards was not read in the previous sample: NULL, never zero. */
	if p.OutDiscPS != nil {
		t.Errorf("OutDiscPS = %v, want nil", *p.OutDiscPS)
	}

	/* A counter not read in the current sample is NULL too, and a decrease is not a rate. */
	c := ifc(1, 1000+15_000_000, 5000+1_500_000, true)
	c.InErrors, c.InDiscards = u64(5), u64(8)
	pts = rc.Rates(7, sample(time.Hour+2*pollEvery, c), t0.Add(2*pollEvery))
	if len(pts) != 1 || pts[0].InErrPS != nil || pts[0].OutErrPS != nil || pts[0].OutDiscPS != nil ||
		pts[0].InDiscPS == nil || *pts[0].InDiscPS != 1.0/60 {
		t.Errorf("third point = %+v", pts)
	}
}

func TestRateCounterWrap32(t *testing.T) {
	rc := newCalc()
	const wrap = 1 << 32
	/* 100 Mbit/s interface; 600 MB in a minute = 80 Mbit/s across the wrap. */
	a := ifc(2, wrap-100_000_000, 1000, false)
	a.SpeedBps = 100_000_000
	rc.Rates(1, sample(time.Hour, a), t0)
	b := ifc(2, 500_000_000, 1000, false)
	b.SpeedBps = 100_000_000
	pts := rc.Rates(1, sample(time.Hour+pollEvery, b), t0.Add(pollEvery))
	if len(pts) != 1 || pts[0].InBps != 80_000_000 || pts[0].OutBps != 0 {
		t.Fatalf("wrapped point = %+v", pts)
	}

	/* A "wrap" that implies more than speed x 1.1 is a reset: the point is skipped. */
	c := ifc(2, 400_000_000, 1000, false)
	c.SpeedBps = 100_000_000
	if pts := rc.Rates(1, sample(time.Hour+2*pollEvery, c), t0.Add(2*pollEvery)); len(pts) != 0 {
		t.Fatalf("implausible wrap produced %+v", pts)
	}
	/* ...and becomes the new baseline. */
	d := ifc(2, 400_000_000+750_000, 1000, false)
	d.SpeedBps = 100_000_000
	if pts := rc.Rates(1, sample(time.Hour+3*pollEvery, d), t0.Add(3*pollEvery)); len(pts) != 1 || pts[0].InBps != 100_000 {
		t.Fatalf("after skipped wrap = %+v", pts)
	}

	/* Unknown speed: a wrap cannot be validated, so it is skipped. */
	rc2 := newCalc()
	e := ifc(3, wrap-10, 0, false)
	e.SpeedBps = 0
	rc2.Rates(1, sample(time.Hour, e), t0)
	f := ifc(3, 10, 0, false)
	f.SpeedBps = 0
	if pts := rc2.Rates(1, sample(time.Hour+pollEvery, f), t0.Add(pollEvery)); len(pts) != 0 {
		t.Fatalf("wrap without speed = %+v", pts)
	}
}

func TestRateRebootSkipped(t *testing.T) {
	rc := newCalc()
	rc.Rates(3, sample(10*time.Hour, ifc(1, 5_000_000, 5_000_000, true), ifc(2, 10, 10, false)), t0)
	/* Uptime went back: every interface of the device is skipped, even though counters "grew". */
	pts := rc.Rates(3, sample(30*time.Second, ifc(1, 6_000_000, 6_000_000, true), ifc(2, 20, 20, false)), t0.Add(pollEvery))
	if len(pts) != 0 {
		t.Fatalf("reboot produced %+v", pts)
	}
	/* The post-reboot sample is the new baseline. */
	pts = rc.Rates(3, sample(90*time.Second, ifc(1, 6_000_600, 6_000_000, true), ifc(2, 80, 20, false)), t0.Add(2*pollEvery))
	if len(pts) != 2 || pts[0].InBps != 80 || pts[1].InBps != 8 {
		t.Fatalf("after reboot = %+v", pts)
	}
	/* Other devices are not affected by this device's reboot. */
	rc.Rates(4, sample(time.Hour, ifc(1, 0, 0, true)), t0)
	rc.Rates(3, sample(time.Second, ifc(1, 0, 0, true)), t0.Add(3*pollEvery))
	if pts := rc.Rates(4, sample(time.Hour+pollEvery, ifc(1, 60, 0, true)), t0.Add(pollEvery)); len(pts) != 1 {
		t.Fatalf("device 4 = %+v", pts)
	}
}

func TestRateUnknownUptimeKeepsPrevious(t *testing.T) {
	rc := newCalc()
	rc.Rates(5, sample(10*time.Hour, ifc(1, 1000, 1000, true)), t0)
	/* sysUpTime missing (0): not a reboot, the rate is computed and the stored uptime is kept. */
	pts := rc.Rates(5, sample(0, ifc(1, 1600, 1000, true)), t0.Add(pollEvery))
	if len(pts) != 1 || pts[0].InBps != 80 {
		t.Fatalf("unknown uptime = %+v", pts)
	}
	/* The next real uptime is compared with the last known one (10h), so 10h+2m is no reboot... */
	if pts := rc.Rates(5, sample(10*time.Hour+2*pollEvery, ifc(1, 2200, 1000, true)), t0.Add(2*pollEvery)); len(pts) != 1 {
		t.Fatalf("after unknown uptime = %+v", pts)
	}
	/* ...while a smaller one still is. */
	if pts := rc.Rates(5, sample(time.Minute, ifc(1, 2800, 1000, true)), t0.Add(3*pollEvery)); len(pts) != 0 {
		t.Fatalf("reboot after unknown uptime = %+v", pts)
	}
	/* A first sample without uptime is a baseline like any other. */
	rc.Rates(6, sample(0, ifc(1, 0, 0, true)), t0)
	if pts := rc.Rates(6, sample(time.Hour, ifc(1, 600, 0, true)), t0.Add(pollEvery)); len(pts) != 1 {
		t.Fatalf("baseline without uptime = %+v", pts)
	}
}

func TestRateHCDecreaseSkipped(t *testing.T) {
	rc := newCalc()
	rc.Rates(1, sample(time.Hour, ifc(1, 1<<40, 1<<40, true)), t0)
	if pts := rc.Rates(1, sample(time.Hour+pollEvery, ifc(1, 1<<39, 1<<40+60, true)), t0.Add(pollEvery)); len(pts) != 0 {
		t.Fatalf("HC decrease produced %+v", pts)
	}
	if pts := rc.Rates(1, sample(time.Hour+2*pollEvery, ifc(1, 1<<39+600, 1<<40+120, true)), t0.Add(2*pollEvery)); len(pts) != 1 || pts[0].InBps != 80 {
		t.Fatalf("after HC decrease = %+v", pts)
	}
	/* Small HC values are never treated as a 32-bit wrap, even when it would look plausible. */
	rc.Rates(2, sample(time.Hour, ifc(1, 1000, 0, true)), t0)
	if pts := rc.Rates(2, sample(time.Hour+pollEvery, ifc(1, 500, 0, true)), t0.Add(pollEvery)); len(pts) != 0 {
		t.Fatalf("small HC decrease produced %+v", pts)
	}
}

func TestRateHCFlagChangeSkipped(t *testing.T) {
	rc := newCalc()
	rc.Rates(1, sample(time.Hour, ifc(1, 1000, 1000, true)), t0)
	if pts := rc.Rates(1, sample(time.Hour+pollEvery, ifc(1, 2000, 2000, false)), t0.Add(pollEvery)); len(pts) != 0 {
		t.Fatalf("HC flag change produced %+v", pts)
	}
	if pts := rc.Rates(1, sample(time.Hour+2*pollEvery, ifc(1, 2600, 2000, false)), t0.Add(2*pollEvery)); len(pts) != 1 || pts[0].InBps != 80 {
		t.Fatalf("after flag change = %+v", pts)
	}
}

func TestRateGapSkipped(t *testing.T) {
	rc := newCalc()
	rc.Rates(1, sample(time.Hour, ifc(1, 0, 0, true)), t0)
	/* Exactly three intervals is still fine. */
	if pts := rc.Rates(1, sample(time.Hour+3*pollEvery, ifc(1, 1800, 0, true)), t0.Add(3*pollEvery)); len(pts) != 1 || pts[0].InBps != 80 {
		t.Fatalf("3 intervals = %+v", pts)
	}
	at := t0.Add(3*pollEvery + 3*pollEvery + time.Second)
	if pts := rc.Rates(1, sample(2*time.Hour, ifc(1, 3600, 0, true)), at); len(pts) != 0 {
		t.Fatalf("gap produced %+v", pts)
	}
	/* A clock going backwards is not a rate either. */
	if pts := rc.Rates(1, sample(3*time.Hour, ifc(1, 7200, 0, true)), at.Add(-time.Second)); len(pts) != 0 {
		t.Fatalf("negative dt produced %+v", pts)
	}
}

func TestRateMissingInterfaceKeepsBaseline(t *testing.T) {
	rc := newCalc()
	rc.Rates(1, sample(time.Hour, ifc(1, 0, 0, true), ifc(2, 0, 0, true)), t0)
	/* if2 is missing from one poll (Sample.Incomplete) but comes back within the gap limit. */
	rc.Rates(1, sample(time.Hour+pollEvery, ifc(1, 60, 0, true)), t0.Add(pollEvery))
	pts := rc.Rates(1, sample(time.Hour+2*pollEvery, ifc(1, 120, 0, true), ifc(2, 1200, 0, true)), t0.Add(2*pollEvery))
	if len(pts) != 2 || pts[1].IfIndex != 2 || pts[1].InBps != 80 {
		t.Fatalf("points = %+v", pts)
	}
	/* Forget drops the device state. */
	rc.Forget(1)
	if pts := rc.Rates(1, sample(time.Hour+3*pollEvery, ifc(1, 180, 0, true)), t0.Add(3*pollEvery)); len(pts) != 0 {
		t.Fatalf("after Forget = %+v", pts)
	}
}

func TestRateSpeedClamped(t *testing.T) {
	rc := newCalc()
	a := ifc(1, 0, 0, true)
	a.SpeedBps = math.MaxUint64
	rc.Rates(1, sample(time.Hour, a), t0)
	pts := rc.Rates(1, sample(time.Hour+pollEvery, a), t0.Add(pollEvery))
	if len(pts) != 1 || pts[0].SpeedBps != math.MaxInt64 {
		t.Fatalf("points = %+v", pts)
	}
}
