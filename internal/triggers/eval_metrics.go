package triggers

import (
	"fmt"
)

/* isInterfaceMetric reports whether the metric is read per interface. */
func (m *MetricThreshold) isInterfaceMetric() bool {
	switch m.Metric {
	case MetricIfUtilIn, MetricIfUtilOut, MetricIfErrors:
		return true
	}
	return false
}

/* holds compares v with the threshold (Validate guarantees Value is set). */
func (m *MetricThreshold) holds(v float64) bool {
	if m.Op == OpGreater {
		return v > *m.Value
	}
	return v < *m.Value
}

func (m *MetricThreshold) describe(v float64) string {
	return fmt.Sprintf("%s %.1f (%s %g)", m.Metric, v, m.Op, *m.Value)
}

/* ifMetricValue derives an interface metric from a sample; ok is false when the sample cannot tell. */
func ifMetricValue(metric string, p IfSample) (v float64, ok bool) {
	switch metric {
	case MetricIfUtilIn, MetricIfUtilOut:
		if p.SpeedBps <= 0 {
			return 0, false
		}
		bps := p.InBps
		if metric == MetricIfUtilOut {
			bps = p.OutBps
		}
		return min(bps/float64(p.SpeedBps)*100, 100), true
	case MetricIfErrors:
		if p.InErrPS == nil && p.OutErrPS == nil {
			return 0, false
		}
		for _, e := range []*float64{p.InErrPS, p.OutErrPS} {
			if e != nil {
				v += *e
			}
		}
		return v, true
	}
	return 0, false
}

/* sysSample applies one system sample to one metric trigger of its device. */
func (e *Engine) sysSample(a *actions, t *effTrigger, p SysSample) {
	m := t.params.(*MetricThreshold)
	var val *float64
	switch m.Metric {
	case MetricCPU:
		val = p.CPUPct
	case MetricMem:
		val = p.MemUsedPct
	case MetricTemp:
		val = p.TempC
	}
	if val == nil {
		return /* not reported: no evidence either way */
	}
	e.sample(a, t, p.DeviceID, "", p.TS, m.holds(*val), m.describe(*val), true)
}
