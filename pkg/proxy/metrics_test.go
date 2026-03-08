package proxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

func TestMetrics_RecordsValues(t *testing.T) {
	m := NewMetrics()

	m.ObserveHTTPRequest("POST", "block", "blocked")
	m.ObserveScanDuration(0.05, "injection")
	m.ObserveDetectionScore(0.9, "injection")
	m.IncInjectionDetection("block")
	m.IncRateLimitEvent("exceeded")
	m.IncAlertEvent("injection_blocked", "enqueued")
	m.IncAlertSinkDelivery("webhook", "sent")

	assert.Equal(t, 1.0, testutil.ToFloat64(m.httpRequestsTotal.WithLabelValues("POST", "block", "blocked")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.injectionDetectionsTotal.WithLabelValues("block")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.rateLimitEventsTotal.WithLabelValues("exceeded")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.alertEventsTotal.WithLabelValues("injection_blocked", "enqueued")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.alertSinkDeliveriesTotal.WithLabelValues("webhook", "sent")))
}

func TestMetrics_SnapshotIncludesDashboardAggregates(t *testing.T) {
	m := NewMetrics()

	m.ObserveHTTPRequest("POST", "block", "blocked")
	m.ObserveHTTPRequest("GET", "block", "forwarded")
	m.ObserveScanDuration(0.01, "clean")
	m.ObserveScanDuration(0.05, "injection")
	m.ObserveScanDuration(0.09, "injection")
	m.ObserveDetectionScore(0.2, "clean")
	m.ObserveDetectionScore(0.9, "injection")
	m.IncInjectionDetection("block")
	m.IncRateLimitEvent("exceeded")

	snap := m.Snapshot()
	assert.GreaterOrEqual(t, snap.GeneratedAt.Unix(), m.startedAt.Unix())
	assert.GreaterOrEqual(t, snap.LastUpdate.Unix(), m.startedAt.Unix())
	assert.GreaterOrEqual(t, snap.UptimeSeconds, int64(0))

	assert.Equal(t, uint64(2), snap.TotalRequests)
	assert.Equal(t, uint64(1), snap.TotalInjectionDetections)
	assert.Equal(t, uint64(1), snap.TotalRateLimitEvents)
	assert.Equal(t, uint64(1), snap.RequestsByMethod["POST"])
	assert.Equal(t, uint64(1), snap.RequestsByMethod["GET"])
	assert.Equal(t, uint64(1), snap.InjectionsByAction["block"])
	assert.Equal(t, uint64(1), snap.RateLimitByReason["exceeded"])
	assert.Greater(t, snap.ScanDurationSeconds.P95, 0.0)
	assert.Greater(t, snap.DetectionScore.P95, 0.0)
}

func TestMetrics_NilSnapshot(t *testing.T) {
	var m *Metrics
	snap := m.Snapshot()
	assert.False(t, snap.GeneratedAt.IsZero())
	assert.WithinDuration(t, snap.GeneratedAt, snap.StartedAt, time.Second)
}
