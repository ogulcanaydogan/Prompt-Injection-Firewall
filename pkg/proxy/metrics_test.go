package proxy

import (
	"testing"

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

	assert.Equal(t, 1.0, testutil.ToFloat64(m.httpRequestsTotal.WithLabelValues("POST", "block", "blocked")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.injectionDetectionsTotal.WithLabelValues("block")))
	assert.Equal(t, 1.0, testutil.ToFloat64(m.rateLimitEventsTotal.WithLabelValues("exceeded")))
}
