package proxy

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics exposed by the proxy server.
type Metrics struct {
	registry *prometheus.Registry

	httpRequestsTotal        *prometheus.CounterVec
	scanDurationSeconds      *prometheus.HistogramVec
	injectionDetectionsTotal *prometheus.CounterVec
	detectionScore           *prometheus.HistogramVec
	rateLimitEventsTotal     *prometheus.CounterVec
}

// NewMetrics creates and registers PIF metrics in an isolated registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pif_http_requests_total",
				Help: "Total number of HTTP requests handled by PIF proxy middleware.",
			},
			[]string{"method", "action", "outcome"},
		),
		scanDurationSeconds: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "pif_scan_duration_seconds",
				Help:    "Duration of scan operations in seconds.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"outcome"},
		),
		injectionDetectionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pif_injection_detections_total",
				Help: "Total number of injection detections.",
			},
			[]string{"action"},
		),
		detectionScore: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "pif_detection_score",
				Help:    "Distribution of detection scores produced by scan requests.",
				Buckets: []float64{0, 0.1, 0.25, 0.5, 0.75, 0.9, 1},
			},
			[]string{"outcome"},
		),
		rateLimitEventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pif_rate_limit_events_total",
				Help: "Total number of rate-limit events.",
			},
			[]string{"reason"},
		),
	}

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.httpRequestsTotal,
		m.scanDurationSeconds,
		m.injectionDetectionsTotal,
		m.detectionScore,
		m.rateLimitEventsTotal,
	)

	return m
}

// Handler returns the HTTP handler that serves Prometheus metrics.
func (m *Metrics) Handler() http.Handler {
	if m == nil {
		return promhttp.Handler()
	}
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

func (m *Metrics) ObserveHTTPRequest(method, action, outcome string) {
	if m == nil {
		return
	}
	m.httpRequestsTotal.WithLabelValues(method, action, outcome).Inc()
}

func (m *Metrics) ObserveScanDuration(seconds float64, outcome string) {
	if m == nil {
		return
	}
	m.scanDurationSeconds.WithLabelValues(outcome).Observe(seconds)
}

func (m *Metrics) ObserveDetectionScore(score float64, outcome string) {
	if m == nil {
		return
	}
	m.detectionScore.WithLabelValues(outcome).Observe(score)
}

func (m *Metrics) IncInjectionDetection(action string) {
	if m == nil {
		return
	}
	m.injectionDetectionsTotal.WithLabelValues(action).Inc()
}

func (m *Metrics) IncRateLimitEvent(reason string) {
	if m == nil {
		return
	}
	m.rateLimitEventsTotal.WithLabelValues(reason).Inc()
}
