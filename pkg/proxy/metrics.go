package proxy

import (
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const dashboardSampleLimit = 1024

// Metrics holds all Prometheus metrics exposed by the proxy server.
type Metrics struct {
	registry *prometheus.Registry

	httpRequestsTotal        *prometheus.CounterVec
	scanDurationSeconds      *prometheus.HistogramVec
	injectionDetectionsTotal *prometheus.CounterVec
	detectionScore           *prometheus.HistogramVec
	rateLimitEventsTotal     *prometheus.CounterVec
	alertEventsTotal         *prometheus.CounterVec
	alertSinkDeliveriesTotal *prometheus.CounterVec

	mu sync.RWMutex

	startedAt  time.Time
	lastUpdate time.Time

	totalRequests            uint64
	totalInjectionDetections uint64
	totalRateLimitEvents     uint64

	requestsByMethod    map[string]uint64
	requestsByAction    map[string]uint64
	requestsByOutcome   map[string]uint64
	injectionsByAction  map[string]uint64
	rateLimitByReason   map[string]uint64
	scanDurationSamples []float64
	detectionScoreSlice []float64
}

// MetricQuantiles holds p50/p95/p99 values for a sample series.
type MetricQuantiles struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
}

// MetricsSnapshot is a JSON-friendly projection used by dashboard endpoints.
type MetricsSnapshot struct {
	GeneratedAt time.Time `json:"generated_at"`
	StartedAt   time.Time `json:"started_at"`
	LastUpdate  time.Time `json:"last_update"`

	UptimeSeconds int64 `json:"uptime_seconds"`

	TotalRequests            uint64 `json:"total_requests"`
	TotalInjectionDetections uint64 `json:"total_injection_detections"`
	TotalRateLimitEvents     uint64 `json:"total_rate_limit_events"`

	RequestsByMethod   map[string]uint64 `json:"requests_by_method"`
	RequestsByAction   map[string]uint64 `json:"requests_by_action"`
	RequestsByOutcome  map[string]uint64 `json:"requests_by_outcome"`
	InjectionsByAction map[string]uint64 `json:"injections_by_action"`
	RateLimitByReason  map[string]uint64 `json:"rate_limit_by_reason"`

	ScanDurationSeconds MetricQuantiles `json:"scan_duration_seconds"`
	DetectionScore      MetricQuantiles `json:"detection_score"`
}

// NewMetrics creates and registers PIF metrics in an isolated registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()
	now := time.Now().UTC()

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
		alertEventsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pif_alert_events_total",
				Help: "Total number of alert events enqueued or dropped by type and status.",
			},
			[]string{"event_type", "status"},
		),
		alertSinkDeliveriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pif_alert_sink_deliveries_total",
				Help: "Total number of alert sink delivery outcomes by sink and status.",
			},
			[]string{"sink", "status"},
		),
		startedAt:          now,
		lastUpdate:         now,
		requestsByMethod:   make(map[string]uint64),
		requestsByAction:   make(map[string]uint64),
		requestsByOutcome:  make(map[string]uint64),
		injectionsByAction: make(map[string]uint64),
		rateLimitByReason:  make(map[string]uint64),
	}

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.httpRequestsTotal,
		m.scanDurationSeconds,
		m.injectionDetectionsTotal,
		m.detectionScore,
		m.rateLimitEventsTotal,
		m.alertEventsTotal,
		m.alertSinkDeliveriesTotal,
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
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUpdate = time.Now().UTC()
	m.totalRequests++
	m.requestsByMethod[method]++
	m.requestsByAction[action]++
	m.requestsByOutcome[outcome]++
}

func (m *Metrics) ObserveScanDuration(seconds float64, outcome string) {
	if m == nil {
		return
	}
	m.scanDurationSeconds.WithLabelValues(outcome).Observe(seconds)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUpdate = time.Now().UTC()
	m.scanDurationSamples = appendSample(m.scanDurationSamples, seconds, dashboardSampleLimit)
}

func (m *Metrics) ObserveDetectionScore(score float64, outcome string) {
	if m == nil {
		return
	}
	m.detectionScore.WithLabelValues(outcome).Observe(score)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUpdate = time.Now().UTC()
	m.detectionScoreSlice = appendSample(m.detectionScoreSlice, score, dashboardSampleLimit)
}

func (m *Metrics) IncInjectionDetection(action string) {
	if m == nil {
		return
	}
	m.injectionDetectionsTotal.WithLabelValues(action).Inc()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUpdate = time.Now().UTC()
	m.totalInjectionDetections++
	m.injectionsByAction[action]++
}

func (m *Metrics) IncRateLimitEvent(reason string) {
	if m == nil {
		return
	}
	m.rateLimitEventsTotal.WithLabelValues(reason).Inc()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUpdate = time.Now().UTC()
	m.totalRateLimitEvents++
	m.rateLimitByReason[reason]++
}

func (m *Metrics) IncAlertEvent(eventType, status string) {
	if m == nil {
		return
	}
	m.alertEventsTotal.WithLabelValues(eventType, status).Inc()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUpdate = time.Now().UTC()
}

func (m *Metrics) IncAlertSinkDelivery(sink, status string) {
	if m == nil {
		return
	}
	m.alertSinkDeliveriesTotal.WithLabelValues(sink, status).Inc()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastUpdate = time.Now().UTC()
}

// Snapshot returns a thread-safe metrics snapshot for dashboard JSON endpoints.
func (m *Metrics) Snapshot() MetricsSnapshot {
	if m == nil {
		now := time.Now().UTC()
		return MetricsSnapshot{
			GeneratedAt: now,
			StartedAt:   now,
			LastUpdate:  now,
		}
	}

	m.mu.RLock()
	startedAt := m.startedAt
	lastUpdate := m.lastUpdate
	totalRequests := m.totalRequests
	totalInjectionDetections := m.totalInjectionDetections
	totalRateLimitEvents := m.totalRateLimitEvents
	requestsByMethod := copyCounterMap(m.requestsByMethod)
	requestsByAction := copyCounterMap(m.requestsByAction)
	requestsByOutcome := copyCounterMap(m.requestsByOutcome)
	injectionsByAction := copyCounterMap(m.injectionsByAction)
	rateLimitByReason := copyCounterMap(m.rateLimitByReason)
	scanSamples := append([]float64(nil), m.scanDurationSamples...)
	scoreSamples := append([]float64(nil), m.detectionScoreSlice...)
	m.mu.RUnlock()

	now := time.Now().UTC()
	return MetricsSnapshot{
		GeneratedAt:              now,
		StartedAt:                startedAt,
		LastUpdate:               lastUpdate,
		UptimeSeconds:            int64(now.Sub(startedAt).Seconds()),
		TotalRequests:            totalRequests,
		TotalInjectionDetections: totalInjectionDetections,
		TotalRateLimitEvents:     totalRateLimitEvents,
		RequestsByMethod:         requestsByMethod,
		RequestsByAction:         requestsByAction,
		RequestsByOutcome:        requestsByOutcome,
		InjectionsByAction:       injectionsByAction,
		RateLimitByReason:        rateLimitByReason,
		ScanDurationSeconds:      computeQuantiles(scanSamples),
		DetectionScore:           computeQuantiles(scoreSamples),
	}
}

func appendSample(samples []float64, value float64, limit int) []float64 {
	if limit <= 0 {
		return samples
	}
	if len(samples) < limit {
		return append(samples, value)
	}
	copy(samples, samples[1:])
	samples[len(samples)-1] = value
	return samples
}

func copyCounterMap(src map[string]uint64) map[string]uint64 {
	dst := make(map[string]uint64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func computeQuantiles(samples []float64) MetricQuantiles {
	if len(samples) == 0 {
		return MetricQuantiles{}
	}
	values := append([]float64(nil), samples...)
	sort.Float64s(values)
	return MetricQuantiles{
		P50: quantile(values, 0.50),
		P95: quantile(values, 0.95),
		P99: quantile(values, 0.99),
	}
}

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := int((float64(len(sorted)-1))*q + 0.5)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
