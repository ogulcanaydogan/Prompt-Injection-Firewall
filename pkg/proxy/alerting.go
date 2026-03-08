package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultAlertQueueSize      = 1024
	defaultAlertTimeout        = 3 * time.Second
	defaultAlertMaxRetries     = 3
	defaultAlertBackoffInitial = 200 * time.Millisecond
	defaultPagerDutyEventsURL  = "https://events.pagerduty.com/v2/enqueue"
	maxAlertBackoff            = 5 * time.Second
)

// AlertEventType identifies the emitted alert category.
type AlertEventType string

const (
	AlertEventInjectionBlocked AlertEventType = "injection_blocked"
	AlertEventRateLimit        AlertEventType = "rate_limit_exceeded"
	AlertEventScanError        AlertEventType = "scan_error"
)

// AlertFinding is a compact representation of a detection finding.
type AlertFinding struct {
	RuleID   string `json:"rule_id"`
	Category string `json:"category"`
	Severity int    `json:"severity"`
	Match    string `json:"match,omitempty"`
}

// AlertEvent is the canonical payload sent to outbound alert sinks.
type AlertEvent struct {
	EventID        string         `json:"event_id"`
	Timestamp      time.Time      `json:"timestamp"`
	EventType      AlertEventType `json:"event_type"`
	Action         string         `json:"action"`
	ClientKey      string         `json:"client_key"`
	Method         string         `json:"method"`
	Path           string         `json:"path"`
	Target         string         `json:"target"`
	Score          float64        `json:"score"`
	Threshold      float64        `json:"threshold"`
	FindingsCount  int            `json:"findings_count"`
	Reason         string         `json:"reason"`
	SampleFindings []AlertFinding `json:"sample_findings,omitempty"`
	AggregateCount int            `json:"aggregate_count"`
}

// AlertPublisher accepts alert events and publishes asynchronously.
type AlertPublisher interface {
	Publish(event AlertEvent)
}

// AlertPublisherWithClose extends publisher with shutdown behavior.
type AlertPublisherWithClose interface {
	AlertPublisher
	Close()
}

type noopAlertPublisher struct{}

func NewNoopAlertPublisher() AlertPublisherWithClose {
	return &noopAlertPublisher{}
}

func (n *noopAlertPublisher) Publish(event AlertEvent) {}

func (n *noopAlertPublisher) Close() {}

type alertDispatcher struct {
	logger  *slog.Logger
	metrics *Metrics
	queue   chan AlertEvent
	sinks   []alertSink

	closeOnce sync.Once
	wg        sync.WaitGroup
}

// BuildAlertPublisher creates a dispatcher-backed publisher when enabled,
// otherwise returns a no-op publisher.
func BuildAlertPublisher(opts AlertingOptions, logger *slog.Logger, metrics *Metrics) AlertPublisherWithClose {
	if !opts.Enabled {
		return NewNoopAlertPublisher()
	}
	logger = ensureLogger(logger)

	d := &alertDispatcher{
		logger:  logger,
		metrics: metrics,
		queue:   make(chan AlertEvent, sanitizeQueueSize(opts.QueueSize)),
		sinks:   buildAlertSinks(opts, logger),
	}

	if len(d.sinks) == 0 {
		logger.Warn("alerting enabled but no alert sinks configured; publisher will be disabled")
		return NewNoopAlertPublisher()
	}

	d.wg.Add(1)
	go d.run()
	return d
}

func (d *alertDispatcher) Publish(event AlertEvent) {
	if event.EventType == "" {
		return
	}
	if event.AggregateCount <= 0 {
		event.AggregateCount = 1
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.EventID == "" {
		event.EventID = nextAlertEventID()
	}

	select {
	case d.queue <- event:
		d.metrics.IncAlertEvent(string(event.EventType), "enqueued")
	default:
		d.metrics.IncAlertEvent(string(event.EventType), "dropped")
		d.logger.Warn("dropping alert event because queue is full", "event_type", event.EventType)
	}
}

func (d *alertDispatcher) Close() {
	d.closeOnce.Do(func() {
		close(d.queue)
		d.wg.Wait()
	})
}

func (d *alertDispatcher) run() {
	defer d.wg.Done()
	for event := range d.queue {
		d.dispatch(event)
	}
}

func (d *alertDispatcher) dispatch(event AlertEvent) {
	for _, sink := range d.sinks {
		if err := d.sendWithRetry(sink, event); err != nil {
			d.logger.Warn("alert sink delivery failed", "sink", sink.name(), "event_type", event.EventType, "error", err)
		}
	}
}

func (d *alertDispatcher) sendWithRetry(sink alertSink, event AlertEvent) error {
	attempts := sink.maxRetries()
	if attempts <= 0 {
		attempts = 1
	}
	backoff := sink.backoffInitial()
	if backoff <= 0 {
		backoff = defaultAlertBackoffInitial
	}

	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		err := sink.send(event)
		if err == nil {
			d.metrics.IncAlertSinkDelivery(sink.name(), "sent")
			return nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		d.metrics.IncAlertSinkDelivery(sink.name(), "retry")
		time.Sleep(nextAlertBackoff(backoff, attempt))
	}

	d.metrics.IncAlertSinkDelivery(sink.name(), "failed")
	return lastErr
}

type alertSink interface {
	name() string
	send(event AlertEvent) error
	maxRetries() int
	backoffInitial() time.Duration
}

type httpAlertSink struct {
	sinkName            string
	url                 string
	token               string
	client              *http.Client
	retries             int
	backoffInitialDelay time.Duration
	mapPayload          func(event AlertEvent) ([]byte, error)
}

func (s *httpAlertSink) name() string {
	return s.sinkName
}

func (s *httpAlertSink) maxRetries() int {
	return s.retries
}

func (s *httpAlertSink) backoffInitial() time.Duration {
	return s.backoffInitialDelay
}

func (s *httpAlertSink) send(event AlertEvent) error {
	payload, err := s.mapPayload(event)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, s.url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

func buildAlertSinks(opts AlertingOptions, logger *slog.Logger) []alertSink {
	sinks := make([]alertSink, 0, 3)
	logger = ensureLogger(logger)

	if opts.Webhook.Enabled && strings.TrimSpace(opts.Webhook.URL) != "" {
		sinks = append(sinks, &httpAlertSink{
			sinkName:            "webhook",
			url:                 strings.TrimSpace(opts.Webhook.URL),
			token:               strings.TrimSpace(opts.Webhook.AuthBearerToken),
			client:              &http.Client{Timeout: sanitizeTimeout(opts.Webhook.Timeout)},
			retries:             sanitizeRetries(opts.Webhook.MaxRetries),
			backoffInitialDelay: sanitizeBackoff(opts.Webhook.BackoffInitial),
			mapPayload: func(event AlertEvent) ([]byte, error) {
				return json.Marshal(event)
			},
		})
	}

	if opts.Slack.Enabled && strings.TrimSpace(opts.Slack.URL) != "" {
		sinks = append(sinks, &httpAlertSink{
			sinkName:            "slack",
			url:                 strings.TrimSpace(opts.Slack.URL),
			client:              &http.Client{Timeout: sanitizeTimeout(opts.Slack.Timeout)},
			retries:             sanitizeRetries(opts.Slack.MaxRetries),
			backoffInitialDelay: sanitizeBackoff(opts.Slack.BackoffInitial),
			mapPayload:          mapSlackPayload,
		})
	}

	if opts.PagerDuty.Enabled {
		routingKey := strings.TrimSpace(opts.PagerDuty.RoutingKey)
		if routingKey == "" {
			logger.Warn("pagerduty alert sink enabled but routing_key is empty; sink disabled")
		} else {
			url := strings.TrimSpace(opts.PagerDuty.URL)
			if url == "" {
				url = defaultPagerDutyEventsURL
			}
			pagerDutyOptions := opts.PagerDuty

			sinks = append(sinks, &httpAlertSink{
				sinkName:            "pagerduty",
				url:                 url,
				client:              &http.Client{Timeout: sanitizeTimeout(pagerDutyOptions.Timeout)},
				retries:             sanitizeRetries(pagerDutyOptions.MaxRetries),
				backoffInitialDelay: sanitizeBackoff(pagerDutyOptions.BackoffInitial),
				mapPayload: func(event AlertEvent) ([]byte, error) {
					return mapPagerDutyPayload(event, routingKey, pagerDutyOptions)
				},
			})
		}
	}

	return sinks
}

func mapSlackPayload(event AlertEvent) ([]byte, error) {
	payload := map[string]interface{}{
		"text": fmt.Sprintf("PIF alert: %s", event.EventType),
		"attachments": []map[string]interface{}{
			{
				"color": alertColor(event.EventType),
				"title": strings.ToUpper(string(event.EventType)),
				"text":  fmt.Sprintf("action=%s method=%s path=%s client=%s score=%.2f threshold=%.2f findings=%d aggregate_count=%d reason=%s", event.Action, event.Method, event.Path, event.ClientKey, event.Score, event.Threshold, event.FindingsCount, event.AggregateCount, event.Reason),
				"ts":    event.Timestamp.Unix(),
			},
		},
	}
	return json.Marshal(payload)
}

func alertColor(eventType AlertEventType) string {
	switch eventType {
	case AlertEventInjectionBlocked:
		return "danger"
	case AlertEventRateLimit:
		return "warning"
	case AlertEventScanError:
		return "#8B0000"
	default:
		return "#2F855A"
	}
}

func mapPagerDutyPayload(event AlertEvent, routingKey string, opts AlertingPagerDutyOptions) ([]byte, error) {
	timestamp := event.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	source := strings.TrimSpace(opts.Source)
	if source == "" {
		source = "prompt-injection-firewall"
	}
	component := strings.TrimSpace(opts.Component)
	if component == "" {
		component = "proxy"
	}
	group := strings.TrimSpace(opts.Group)
	if group == "" {
		group = "pif"
	}
	class := strings.TrimSpace(opts.Class)
	if class == "" {
		class = "security"
	}

	customDetails := map[string]interface{}{
		"event_id":        event.EventID,
		"event_type":      string(event.EventType),
		"action":          event.Action,
		"client_key":      event.ClientKey,
		"method":          event.Method,
		"path":            event.Path,
		"target":          event.Target,
		"score":           event.Score,
		"threshold":       event.Threshold,
		"findings_count":  event.FindingsCount,
		"reason":          event.Reason,
		"aggregate_count": event.AggregateCount,
		"sample_findings": event.SampleFindings,
	}

	payload := map[string]interface{}{
		"routing_key":  routingKey,
		"event_action": "trigger",
		"payload": map[string]interface{}{
			"summary":        pagerDutySummary(event),
			"source":         source,
			"severity":       pagerDutySeverity(event.EventType),
			"timestamp":      timestamp.UTC().Format(time.RFC3339),
			"component":      component,
			"group":          group,
			"class":          class,
			"custom_details": customDetails,
		},
	}

	return json.Marshal(payload)
}

func pagerDutySeverity(eventType AlertEventType) string {
	switch eventType {
	case AlertEventInjectionBlocked:
		return "critical"
	case AlertEventScanError:
		return "error"
	case AlertEventRateLimit:
		return "warning"
	default:
		return "info"
	}
}

func pagerDutySummary(event AlertEvent) string {
	action := event.Action
	if action == "" {
		action = "unknown"
	}
	path := event.Path
	if path == "" {
		path = "/"
	}
	reason := event.Reason
	if strings.TrimSpace(reason) == "" {
		reason = "n/a"
	}
	return fmt.Sprintf("pif %s action=%s path=%s reason=%s", event.EventType, action, path, reason)
}

func sanitizeQueueSize(size int) int {
	if size <= 0 {
		return defaultAlertQueueSize
	}
	return size
}

func sanitizeTimeout(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		return defaultAlertTimeout
	}
	return timeout
}

func sanitizeRetries(retries int) int {
	if retries <= 0 {
		return defaultAlertMaxRetries
	}
	return retries
}

func sanitizeBackoff(backoff time.Duration) time.Duration {
	if backoff <= 0 {
		return defaultAlertBackoffInitial
	}
	return backoff
}

func nextAlertBackoff(initial time.Duration, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	backoff := initial * time.Duration(1<<(attempt-1))
	if backoff > maxAlertBackoff {
		backoff = maxAlertBackoff
	}
	jitterMax := backoff / 2
	if jitterMax <= 0 {
		return backoff
	}
	jitter := time.Duration(rand.Int63n(int64(jitterMax) + 1))
	return backoff + jitter
}

var alertEventSequence uint64

func nextAlertEventID() string {
	seq := atomic.AddUint64(&alertEventSequence, 1)
	return fmt.Sprintf("evt-%d-%d", time.Now().UTC().UnixNano(), seq)
}

type aggregateWindowBucket struct {
	windowStart time.Time
	suppressed  int
}

// alertWindowAggregator emits at most one event per key per window and returns
// aggregate counts for bursty repeated signals.
type alertWindowAggregator struct {
	mu      sync.Mutex
	window  time.Duration
	buckets map[string]aggregateWindowBucket
}

func newAlertWindowAggregator(window time.Duration) *alertWindowAggregator {
	if window <= 0 {
		window = 60 * time.Second
	}
	return &alertWindowAggregator{
		window:  window,
		buckets: make(map[string]aggregateWindowBucket),
	}
}

func (a *alertWindowAggregator) Record(key string, now time.Time) (emit bool, aggregateCount int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	bucket, ok := a.buckets[key]
	if !ok || bucket.windowStart.IsZero() {
		a.buckets[key] = aggregateWindowBucket{windowStart: now, suppressed: 0}
		return true, 1
	}

	if now.Sub(bucket.windowStart) < a.window {
		bucket.suppressed++
		a.buckets[key] = bucket
		return false, 0
	}

	count := bucket.suppressed + 1
	a.buckets[key] = aggregateWindowBucket{windowStart: now, suppressed: 0}
	return true, count
}
