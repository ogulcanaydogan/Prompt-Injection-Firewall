package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlertWindowAggregator(t *testing.T) {
	agg := newAlertWindowAggregator(200 * time.Millisecond)
	now := time.Now().UTC()

	emit, count := agg.Record("k1", now)
	assert.True(t, emit)
	assert.Equal(t, 1, count)

	emit, count = agg.Record("k1", now.Add(50*time.Millisecond))
	assert.False(t, emit)
	assert.Equal(t, 0, count)

	emit, count = agg.Record("k1", now.Add(100*time.Millisecond))
	assert.False(t, emit)
	assert.Equal(t, 0, count)

	emit, count = agg.Record("k1", now.Add(250*time.Millisecond))
	assert.True(t, emit)
	assert.Equal(t, 3, count)
}

func TestAlertDispatcher_WebhookRetryAndBearer(t *testing.T) {
	var attempts int32
	var authHeader atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		authHeader.Store(r.Header.Get("Authorization"))
		if atomic.LoadInt32(&attempts) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("temporary failure"))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	metrics := NewMetrics()
	pub := BuildAlertPublisher(AlertingOptions{
		Enabled:   true,
		QueueSize: 16,
		Events: AlertingEventOptions{
			Block:     true,
			RateLimit: true,
			ScanError: true,
		},
		Webhook: AlertingSinkOptions{
			Enabled:         true,
			URL:             srv.URL,
			Timeout:         2 * time.Second,
			MaxRetries:      3,
			BackoffInitial:  2 * time.Millisecond,
			AuthBearerToken: "abc123",
		},
	}, nil, metrics)
	defer pub.Close()

	pub.Publish(AlertEvent{
		Timestamp:      time.Now().UTC(),
		EventType:      AlertEventInjectionBlocked,
		Action:         "block",
		ClientKey:      "10.0.0.1",
		Method:         http.MethodPost,
		Path:           "/v1/chat/completions",
		Target:         "https://api.openai.com",
		Score:          0.92,
		Threshold:      0.5,
		FindingsCount:  1,
		Reason:         "blocked_by_policy",
		AggregateCount: 1,
	})

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&attempts) >= 2
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, "Bearer abc123", authHeader.Load())
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("webhook", "retry")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("webhook", "sent")))
}

func TestAlertDispatcher_SlackPayload(t *testing.T) {
	var received map[string]interface{}
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		var payload map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
		mu.Lock()
		received = payload
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	pub := BuildAlertPublisher(AlertingOptions{
		Enabled:   true,
		QueueSize: 16,
		Slack: AlertingSinkOptions{
			Enabled:        true,
			URL:            srv.URL,
			Timeout:        2 * time.Second,
			MaxRetries:     1,
			BackoffInitial: 1 * time.Millisecond,
		},
	}, nil, NewMetrics())
	defer pub.Close()

	pub.Publish(AlertEvent{
		Timestamp:      time.Now().UTC(),
		EventType:      AlertEventRateLimit,
		Action:         "block",
		ClientKey:      "10.0.0.2",
		Method:         http.MethodPost,
		Path:           "/v1/chat/completions",
		Target:         "https://api.openai.com",
		Reason:         "exceeded",
		AggregateCount: 4,
	})

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return received != nil
	}, 2*time.Second, 10*time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	assert.Contains(t, received["text"], "PIF alert")
	attachments, ok := received["attachments"].([]interface{})
	require.True(t, ok)
	require.NotEmpty(t, attachments)
}

func TestBuildAlertPublisher_NoSinksReturnsNoop(t *testing.T) {
	pub := BuildAlertPublisher(AlertingOptions{Enabled: true, QueueSize: 4}, nil, NewMetrics())
	defer pub.Close()

	pub.Publish(AlertEvent{EventType: AlertEventInjectionBlocked})
}

func TestAlertDispatcher_ContinuesToNextSinkOnFailure(t *testing.T) {
	var webhookAttempts int32
	var slackAttempts int32

	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookAttempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer webhookSrv.Close()

	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&slackAttempts, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer slackSrv.Close()

	metrics := NewMetrics()
	pub := BuildAlertPublisher(AlertingOptions{
		Enabled:   true,
		QueueSize: 16,
		Webhook: AlertingSinkOptions{
			Enabled:    true,
			URL:        webhookSrv.URL,
			Timeout:    2 * time.Second,
			MaxRetries: 1,
		},
		Slack: AlertingSinkOptions{
			Enabled:    true,
			URL:        slackSrv.URL,
			Timeout:    2 * time.Second,
			MaxRetries: 1,
		},
	}, nil, metrics)
	defer pub.Close()

	pub.Publish(AlertEvent{
		EventType:      AlertEventInjectionBlocked,
		Action:         "block",
		ClientKey:      "10.0.0.1",
		Method:         http.MethodPost,
		Path:           "/v1/chat/completions",
		Target:         "https://api.openai.com",
		AggregateCount: 1,
	})

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&webhookAttempts) >= 1 && atomic.LoadInt32(&slackAttempts) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("webhook", "failed")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("slack", "sent")))
}

func TestAlertDispatcher_QueueDropDoesNotBlockPublisher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	metrics := NewMetrics()
	pub := BuildAlertPublisher(AlertingOptions{
		Enabled:   true,
		QueueSize: 1,
		Webhook: AlertingSinkOptions{
			Enabled:    true,
			URL:        srv.URL,
			Timeout:    2 * time.Second,
			MaxRetries: 1,
		},
	}, nil, metrics)
	defer pub.Close()

	for i := 0; i < 50; i++ {
		pub.Publish(AlertEvent{
			EventType:      AlertEventRateLimit,
			Action:         "block",
			ClientKey:      "10.0.0.1",
			Method:         http.MethodPost,
			Path:           "/v1/chat/completions",
			Target:         "https://api.openai.com",
			AggregateCount: 1,
		})
	}

	require.Eventually(t, func() bool {
		return testutil.ToFloat64(metrics.alertEventsTotal.WithLabelValues(string(AlertEventRateLimit), "dropped")) > 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestMapPagerDutyPayload_TriggerContract(t *testing.T) {
	event := AlertEvent{
		EventID:        "evt-1",
		Timestamp:      time.Date(2026, 3, 8, 1, 2, 3, 0, time.UTC),
		EventType:      AlertEventInjectionBlocked,
		Action:         "block",
		ClientKey:      "10.0.0.1",
		Method:         http.MethodPost,
		Path:           "/v1/chat/completions",
		Target:         "https://api.openai.com",
		Score:          0.91,
		Threshold:      0.5,
		FindingsCount:  2,
		Reason:         "blocked_by_policy",
		AggregateCount: 1,
		SampleFindings: []AlertFinding{
			{RuleID: "PIF-1", Category: "prompt_injection", Severity: 4, Match: "ignore"},
		},
	}
	payloadBytes, err := mapPagerDutyPayload(event, "pd-routing-key", AlertingPagerDutyOptions{
		Source:    "pif-prod",
		Component: "proxy-main",
		Group:     "secops",
		Class:     "firewall",
	})
	require.NoError(t, err)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(payloadBytes, &payload))
	assert.Equal(t, "pd-routing-key", payload["routing_key"])
	assert.Equal(t, "trigger", payload["event_action"])

	pdPayload, ok := payload["payload"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "critical", pdPayload["severity"])
	assert.Equal(t, "pif-prod", pdPayload["source"])
	assert.Equal(t, "proxy-main", pdPayload["component"])
	assert.Equal(t, "secops", pdPayload["group"])
	assert.Equal(t, "firewall", pdPayload["class"])
	assert.Contains(t, pdPayload["summary"], "injection_blocked")

	customDetails, ok := pdPayload["custom_details"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "evt-1", customDetails["event_id"])
	assert.Equal(t, "injection_blocked", customDetails["event_type"])
	assert.Equal(t, "block", customDetails["action"])
	assert.Equal(t, "/v1/chat/completions", customDetails["path"])
}

func TestBuildAlertPublisher_PagerDutyMissingRoutingKey_DisabledSink(t *testing.T) {
	pub := BuildAlertPublisher(AlertingOptions{
		Enabled:   true,
		QueueSize: 8,
		PagerDuty: AlertingPagerDutyOptions{
			Enabled: true,
			URL:     "https://events.pagerduty.com/v2/enqueue",
		},
	}, nil, NewMetrics())
	defer pub.Close()

	_, ok := pub.(*noopAlertPublisher)
	assert.True(t, ok)
}

func TestAlertDispatcher_PagerDutyDeliveryAndRetry(t *testing.T) {
	var attempts int32
	var captured map[string]interface{}
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		atomic.AddInt32(&attempts, 1)
		if atomic.LoadInt32(&attempts) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var body map[string]interface{}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		mu.Lock()
		captured = body
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	metrics := NewMetrics()
	pub := BuildAlertPublisher(AlertingOptions{
		Enabled:   true,
		QueueSize: 8,
		PagerDuty: AlertingPagerDutyOptions{
			Enabled:        true,
			URL:            srv.URL,
			RoutingKey:     "pd-key",
			Timeout:        2 * time.Second,
			MaxRetries:     2,
			BackoffInitial: 2 * time.Millisecond,
		},
	}, nil, metrics)
	defer pub.Close()

	pub.Publish(AlertEvent{
		EventType:      AlertEventRateLimit,
		Action:         "block",
		ClientKey:      "10.0.0.5",
		Method:         http.MethodPost,
		Path:           "/v1/chat/completions",
		Reason:         "exceeded",
		AggregateCount: 3,
	})

	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return captured != nil
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("pagerduty", "retry")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("pagerduty", "sent")))
}

func TestAlertDispatcher_PagerDutyReceivesAfterWebhookFailure(t *testing.T) {
	var webhookAttempts int32
	var pagerDutyAttempts int32

	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&webhookAttempts, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer webhookSrv.Close()

	pagerDutySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&pagerDutyAttempts, 1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer pagerDutySrv.Close()

	metrics := NewMetrics()
	pub := BuildAlertPublisher(AlertingOptions{
		Enabled:   true,
		QueueSize: 8,
		Webhook: AlertingSinkOptions{
			Enabled:    true,
			URL:        webhookSrv.URL,
			Timeout:    2 * time.Second,
			MaxRetries: 1,
		},
		PagerDuty: AlertingPagerDutyOptions{
			Enabled:    true,
			URL:        pagerDutySrv.URL,
			RoutingKey: "pd-key",
			Timeout:    2 * time.Second,
			MaxRetries: 1,
		},
	}, nil, metrics)
	defer pub.Close()

	pub.Publish(AlertEvent{
		EventType:      AlertEventScanError,
		Action:         "block",
		ClientKey:      "10.0.0.5",
		Method:         http.MethodPost,
		Path:           "/v1/chat/completions",
		Reason:         "detector_scan_error",
		AggregateCount: 1,
	})

	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&webhookAttempts) >= 1 && atomic.LoadInt32(&pagerDutyAttempts) >= 1
	}, 2*time.Second, 10*time.Millisecond)

	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("webhook", "failed")))
	assert.Equal(t, 1.0, testutil.ToFloat64(metrics.alertSinkDeliveriesTotal.WithLabelValues("pagerduty", "sent")))
}
