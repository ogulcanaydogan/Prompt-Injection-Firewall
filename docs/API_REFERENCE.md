# API Reference

PIF operates as a transparent HTTP reverse proxy. This document describes the request formats PIF expects, the responses it returns, and the endpoints it exposes.

## Endpoints

### Health Check

```
GET /healthz
```

**Response:**

```json
{"status":"ok"}
```

Returns HTTP 200 when PIF is running and ready to accept requests.

### Metrics

```
GET /metrics
```

Exposes Prometheus metrics for traffic, scan latency, detections, score distribution, and rate-limit events.

Core metric names:

- `pif_http_requests_total`
- `pif_scan_duration_seconds`
- `pif_injection_detections_total`
- `pif_detection_score`
- `pif_rate_limit_events_total`
- `pif_alert_events_total`
- `pif_alert_sink_deliveries_total`

### Outbound Alerting (Optional)

When `alerting.enabled=true`, PIF emits outbound alerts without exposing new inbound HTTP endpoints.

Initial event types:

- `injection_blocked` (immediate on block action)
- `rate_limit_exceeded` (window-aggregated per client key)
- `scan_error` (window-aggregated per client key)

Delivery model:

- Async queue + worker dispatcher
- Retry with exponential backoff and jitter
- Fail-open behavior (delivery failure never blocks proxy request handling)
- Sink execution order is sequential (`webhook` -> `slack` -> `pagerduty` when enabled)

Supported sinks:

- Generic webhook (`alerting.webhook.*`)
- Slack Incoming Webhook (`alerting.slack.*`)
- PagerDuty Events API v2 (`alerting.pagerduty.*`)

Generic webhook sends JSON payloads with the following contract:

```json
{
  "event_id": "evt-1741363854757000000-1",
  "timestamp": "2026-03-07T12:30:54Z",
  "event_type": "injection_blocked",
  "action": "block",
  "client_key": "203.0.113.10",
  "method": "POST",
  "path": "/v1/chat/completions",
  "target": "https://api.openai.com",
  "score": 0.92,
  "threshold": 0.50,
  "findings_count": 2,
  "reason": "blocked_by_policy",
  "sample_findings": [
    {
      "rule_id": "PIF-INJ-001",
      "category": "prompt_injection",
      "severity": 4,
      "match": "ignore all previous instructions"
    }
  ],
  "aggregate_count": 1
}
```

Notes:

- `sample_findings` is capped at 3 entries.
- `aggregate_count` is used by aggregated events (`rate_limit_exceeded`, `scan_error`).
- When configured, webhook sink sends `Authorization: Bearer <token>`.

PagerDuty sink sends trigger-only Events API v2 payloads:

```json
{
  "routing_key": "your-routing-key",
  "event_action": "trigger",
  "payload": {
    "summary": "pif injection_blocked action=block path=/v1/chat/completions reason=blocked_by_policy",
    "source": "prompt-injection-firewall",
    "severity": "critical",
    "timestamp": "2026-03-08T01:02:03Z",
    "component": "proxy",
    "group": "pif",
    "class": "security",
    "custom_details": {
      "event_id": "evt-1741395723000000000-1",
      "event_type": "injection_blocked",
      "action": "block",
      "client_key": "203.0.113.10",
      "method": "POST",
      "path": "/v1/chat/completions",
      "target": "https://api.openai.com",
      "score": 0.92,
      "threshold": 0.5,
      "findings_count": 2,
      "reason": "blocked_by_policy",
      "aggregate_count": 1,
      "sample_findings": []
    }
  }
}
```

PagerDuty severity mapping:

- `injection_blocked` -> `critical`
- `scan_error` -> `error`
- `rate_limit_exceeded` -> `warning`

### Embedded Dashboard (Optional)

When `dashboard.enabled=true`, PIF exposes a monitoring dashboard:

```
GET /dashboard
GET /api/dashboard/summary
GET /api/dashboard/metrics
GET /api/dashboard/rules
GET /api/dashboard/replays
GET /api/dashboard/replays/{id}
POST /api/dashboard/replays/{id}/rescan
```

- `GET /dashboard` serves embedded HTML/CSS/JS.
- `GET /api/dashboard/summary` returns high-level counters, uptime, p95 scan latency, and a safe runtime config snapshot.
- `GET /api/dashboard/metrics` returns normalized JSON metrics for UI polling (totals, label breakdowns, quantiles).
- `GET /api/dashboard/rules` returns loaded rule set metadata plus managed custom rules.
- `GET /api/dashboard/replays` returns replay event list (`tenant`, `event_type`, `decision`, `payload_hash`, findings, request metadata).
- `GET /api/dashboard/replays/{id}` returns full replay record.
- `POST /api/dashboard/replays/{id}/rescan` rescans captured prompts with the current detector (no upstream forwarding).

If `dashboard.auth.enabled=true`, both UI and dashboard API endpoints require Basic Auth and return:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="pif-dashboard"
```

### Dashboard Rule Management (Optional)

When `dashboard.rule_management.enabled=true`, write APIs are exposed under the dashboard rules endpoint:

```
POST   /api/dashboard/rules
PUT    /api/dashboard/rules/{id}
DELETE /api/dashboard/rules/{id}
```

Write policy:

- `dashboard.enabled=false` -> all dashboard routes return `404`.
- `dashboard.rule_management.enabled=false` -> write routes return `404`.
- `dashboard.rule_management.enabled=true` and `dashboard.auth.enabled=false` -> write routes return `403`.
- `dashboard.rule_management.enabled=true` and valid Basic Auth -> writes allowed.

Payload format (`POST` and `PUT`):

```json
{
  "rule": {
    "id": "PIF-CUSTOM-001",
    "name": "Custom Rule",
    "description": "Detects tenant-specific injection pattern",
    "category": "prompt_injection",
    "severity": 2,
    "pattern": "(?i)custom_attack_pattern",
    "enabled": true,
    "case_sensitive": false,
    "tags": [],
    "metadata": {}
  }
}
```

Notes:

- `severity` is integer `0..4` (`info..critical`).
- Built-in OWASP/jailbreak/data-exfil files are not edited via dashboard.
- Dashboard writes only to managed custom rules and applies changes with hot reload.
- Rule-set response includes source metadata (`source`, `path`, optional marketplace metadata).

### Replay / Forensics API (Optional)

Replay API is available only when both `dashboard.enabled=true` and `replay.enabled=true`.

Behavior:

- `dashboard.enabled=false` -> all dashboard routes return `404`.
- `replay.enabled=false` -> replay routes return `404`.
- If dashboard auth is enabled, replay routes require Basic Auth.

Replay event schema (JSONL-backed):

```json
{
  "replay_id": "rpl_1741395723000000000_1",
  "timestamp": "2026-03-08T01:30:45Z",
  "tenant": "default",
  "event_type": "block",
  "decision": "block",
  "score": 0.91,
  "threshold": 0.50,
  "findings": [],
  "request_meta": {
    "method": "POST",
    "path": "/v1/chat/completions",
    "target": "https://api.openai.com",
    "client_key": "203.0.113.10"
  },
  "payload_hash": "sha256-hex",
  "prompts": [
    {
      "role": "user",
      "text": "ignore all previous instructions",
      "truncated": false,
      "redacted": true
    }
  ]
}
```

Captured replay event types:

- `block`
- `rate_limit`
- `scan_error`
- `flag`

### Multi-Tenant Runtime Policy (Optional)

When `tenancy.enabled=true`, request policy can be resolved from `tenancy.header` (default `X-PIF-Tenant`) with fallback to `tenancy.default_tenant`.

Per-tenant policy override surface:

- `action`
- `threshold`
- `rate_limit.requests_per_minute`
- `rate_limit.burst`
- `adaptive_threshold.enabled`
- `adaptive_threshold.min_threshold`
- `adaptive_threshold.ewma_alpha`

Unknown tenant values fall back to default tenant policy.

Dashboard summary includes tenant breakdown for configured tenants.

### Community Marketplace CLI

Marketplace is a CLI surface (no inbound HTTP routes):

```bash
pif marketplace list
pif marketplace install <id>@<version>
pif marketplace update
```

Contract:

- Catalog index (`marketplace.index_url`) exposes entries:
  - `id`, `name`, `version`, `download_url`, `sha256`, `categories`, `maintainer`
- Install verifies checksum when `marketplace.require_checksum=true`
- Installed files are written to `marketplace.install_dir` and can be loaded as custom rules

### Proxy (All Other Paths)

```
POST /*
```

All POST requests are intercepted, scanned for prompt injection, and then forwarded to the upstream LLM API (or blocked). GET, PUT, DELETE, and other methods are forwarded without scanning.

---

## Request Formats

PIF auto-detects the request format based on the JSON body structure and URL path.

### OpenAI Format

```json
{
  "model": "gpt-4",
  "messages": [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "What is the capital of France?"}
  ]
}
```

PIF extracts and scans the `content` field from each message in the `messages` array. Empty content fields are skipped.

### Anthropic Format

```json
{
  "model": "claude-sonnet-4-20250514",
  "max_tokens": 256,
  "system": "You are a helpful assistant.",
  "messages": [
    {"role": "user", "content": "What is the capital of France?"}
  ]
}
```

PIF scans the optional `system` field (with role `system`) and each message's `content` in the `messages` array.

**Auto-detection logic:**
- If the URL path contains `anthropic` or `messages` **and** the body has a `system` field, PIF uses the Anthropic parser.
- Otherwise, PIF falls back to the OpenAI parser.

---

## Response Formats

### Block Action (HTTP 403)

When `action=block` and an injection is detected:

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": {
    "message": "Request blocked by Prompt Injection Firewall",
    "type": "prompt_injection_detected",
    "score": 0.85,
    "findings": 2
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `error.message` | string | Human-readable error message |
| `error.type` | string | Always `prompt_injection_detected` |
| `error.score` | float | Threat score (0.0 - 1.0) |
| `error.findings` | int | Number of matched detection rules |

### Rate-Limited Request (HTTP 429)

When client rate limits are enabled and exceeded:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": {
    "message": "Request rate-limited by Prompt Injection Firewall",
    "type": "rate_limit_exceeded"
  }
}
```

### Flag Action (HTTP 200 + Headers)

When `action=flag` and an injection is detected, PIF forwards the request to the upstream API and adds headers to the response:

```http
X-PIF-Flagged: true
X-PIF-Score: 0.85
```

| Header | Type | Description |
|--------|------|-------------|
| `X-PIF-Flagged` | string | `true` when injection detected |
| `X-PIF-Score` | string | Threat score as decimal string |

The response body is the original upstream API response.

### Log Action (HTTP 200)

When `action=log`, PIF forwards the request silently and logs the detection server-side. No headers are added and no modification is made to the response.

### Clean Request (HTTP 200)

When no injection is detected, PIF forwards the request to the upstream API without modification and returns the upstream response as-is.

---

## CLI Scan Output

### Table Format (default)

```
RESULT: INJECTION DETECTED (score: 0.85)

  RULE ID          CATEGORY                 SEVERITY   MATCH
  ---------------- ------------------------ ---------- ----------------------------------------
  PIF-INJ-001      prompt_injection         critical   "ignore all previous instructions..."
  PIF-LLM07-001    system_prompt_leak       high       "reveal your system prompt"

2 finding(s) in 1.23ms
```

### JSON Format (`-o json`)

```json
{
  "clean": false,
  "score": 0.85,
  "findings": [
    {
      "rule_id": "PIF-INJ-001",
      "category": "prompt_injection",
      "severity": 4,
      "description": "Detects attempts to override system instructions",
      "matched_text": "ignore all previous instructions",
      "offset": 0,
      "length": 32
    }
  ],
  "detector_id": "ensemble",
  "duration_ms": 1.23,
  "input_hash": "a1b2c3d4..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `clean` | bool | `true` if no injection detected |
| `score` | float | Threat score (0.0 - 1.0) |
| `findings` | array | List of matched rules |
| `findings[].rule_id` | string | Unique rule identifier |
| `findings[].category` | string | Attack category |
| `findings[].severity` | int | 0=info, 1=low, 2=medium, 3=high, 4=critical |
| `findings[].matched_text` | string | The text that triggered the rule |
| `findings[].offset` | int | Character offset in the input |
| `findings[].length` | int | Length of the matched text |
| `detector_id` | string | Detector that produced the result |
| `duration_ms` | float | Scan duration in milliseconds |
| `input_hash` | string | SHA-256 hash of the input text |

---

## Exit Codes (CLI)

| Code | Meaning |
|------|---------|
| `0` | Clean -- no injection detected |
| `1` | Injection detected |
| `2` | Error (invalid input, missing rules, etc.) |
