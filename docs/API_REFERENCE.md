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
