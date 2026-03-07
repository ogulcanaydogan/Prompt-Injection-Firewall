# Integration Guide

This guide walks you through setting up PIF as a transparent proxy in front of your LLM API and integrating it with popular SDKs.

## How PIF Works

PIF sits between your application and the LLM API as a reverse proxy:

```
Your App  ──▶  PIF Proxy (:8080)  ──▶  LLM API (OpenAI / Anthropic)
                    │
              Scans every prompt
              for injection attacks
```

Your application sends requests to PIF instead of directly to the LLM API. PIF scans all prompts in real time and either forwards clean requests or blocks malicious ones.

## Step 1: Install PIF

### Option A: Go Install

```bash
go install github.com/ogulcanaydogan/Prompt-Injection-Firewall/cmd/pif-cli@latest
```

### Option B: Build from Source

```bash
git clone https://github.com/ogulcanaydogan/Prompt-Injection-Firewall.git
cd Prompt-Injection-Firewall
go build -o pif ./cmd/pif-cli/
go build -o pif-firewall ./cmd/firewall/
```

### Option C: Docker

```bash
docker pull ghcr.io/ogulcanaydogan/prompt-injection-firewall:latest
```

## Step 2: Start the Proxy

```bash
# For OpenAI
pif proxy --target https://api.openai.com --listen :8080

# For Anthropic
pif proxy --target https://api.anthropic.com --listen :8080
```

Verify it is running:

```bash
curl http://localhost:8080/healthz
# {"status":"ok"}

curl http://localhost:8080/metrics
# Prometheus metrics output
```

## Step 3: Integrate with Your SDK

### Python (OpenAI)

```python
from openai import OpenAI

client = OpenAI(
    api_key="sk-...",
    base_url="http://localhost:8080/v1",  # Point to PIF
)

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

### Python (Anthropic)

```python
import anthropic

client = anthropic.Anthropic(
    api_key="sk-ant-...",
    base_url="http://localhost:8080",  # Point to PIF
)

response = client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=256,
    messages=[{"role": "user", "content": "Hello!"}],
)
```

### Node.js (OpenAI)

```javascript
const OpenAI = require("openai");

const client = new OpenAI({
  apiKey: "sk-...",
  baseURL: "http://localhost:8080/v1", // Point to PIF
});

const response = await client.chat.completions.create({
  model: "gpt-4",
  messages: [{ role: "user", content: "Hello!" }],
});
```

### Go (net/http)

```go
req, _ := http.NewRequest("POST", "http://localhost:8080/v1/chat/completions", body)
req.Header.Set("Authorization", "Bearer sk-...")
req.Header.Set("Content-Type", "application/json")

resp, err := http.DefaultClient.Do(req)
```

### cURL

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer sk-..." \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello!"}]}'
```

### Environment Variable (SDK-agnostic)

Many SDKs support a base URL environment variable:

```bash
export OPENAI_BASE_URL=http://localhost:8080/v1
# Now any OpenAI SDK call will go through PIF automatically
```

## Step 4: Handle Blocked Requests

When PIF detects an injection, it returns **HTTP 403** with a JSON error body:

```json
{
  "error": {
    "message": "Request blocked by Prompt Injection Firewall",
    "type": "prompt_injection_detected",
    "score": 0.85,
    "findings": 2
  }
}
```

Make sure your application handles 403 responses gracefully.

## Step 5: Choose a Response Action

PIF supports three response modes configured via `--action`:

| Action | Behavior | Use Case |
|--------|----------|----------|
| `block` | Returns HTTP 403 | Production |
| `flag` | Forwards with `X-PIF-Flagged: true` header | Staging |
| `log` | Forwards silently, logs detection | Development |

```bash
# Staging: flag but don't block
pif proxy --target https://api.openai.com --listen :8080 --action flag

# Development: log only
pif proxy --target https://api.openai.com --listen :8080 --action log
```

When using `flag` mode, check the response headers:

```bash
X-PIF-Flagged: true
X-PIF-Score: 0.85
```

## Step 6: Enable Rate Limiting and Adaptive Thresholds

Rate limiting and adaptive thresholds are enabled by default in `config.yaml`.

```yaml
proxy:
  rate_limit:
    enabled: true
    requests_per_minute: 120
    burst: 30
    key_header: "X-Forwarded-For"

detector:
  adaptive_threshold:
    enabled: true
    min_threshold: 0.25
    ewma_alpha: 0.2
```

## Step 7: Kubernetes Admission Webhook (Optional)

To enforce PIF proxy usage cluster-wide for LLM-enabled workloads:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/webhook-service.yaml
kubectl apply -f deploy/kubernetes/webhook-deployment.yaml
kubectl apply -f deploy/kubernetes/webhook-certificate.yaml
kubectl apply -f deploy/kubernetes/validating-webhook-configuration.yaml
```

The webhook validates `Pod`, `Deployment`, `StatefulSet`, `Job`, and `CronJob` on `CREATE/UPDATE`.

## Verify Setup Checklist

- [ ] PIF proxy starts without errors
- [ ] `curl /healthz` returns `{"status":"ok"}`
- [ ] `curl /metrics` returns Prometheus metrics
- [ ] Clean prompts pass through successfully
- [ ] Known injection attempts return HTTP 403
- [ ] Your application handles 403 responses gracefully
