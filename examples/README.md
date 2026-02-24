# Examples

Integration examples for the Prompt Injection Firewall (PIF). Each example demonstrates how to route LLM API requests through PIF for real-time prompt injection detection.

## Prerequisites

1. **PIF proxy running:**
   ```bash
   # For OpenAI
   pif proxy --target https://api.openai.com --listen :8080

   # For Anthropic
   pif proxy --target https://api.anthropic.com --listen :8080
   ```

2. **API key** for your LLM provider (OpenAI or Anthropic).

## Examples

| Directory | Language | Description |
|-----------|----------|-------------|
| [`python/`](python/) | Python | OpenAI and Anthropic SDK integration |
| [`nodejs/`](nodejs/) | Node.js | OpenAI SDK integration with async/await |
| [`curl/`](curl/) | Shell | Raw HTTP requests for testing |
| [`docker/`](docker/) | Docker | Production-ready Docker Compose setup |

## Python

```bash
cd python
pip install -r requirements.txt

# OpenAI example
OPENAI_API_KEY=sk-... python openai_example.py

# Anthropic example
ANTHROPIC_API_KEY=sk-ant-... python anthropic_example.py
```

## Node.js

```bash
cd nodejs
npm install

OPENAI_API_KEY=sk-... node openai_example.js
```

## cURL

```bash
cd curl

# OpenAI
OPENAI_API_KEY=sk-... bash openai.sh

# Anthropic
ANTHROPIC_API_KEY=sk-ant-... bash anthropic.sh
```

## Docker

```bash
cd docker
docker compose up -d

# Verify PIF is running
curl http://localhost:8080/healthz

# Then point your SDK at http://localhost:8080/v1
```

## What Each Example Demonstrates

Every example shows three scenarios:

1. **Clean prompt** -- A benign request that passes through PIF to the LLM API
2. **Prompt injection** -- An attempt to override system instructions (blocked with HTTP 403)
3. **Data exfiltration / jailbreak** -- An attempt to extract data or bypass safety (blocked with HTTP 403)

## Expected Output

When PIF blocks a request, you will receive:

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
