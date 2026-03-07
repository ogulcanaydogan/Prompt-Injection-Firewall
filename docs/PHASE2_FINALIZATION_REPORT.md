# Phase 2 Finalization Report

Date: 2026-03-07

This report records the verification evidence used to close Phase 2.

## Local Verification

Commands executed:

```bash
go test ./...
go test -coverprofile=/tmp/pif-cover.out ./...
go test -race ./...
```

Result:

- `go test ./...` passed.
- Total coverage: `82.7%` (>= 80% target).
- `-race` test suite passed.

## CI/Release Dry-Check (Local Equivalent)

Release/CI build matrix commands executed locally for `linux|darwin|windows` x `amd64|arm64`:

- `./cmd/pif-cli`
- `./cmd/firewall`
- `./cmd/webhook`

All builds succeeded.

Note: GitHub-hosted CI jobs run on pushed commits; this report includes the
local equivalent of `ci.yml`/`release.yml` build and test commands.

## Docker Packaging Verification

Standard image build:

```bash
docker build -f deploy/docker/Dockerfile -t pif:phase2-final .
```

Entrypoint/binary checks:

```bash
docker run --rm pif:phase2-final version
docker run --rm --entrypoint /usr/local/bin/pif-cli pif:phase2-final version
docker run --rm --entrypoint /usr/local/bin/pif-webhook pif:phase2-final -h
```

Result: all binaries present and runnable.

ML builder verification:

```bash
docker build -f deploy/docker/Dockerfile.ml --target builder -t pif:phase2-final-ml-builder .
```

Result: `pif-firewall`, `pif-cli`, `pif-webhook` all built successfully with `-tags ml`.

## Kubernetes Admission Webhook Smoke (kind)

Environment:

- `kind v0.31.0`
- `kubectl v1.34.1`
- `cert-manager v1.17.1`

Deployment flow used:

1. Create kind cluster
2. Install cert-manager
3. Load local image `pif:phase2-final` to kind
4. Apply webhook resources (without `ValidatingWebhookConfiguration`)
5. Set webhook deployment image to `pif:phase2-final`
6. Wait rollout + TLS secret
7. Apply `ValidatingWebhookConfiguration`

Validation results:

- Deny case: `OPENAI_API_KEY + OPENAI_BASE_URL=https://api.openai.com/v1` => **DENIED**
- Allow case: `OPENAI_API_KEY + OPENAI_BASE_URL=http://pif-firewall.default.svc.cluster.local:8080/v1` => **ALLOWED**
- Bypass case: annotation `pif.io/skip-validation: "true"` => **ALLOWED**

Observed deny message:

```text
admission webhook "pif.proxy.guardrail.io" denied the request:
OPENAI_BASE_URL must route through PIF proxy
```
