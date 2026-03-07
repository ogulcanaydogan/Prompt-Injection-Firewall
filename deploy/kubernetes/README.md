# Kubernetes Admission Webhook Deployment

This folder deploys the Phase 2 validating admission webhook that enforces PIF proxy routing for LLM-enabled workloads.

## Prerequisites

- Kubernetes cluster with `cert-manager` installed
- Image `ghcr.io/ogulcanaydogan/prompt-injection-firewall:latest` available

## Deploy

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/webhook-service.yaml
kubectl apply -f deploy/kubernetes/webhook-deployment.yaml
kubectl apply -f deploy/kubernetes/webhook-certificate.yaml
kubectl apply -f deploy/kubernetes/validating-webhook-configuration.yaml
```

## Validation Rules

- Applies on `CREATE/UPDATE` for `Pod`, `Deployment`, `StatefulSet`, `Job`, and `CronJob`.
- If `OPENAI_API_KEY` is set, `OPENAI_BASE_URL` must match the PIF host pattern.
- If `ANTHROPIC_API_KEY` is set, `ANTHROPIC_BASE_URL` must match the PIF host pattern.
- Bypass is only allowed by setting annotation `pif.io/skip-validation: "true"`.
