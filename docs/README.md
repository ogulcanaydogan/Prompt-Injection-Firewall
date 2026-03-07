# Documentation

Detailed guides for integrating, deploying, and extending the Prompt Injection Firewall.

## Guides

| Document | Description |
|----------|-------------|
| [Integration Guide](INTEGRATION_GUIDE.md) | Step-by-step setup for Python, Node.js, Go, and cURL |
| [API Reference](API_REFERENCE.md) | Request formats, response formats, headers, and endpoints |
| [Rule Development](RULE_DEVELOPMENT.md) | How to write, test, and contribute custom detection rules |
| [ML Training Pipeline](../ml/README.md) | Fine-tune DistilBERT, export to ONNX, and evaluate models |
| [Kubernetes Webhook Deployment](../deploy/kubernetes/README.md) | Cluster-wide validating admission webhook for PIF routing |
| [Observability Assets](../deploy/observability/) | Prometheus scrape config and Grafana dashboard JSON |
| [Phase 2 Finalization Report](PHASE2_FINALIZATION_REPORT.md) | Local and kind smoke verification evidence |

## Quick Links

- [Examples](../examples/) -- Runnable integration code for Python, Node.js, cURL, and Docker
- [Configuration](../config.yaml) -- Default configuration file with all options
- [Contributing](../CONTRIBUTING.md) -- Contribution guidelines
- [Security Policy](../SECURITY.md) -- Vulnerability reporting
- [Changelog](../CHANGELOG.md) -- Version history
