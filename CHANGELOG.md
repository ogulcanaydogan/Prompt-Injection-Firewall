# Changelog

All notable changes to the Prompt Injection Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-02-24

### Added

- **Detection Engine**
  - 129 regex-based detection patterns across 10 attack categories
  - Ensemble detector with 3 aggregation strategies (any-match, majority, weighted)
  - Per-message scanning with role-aware context
  - Configurable severity levels (info, low, medium, high, critical)
  - SHA-256 input hashing for audit trails and deduplication
  - Threat scoring with adjustable thresholds

- **CLI Tool**
  - `pif scan` command for scanning prompts from args, files, or stdin
  - JSON and table output formats
  - Quiet mode with exit codes (0=clean, 1=injection, 2=error)
  - Verbose mode with match offsets and descriptions
  - Severity filtering
  - `pif rules list` and `pif rules validate` commands
  - `pif version` command

- **Proxy Server**
  - Transparent HTTP reverse proxy for OpenAI and Anthropic APIs
  - Auto-detection of API request format
  - Three response actions: block (403), flag (headers), log (passthrough)
  - Health check endpoint (`GET /healthz`)
  - Configurable timeouts and body size limits

- **Detection Rules**
  - `owasp-llm-top10.yaml` -- 24 rules mapped to OWASP LLM Top 10 (2025)
  - `jailbreak-patterns.yaml` -- 87 jailbreak and injection rules
  - `data-exfil.yaml` -- 18 data exfiltration and encoding rules

- **OWASP LLM Top 10 Coverage**
  - Full coverage: LLM01, LLM02, LLM05, LLM07, LLM10
  - Partial coverage: LLM03, LLM04, LLM06, LLM08, LLM09

- **Deployment**
  - Multi-stage Docker build with distroless image
  - Docker Compose configuration
  - Non-root execution
  - Environment variable overrides (`PIF_*` prefix)

- **Quality**
  - 84.6% test coverage with race condition detection
  - CI/CD pipeline (lint, test, benchmark, multi-platform build)
  - golangci-lint with strict rules
  - Accuracy benchmarks (100% detection rate, 0% false positive rate on test set)

- **Documentation**
  - Integration guide for Python, Node.js, Go, and cURL
  - API reference with request/response formats
  - Rule development guide
  - Integration examples for Python, Node.js, cURL, and Docker

[1.0.0]: https://github.com/ogulcanaydogan/Prompt-Injection-Firewall/releases/tag/v1.0.0
