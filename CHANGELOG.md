# Changelog

All notable changes to the Prompt Injection Firewall will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] - 2026-03-07

### Added

- **Phase 2 Finalization**
  - Prometheus metrics endpoint (`GET /metrics`) and dashboard assets
  - Client rate limiting and adaptive threshold controls
  - Kubernetes validating admission webhook (`cmd/webhook`) and deployment manifests
  - Phase 2 finalization report with local/CI-dry-run/docker/kind smoke evidence:
    `docs/PHASE2_FINALIZATION_REPORT.md`

### Changed

- Restored official CLI entrypoint at `cmd/pif-cli` (`pif` command surface).
- Build/release/docker paths split between `cmd/pif-cli` and `cmd/firewall`.
- Go toolchain references in CI and Docker upgraded to `1.25.x` / `1.25`.

## [1.1.0] - 2026-02-24

### Added

- **ML-Powered Semantic Detection**
  - Fine-tuned DistilBERT classifier for prompt injection detection
  - ONNX export with INT8 dynamic quantization (~65MB model)
  - Go MLDetector implementation using `knights-analytics/hugot` ONNX Runtime
  - Build tag system (`-tags ml`) keeps default builds unchanged (no CGO)
  - Automatic fallback to regex-only when ML is unavailable

- **Hybrid Ensemble Engine**
  - Weighted scoring: regex (0.6) + ML (0.4) for balanced detection
  - ML confidence mapped to PIF severity levels (≥0.95 critical, ≥0.90 high, ≥0.85 medium, ≥0.75 low)
  - `HasMLDetector()` method for runtime ML status checking
  - `ParseStrategy()` helper for string-to-strategy conversion

- **Python Training Pipeline** (`ml/`)
  - `train.py` — fine-tune DistilBERT on `deepset/prompt-injections` dataset
  - `export_onnx.py` — ONNX export + INT8 quantization via Optimum
  - `evaluate.py` — standalone evaluation with per-category breakdown
  - Training documentation with HuggingFace Hub upload instructions

- **CLI Enhancements**
  - `--model` / `-m` flag for scan and proxy commands
  - ML status display in proxy startup output
  - Detector count and strategy display

- **Build & Deployment**
  - `deploy/docker/Dockerfile.ml` — ML-enabled Docker image with ONNX Runtime
  - CI `test-ml` job for ONNX Runtime tests (conditional)
  - `.gitignore` updated for ONNX models and Python artifacts

### Changed

- Default ensemble strategy changed from `any` to `weighted`
- Default detection timeout increased from 45ms to 100ms (accommodates ML inference)
- Configuration expanded with `ml_model_path`, `ml_threshold`, and `weights` fields

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

[Unreleased]: https://github.com/ogulcanaydogan/Prompt-Injection-Firewall/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/ogulcanaydogan/Prompt-Injection-Firewall/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/ogulcanaydogan/Prompt-Injection-Firewall/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/ogulcanaydogan/Prompt-Injection-Firewall/releases/tag/v1.0.0
