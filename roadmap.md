# Roadmap

## Current: v1.3.0

Real-time prompt injection detection and prevention middleware for LLM applications. 129 regex detection patterns + DistilBERT ONNX classifier. Multi-tenant, replay forensics, Webhook/Slack/PagerDuty alerting. Patterns mapped to OWASP LLM Top 10.

---

## v1.4.0 — OWASP Coverage Closure (Q2 2026)

- [ ] Close partial OWASP LLM03 (Training Data Poisoning) coverage with dedicated rule set
- [ ] Close partial OWASP LLM04 (Model Denial of Service) — rate-limiting + complexity detectors
- [x] Close partial OWASP LLM06 (Sensitive Information Disclosure) — output scanning rules
- [ ] Close partial OWASP LLM08 (Excessive Agency) — action scope boundary checks
- [ ] Close partial OWASP LLM09 (Overreliance) — confidence-score gating
- [ ] Expanded `marketplace/` rules pack (community-submittable YAML descriptors)

**Target branch**: `feature/v1.4.0-owasp-closure`

---

## v1.5.0 — ML Model Refresh (Q3 2026)

- [ ] DistilBERT retrain on current public injection datasets (Gandalf, Lakera, HackAPrompt)
- [ ] Publish retrained ONNX artifact as a versioned GitHub release asset
- [ ] Multilingual injection detection: French, German, Turkish base coverage
- [ ] False-positive benchmark suite with human-labelled clean prompts

---

## v2.0.0 — Threat Intel Integration (Q4 2026)

- [ ] Real-time threat intel feed: subscribe to community-reported injection pattern updates
- [ ] Declarative policy language for composing multi-stage detection pipelines
- [ ] WASM plugin API for custom detectors without recompiling the core binary
- [ ] eBPF probe variant for kernel-level interception in high-throughput environments

---

## Known issues / backlog

See [open issues](https://github.com/ogulcanaydogan/Prompt-Injection-Firewall/issues).
