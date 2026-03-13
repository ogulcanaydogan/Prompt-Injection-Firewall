# AISI Challenge Fund Application

**Grant Programme:** AISI Challenge Fund
**Funding Body:** UK AI Safety Institute (AISI), Department for Science, Innovation and Technology
**URL:** https://find-government-grants.service.gov.uk/grants/aisi-challenge-fund-1
**Funding Range:** GBP 50,000 -- 200,000
**Application Deadline:** 31 March 2026
**Applicant:** Ogulcan Aydogan
**Repository:** https://github.com/ogulcanaydogan/Prompt-Injection-Firewall
**License:** Apache 2.0

---

## 1. Project Title

**PIF: Open Source Prompt Injection Defense for Safe LLM Deployment**

---

## 2. Executive Summary

Prompt Injection Firewall (PIF) is an open-source, transparent reverse-proxy security middleware that detects and prevents prompt injection attacks targeting Large Language Model (LLM) applications in real time. The project addresses the number-one risk on the OWASP Top 10 for LLM Applications: prompt injection, a class of attack in which adversarial inputs manipulate LLM behaviour to override developer instructions, exfiltrate data, or produce harmful outputs.

PIF operates as a drop-in proxy layer between client traffic and LLM provider APIs (OpenAI, Anthropic). It employs a dual-engine detection architecture combining 129 curated regex patterns with a fine-tuned DistilBERT ONNX classifier, producing ensemble scores that drive configurable response actions (block, flag, or log). The system achieves sub-50ms regex latency and sub-100ms ML latency, making it viable for production deployments where added overhead must be minimal.

This application requests GBP 65,000 to fund a professional security audit of the detection engine, adversarial red-teaming of the ML classifier, model hardening against evasion techniques, and comprehensive documentation to accelerate adoption by organisations deploying LLM-powered services in the UK and internationally.

---

## 3. Problem Statement

### 3.1 The Threat Landscape

Prompt injection is classified as the **#1 risk** in the OWASP Top 10 for Large Language Model Applications (2023, reaffirmed 2025). Unlike traditional injection attacks (SQL injection, XSS), prompt injection exploits the fundamental architecture of LLMs: the inability to reliably distinguish between trusted instructions and untrusted user input within the same context window.

Attack vectors include:

- **Direct prompt injection:** Adversarial text in user messages that overrides system prompts, causing the LLM to ignore developer-defined constraints.
- **Indirect prompt injection:** Malicious instructions embedded in external data sources (documents, web pages, tool outputs) that the LLM processes during retrieval-augmented generation (RAG).
- **Payload smuggling:** Encoded, obfuscated, or multi-language injection payloads designed to bypass naive keyword filters.

### 3.2 The Defence Gap

Despite prompt injection being widely recognised as a critical risk, the ecosystem lacks:

1. **No open standard defence middleware.** Most mitigation advice consists of prompt engineering best practices ("defence in depth" system prompts), which are necessary but insufficient. There is no widely adopted, protocol-level defence layer analogous to a Web Application Firewall (WAF) for LLM traffic.

2. **Vendor lock-in for detection.** Commercial solutions exist (Lakera Guard, Protect AI, Robust Intelligence) but are proprietary, opaque in their detection logic, and introduce vendor dependency. Organisations cannot audit the detection rules they rely on.

3. **Latency-sensitivity mismatch.** Academic detectors (perplexity-based methods, large classifier models) often add hundreds of milliseconds or require GPU inference, making them impractical as inline middleware for production API traffic.

4. **No configurable response policy.** Existing tools typically offer a binary block/allow decision. Production systems need graduated responses: logging for monitoring, flagging for human review, and blocking for high-confidence threats.

### 3.3 Consequences of Inaction

Without effective prompt injection defence, LLM-powered applications are vulnerable to:

- Extraction of confidential system prompts and proprietary instructions
- Manipulation of LLM outputs in customer-facing applications (chatbots, support agents, content generation)
- Data exfiltration through tool-use and function-calling channels
- Reputational and regulatory risk for organisations deploying LLM services

---

## 4. Technical Approach

### 4.1 Architecture Overview

PIF is a transparent reverse-proxy written in Go. It intercepts HTTP requests destined for LLM provider APIs, inspects the content of user messages, applies detection, and either forwards the request (clean or flagged) or returns a configurable block response.

```
Client --> [PIF Reverse Proxy] --> LLM Provider API (OpenAI / Anthropic)
                |
                v
         Detection Engine
         ├── Regex Engine (129 patterns)
         ├── ML Engine (DistilBERT ONNX)
         └── Ensemble Scorer
                |
                v
         Action Policy (block / flag / log)
```

### 4.2 Detection Engines

**Regex Engine**

- 129 curated regular expression patterns organised by attack category (direct injection, role hijacking, instruction override, encoding-based evasion, delimiter abuse, multi-language injection).
- Patterns are compiled once at startup and evaluated concurrently.
- Sub-50ms latency for full pattern evaluation against typical message lengths.
- Transparent and auditable: every pattern is documented with a rationale and example payload.

**ML Engine**

- Fine-tuned DistilBERT classifier exported to ONNX format for CPU inference without Python or GPU dependencies.
- Binary classification: benign vs. injection.
- Sub-100ms inference latency on commodity hardware.
- Trained on curated datasets of injection payloads and benign prompts, with adversarial augmentation.

**Ensemble Scoring**

- Configurable weighting between regex and ML scores.
- Threshold-based action mapping: scores above the block threshold trigger rejection; scores in the flag range annotate the request with metadata headers; scores below the log threshold are recorded silently.
- Operators can tune thresholds per deployment to balance security posture against false-positive tolerance.

### 4.3 Response Actions

| Action | Behaviour | Use Case |
|--------|-----------|----------|
| **Block** | Returns HTTP 403 with configurable error body. Request is not forwarded. | High-confidence injection. Production enforcement. |
| **Flag** | Forwards request with `X-PIF-Flagged: true` header and metadata. | Medium-confidence. Human review workflows. |
| **Log** | Forwards request unchanged. Detection result logged. | Monitoring, baseline collection, audit trails. |

### 4.4 API Format Support

PIF parses and inspects message payloads for both OpenAI Chat Completions API format and Anthropic Messages API format. Format detection is automatic based on request structure and target endpoint. This covers the two most widely deployed commercial LLM APIs.

### 4.5 Deployment Model

- Single static binary (Go). No runtime dependencies beyond the ONNX model file.
- Configuration via YAML file or environment variables.
- Docker image available for containerised deployments.
- Designed for sidecar or gateway deployment patterns in Kubernetes environments.

---

## 5. Safety Impact and Alignment with AISI Mission

### 5.1 Direct Safety Impact

PIF directly contributes to the safe deployment of LLM applications by:

1. **Preventing manipulation of LLM outputs.** By intercepting adversarial inputs before they reach the model, PIF ensures that LLM behaviour remains within developer-defined constraints.

2. **Protecting end users.** In consumer-facing applications (customer support chatbots, content assistants, educational tools), prompt injection can cause the LLM to produce misleading, harmful, or manipulative outputs. PIF acts as a safety layer between users and the model.

3. **Enabling graduated response.** The block/flag/log action model allows organisations to deploy detection in monitoring mode first, build confidence in detection accuracy, and then progressively tighten enforcement, reducing the barrier to adoption.

4. **Providing transparency.** As an open-source project under Apache 2.0, every detection rule and the ML model architecture are fully auditable. This aligns with the principle that safety-critical infrastructure should be inspectable.

### 5.2 Alignment with AISI Objectives

The UK AI Safety Institute's mandate includes developing tools and techniques for evaluating and mitigating risks from AI systems. PIF aligns with this mission in the following ways:

- **Practical, deployable safety tooling.** PIF is not a research prototype; it is production-grade middleware with 4 releases, CI/CD pipelines, and documented integration guides. AISI funding would harden it for broader adoption.

- **Open infrastructure for the ecosystem.** An open-source prompt injection defence layer benefits the entire UK AI ecosystem, from startups building LLM applications to enterprises deploying AI in regulated sectors (financial services, healthcare, government).

- **Defence against a well-characterised risk.** Prompt injection is not a speculative risk; it is actively exploited. OWASP, NIST, and the EU AI Act all identify input manipulation as a priority concern. PIF provides a concrete mitigation.

- **Complementary to model-level safety.** PIF operates at the infrastructure layer, complementing model-level alignment techniques (RLHF, constitutional AI). Defence in depth requires both model-level and infrastructure-level protections.

---

## 6. Current Status

| Metric | Value |
|--------|-------|
| Language | Go |
| Releases | 4 (stable) |
| Regex Patterns | 129 curated |
| ML Model | DistilBERT ONNX (fine-tuned) |
| CI Workflows | 3 (ci.yml, codeql.yml, release.yml) |
| Static Analysis | CodeQL (integrated in CI), golangci-lint |
| Test Coverage | 80%+ with race detector enabled |
| License | Apache 2.0 |
| API Support | OpenAI Chat Completions, Anthropic Messages |
| Detection Latency | <50ms regex, <100ms ML |
| Response Actions | Block, Flag, Log |

---

## 7. Budget

**Total Requested: GBP 65,000**

| Line Item | Cost (GBP) | Description |
|-----------|-----------|-------------|
| Security Audit of Detection Engine | 30,000 | Independent third-party security audit of the regex engine, ML inference pipeline, proxy request handling, and configuration parsing. Includes audit report and remediation verification. Vendor: to be selected from CREST-accredited firms or equivalent. |
| Adversarial Testing Red Team | 15,000 | Engagement of a specialised red team to develop novel prompt injection payloads targeting PIF's detection engines. Goal: identify bypass vectors, measure false-negative rates under adversarial conditions, and produce a categorised evasion report. |
| ML Model Hardening | 12,000 | Adversarial training of the DistilBERT classifier using payloads identified during red-teaming. Includes dataset curation, retraining, evaluation on held-out adversarial test sets, and ONNX model re-export. Covers compute costs for training runs. |
| Documentation and Adoption Materials | 8,000 | Comprehensive deployment guides for common infrastructure patterns (Kubernetes sidecar, API gateway, Docker Compose). Threat model documentation. Integration guides for additional LLM providers. Operator runbooks for tuning detection thresholds. |
| **Total** | **65,000** | |

---

## 8. Project Timeline

**Duration: 14 weeks**

| Week | Activity | Deliverable |
|------|----------|-------------|
| 1--2 | Security audit scoping and vendor selection | Signed statement of work with audit firm |
| 3--6 | Security audit execution | Draft audit report |
| 4--7 | Red team engagement (overlaps with audit) | Adversarial payload dataset and evasion report |
| 7--8 | Audit remediation | Patched codebase; verification by auditor |
| 8--11 | ML model hardening (adversarial retraining) | Updated ONNX model with evaluation metrics |
| 9--12 | Documentation and integration guides | Published documentation on GitHub |
| 12--13 | Integration testing of hardened system | Regression test results; updated CI |
| 14 | Final report and public release | v2.0 release with audit attestation; final grant report |

---

## 9. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Audit identifies critical vulnerabilities | Medium | High | Budget includes remediation time (Weeks 7--8). Responsible disclosure policy already in place. |
| Red team discovers fundamental bypass class | Low | High | ML hardening phase specifically addresses adversarial evasion. Ensemble architecture provides defence in depth. |
| ML retraining degrades benign accuracy | Medium | Medium | Evaluation on held-out benign test set before model promotion. A/B comparison with current model. |
| Timeline slippage due to audit vendor scheduling | Medium | Low | Vendor engagement begins Week 1. Buffer built into Week 12--13 integration phase. |

---

## 10. Applicant Background

**Ogulcan Aydogan** is a software engineer and machine learning practitioner with experience in NLP, LLM fine-tuning, and systems programming. Relevant experience includes:

- Development and maintenance of PIF from inception through 4 production releases
- Fine-tuning of language models (SFT, DPO) for multilingual NLP tasks
- Experience with Go systems programming, ONNX runtime integration, and CI/CD pipeline design
- Open-source contributor with published models on Hugging Face

---

## 11. Supporting Materials Checklist

Before submission, ensure the following materials are prepared:

- [ ] Completed application form on the AISI Challenge Fund portal
- [ ] Project summary (this document, adapted to form fields)
- [ ] Link to public GitHub repository: https://github.com/ogulcanaydogan/Prompt-Injection-Firewall
- [ ] Budget breakdown (Section 7 of this document)
- [ ] Timeline (Section 8 of this document)
- [ ] CV / resume of applicant
- [ ] Evidence of current project status (release tags, CI dashboard, test coverage report)
- [ ] Letter of support (if available; e.g., from an organisation that has evaluated or deployed PIF)
- [ ] Bank account details for grant disbursement (UK bank account required)

---

## 12. Submission Steps

1. **Register** on the Find a Government Grant portal: https://find-government-grants.service.gov.uk/
2. **Navigate** to the AISI Challenge Fund listing: https://find-government-grants.service.gov.uk/grants/aisi-challenge-fund-1
3. **Complete** the online application form, mapping sections of this document to the form fields:
   - "Describe your project" --> Sections 2, 3, 4
   - "What is the expected impact?" --> Section 5
   - "Budget and resources" --> Section 7
   - "Project plan and milestones" --> Section 8
   - "Risk assessment" --> Section 9
4. **Upload** supporting documents (CV, repository evidence, budget spreadsheet if required)
5. **Review** all entries for completeness and accuracy
6. **Submit** before 23:59 BST on 31 March 2026

---

## 13. Key Messages for Reviewers

When adapting this document for form fields with character limits, prioritise the following points:

1. **Prompt injection is the #1 LLM security risk** (OWASP Top 10 for LLM Applications). It is not theoretical; it is actively exploited.
2. **No open standard defence exists.** PIF fills a critical gap in the AI safety toolchain.
3. **PIF is production-ready, not a research prototype.** Four releases, CI/CD, 80%+ test coverage, sub-100ms latency.
4. **The grant funds hardening, not creation.** The core system exists and works. Funding enables independent security validation and adversarial robustness testing.
5. **Open source maximises impact.** Apache 2.0 licensing ensures any UK organisation can adopt PIF without vendor lock-in or licensing barriers.
6. **Direct alignment with AISI mandate.** PIF is practical, deployable AI safety infrastructure that protects end users from LLM manipulation.

---

*Document prepared for AISI Challenge Fund application. Last updated: March 2026.*
