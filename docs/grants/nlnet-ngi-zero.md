# NLnet NGI Zero Grant Proposal

**Grant Programme:** NGI Zero Core / NGI Zero Review
**Funding Body:** NLnet Foundation, funded by the European Commission (Next Generation Internet initiative)
**URL:** https://nlnet.nl/propose/
**Funding Range:** EUR 5,000 to 50,000
**Application Deadline:** 1 April 2026
**Applicant:** Ogulcan Aydogan
**Project:** Prompt Injection Firewall (PIF)
**Repository:** https://github.com/ogulcanaydogan/Prompt-Injection-Firewall
**License:** Apache 2.0

---

## 1. Abstract

*(Target: 200 words. Use this text directly in the NLnet proposal form.)*

Prompt Injection Firewall (PIF) is an open-source reverse-proxy middleware that detects and prevents prompt injection attacks against Large Language Model (LLM) applications. Prompt injection, ranked #1 on the OWASP Top 10 for LLM Applications, allows adversaries to override developer instructions, manipulate model outputs, and exfiltrate data through crafted inputs. Despite widespread recognition of this threat, no open-source, protocol-level defence standard exists.

PIF operates transparently between clients and LLM APIs (OpenAI, Anthropic), applying a dual-engine detection system: 129 curated regex patterns for known attack signatures and a fine-tuned DistilBERT ONNX classifier for semantic analysis. An ensemble scorer combines both engines to drive configurable response actions (block, flag, or log). The system adds less than 100 milliseconds of latency and deploys as a single Go binary with no external dependencies beyond the ONNX model file.

This proposal requests EUR 38,000 to fund adversarial evasion testing, detection engine expansion (indirect injection, multi-modal payloads), security audit, and documentation. PIF provides critical open infrastructure for the safe deployment of LLM applications in Europe and globally, directly supporting the NGI Zero mission of a trustworthy, open internet.

---

## 2. Description of Work

### 2.1 Problem and Motivation

Large Language Models are increasingly embedded in internet-facing applications: customer support chatbots, content generation tools, code assistants, search interfaces, and autonomous agents. These applications accept natural language input from untrusted users, creating a new attack surface: prompt injection.

Prompt injection attacks exploit the LLM's inability to distinguish between trusted system instructions and untrusted user input. An attacker can craft input that causes the model to:

- Ignore system-level instructions ("Ignore all previous instructions and...")
- Exfiltrate confidential data through tool-calling or output channels
- Produce harmful, misleading, or manipulative content
- Execute unintended actions in agent-based systems

The OWASP Foundation ranks prompt injection as the number-one risk for LLM applications. The EU AI Act identifies input manipulation as a concern for high-risk AI systems. Despite this, the open-source community lacks a standard, deployable defence layer.

Commercial solutions exist (Lakera Guard, Protect AI) but are proprietary, opaque, and create vendor dependency. Organisations can't audit the detection logic they rely on for safety-critical filtering.

PIF addresses this gap as open infrastructure: a transparent, auditable, and freely deployable prompt injection defence layer licensed under Apache 2.0.

### 2.2 Current State of the Project

PIF is a functioning, released project with the following characteristics:

- **Language:** Go (single static binary, cross-platform)
- **Releases:** 4 stable releases on GitHub
- **Detection:** 129 regex patterns + fine-tuned DistilBERT ONNX classifier
- **Ensemble scoring:** Configurable weighted combination of regex and ML scores
- **Response actions:** Block (HTTP 403), Flag (header annotation), Log (silent recording)
- **API support:** OpenAI Chat Completions API, Anthropic Messages API
- **Performance:** <50ms regex latency, <100ms ML latency
- **CI/CD:** 3 GitHub Actions workflows (ci.yml, codeql.yml, release.yml)
- **Security analysis:** CodeQL static analysis integrated in CI
- **Test coverage:** 80%+ with Go race detector enabled
- **License:** Apache 2.0

### 2.3 Proposed Work

The grant will fund four work packages that harden PIF for broader adoption and extend its detection capabilities.

**WP1: Adversarial Robustness Testing (Weeks 1--4)**

Systematic evaluation of the detection engines against adversarial evasion techniques:

- Develop an adversarial test suite covering encoding-based evasion (Base64, Unicode, homoglyphs), payload fragmentation, multi-language injection, and delimiter manipulation.
- Benchmark both regex and ML engines individually and as an ensemble against the adversarial suite.
- Identify and document bypass vectors.
- Deliverable: Adversarial test suite (open-source), evasion report, baseline metrics.

**WP2: Detection Engine Expansion (Weeks 3--8)**

Extend detection capabilities to cover emerging attack vectors:

- **Indirect prompt injection patterns:** Detection of injected instructions in retrieved documents (RAG pipelines), tool outputs, and multi-turn conversation histories.
- **Encoding and obfuscation patterns:** Additional regex patterns for Base64-encoded payloads, Unicode confusables, zero-width character insertion, and mixed-script attacks.
- **ML model retraining:** Adversarial training using payloads from WP1. Evaluation on held-out test sets to ensure benign accuracy is maintained.
- Deliverable: Updated regex pattern set, retrained ONNX model, evaluation report.

**WP3: Security Audit (Weeks 6--10)**

Independent security review of the codebase:

- Audit scope: proxy request handling, regex engine, ML inference pipeline, configuration parsing, input validation, error handling.
- Focus on vulnerabilities that could allow detection bypass, denial of service, or information leakage.
- Deliverable: Audit report, remediated codebase, verification by auditor.

**WP4: Documentation and Integration (Weeks 8--12)**

Full documentation to lower the barrier to adoption:

- Deployment guides for common patterns (Docker, Kubernetes sidecar, API gateway integration).
- Threat model documentation explaining what PIF defends against and its limitations.
- Operator guide for tuning detection thresholds and configuring response actions.
- Integration guide for additional LLM providers beyond OpenAI and Anthropic.
- Deliverable: Published documentation on GitHub, updated project README.

---

## 3. Budget

**Total Requested: EUR 38,000**

| Work Package | Cost (EUR) | Justification |
|-------------|-----------|---------------|
| WP1: Adversarial Robustness Testing | 8,000 | Development of adversarial test suite, benchmarking, evasion analysis. Approximately 4 weeks of effort. |
| WP2: Detection Engine Expansion | 12,000 | Regex pattern development, ML dataset curation, model retraining, compute costs for training runs, evaluation. Approximately 6 weeks of effort. |
| WP3: Security Audit | 13,000 | Engagement of independent security reviewer. Includes audit execution, report, and remediation verification. |
| WP4: Documentation | 5,000 | Technical writing for deployment guides, threat model, operator documentation. Approximately 3 weeks of effort. |
| **Total** | **38,000** | |

*Note: NLnet disburses funds upon milestone completion. Budget items above map directly to milestones in Section 4.*

---

## 4. Milestones

NLnet grants are structured around milestone-based disbursement. The following milestones correspond to the work packages above.

| # | Milestone | Deliverable | Completion | Payment (EUR) |
|---|-----------|-------------|------------|---------------|
| M1 | Adversarial test suite complete | Open-source test suite on GitHub; evasion report published | Week 4 | 8,000 |
| M2 | Detection engine expansion | Updated regex patterns merged; retrained ONNX model released; evaluation report | Week 8 | 12,000 |
| M3 | Security audit complete | Audit report delivered; all critical/high findings remediated; verification confirmed | Week 10 | 13,000 |
| M4 | Documentation published | All deployment guides, threat model, and operator docs published on GitHub | Week 12 | 5,000 |

---

## 5. Relevance to NGI Zero

### 5.1 Open Internet Infrastructure

PIF is open infrastructure for securing the next generation of internet applications. As LLMs become embedded in web services, search engines, customer-facing tools, and autonomous agents, the ability to defend against input manipulation becomes a foundational internet safety requirement. PIF provides this defence as a public good, freely available under Apache 2.0.

### 5.2 User Autonomy and Trust

Prompt injection attacks undermine user trust in LLM-powered services. When a chatbot can be manipulated to produce false information, override its safety guidelines, or exfiltrate user data, the end user bears the consequences. PIF protects end users by ensuring that LLM applications behave as their developers intended, preserving the trust relationship between users and services.

### 5.3 No Vendor Lock-In

Unlike proprietary alternatives, PIF doesn't create dependency on a commercial vendor for safety-critical filtering. Organisations can inspect, modify, and extend every detection rule and the ML model. This transparency is essential for trust in security tooling and aligns with NLnet's commitment to open, auditable technology.

### 5.4 European AI Safety

The EU AI Act identifies input manipulation as a concern for high-risk AI systems. PIF provides a concrete, deployable mitigation that organisations can use to demonstrate due diligence in defending against prompt injection, supporting compliance with European regulatory expectations.

---

## 6. NLnet Automatic Audit Support

NLnet provides access to automatic audit and review services for funded projects. PIF will take advantage of the following:

- **Security audit support:** NLnet can facilitate connection with security auditors through its network, potentially reducing the cost and procurement overhead for WP3.
- **Accessibility review:** Since PIF is a backend middleware (not a user-facing application), documentation and configuration interfaces will be reviewed for accessibility instead.
- **Licensing and compliance review:** Verification that all dependencies and the ONNX model comply with Apache 2.0 licensing and NLnet's open-source requirements.

---

## 7. Technical Specifications

| Attribute | Value |
|-----------|-------|
| Programming Language | Go 1.21+ |
| ML Runtime | ONNX Runtime (C library, CGo bindings) |
| ML Model | DistilBERT (fine-tuned, 66M parameters) |
| Binary Size | ~15 MB (excluding ONNX model) |
| ONNX Model Size | ~260 MB |
| Configuration | YAML file or environment variables |
| Deployment | Static binary, Docker image, Kubernetes sidecar |
| Supported APIs | OpenAI Chat Completions, Anthropic Messages |
| Detection Latency | <50ms (regex), <100ms (ML), <120ms (ensemble) |
| Dependencies | Go standard library, ONNX Runtime, YAML parser |

---

## 8. Comparison with Existing Solutions

| Feature | PIF | Lakera Guard | Protect AI | Rebuff |
|---------|-----|-------------|------------|--------|
| Open source | Yes (Apache 2.0) | No | Partial | Yes |
| Deployment model | Self-hosted proxy | Cloud API | Cloud/on-prem | Library |
| Regex detection | 129 patterns | Unknown (proprietary) | Unknown | No |
| ML detection | DistilBERT ONNX | Proprietary model | Proprietary | GPT-based |
| Ensemble scoring | Yes | Unknown | Unknown | No |
| Configurable actions | Block/Flag/Log | Block/Allow | Block/Allow | Block/Allow |
| Latency overhead | <100ms | ~200ms (network) | Variable | ~1s (LLM call) |
| Auditable rules | Yes | No | No | N/A |
| No vendor dependency | Yes | No | No | Partial |

---

## 9. Applicant Information

**Name:** Ogulcan Aydogan
**Role:** Independent developer and researcher
**Location:** United Kingdom
**GitHub:** https://github.com/ogulcanaydogan
**Hugging Face:** https://huggingface.co/ogulcanaydogan

Relevant experience:
- Creator and maintainer of Prompt Injection Firewall (4 releases)
- Experience in LLM fine-tuning (SFT, DPO) for multilingual NLP
- Go systems programming, ONNX runtime integration
- CI/CD pipeline design with GitHub Actions, CodeQL, and static analysis

---

## 10. Submission Checklist

- [ ] Create account on NLnet proposal portal: https://nlnet.nl/propose/
- [ ] Complete the online form with the following field mapping:
  - "Abstract" --> Section 1 of this document (200 words)
  - "Describe the project" --> Section 2
  - "Budget" --> Section 3
  - "Milestones" --> Section 4
  - "Relevance" --> Section 5
- [ ] Provide repository URL: https://github.com/ogulcanaydogan/Prompt-Injection-Firewall
- [ ] Confirm Apache 2.0 license compatibility with NLnet requirements
- [ ] Submit before 1 April 2026 deadline

---

## 11. Notes on NLnet Process

- NLnet proposals are reviewed by an independent committee. Decisions typically take 2--3 months.
- Funding is disbursed in milestones. Each milestone must be completed and verified before the next payment.
- NLnet provides mentoring, audit support, and connections to the NGI ecosystem as part of the grant.
- All funded work must be released under an OSI-approved open-source license (Apache 2.0 qualifies).
- NLnet may request modifications to milestones or budget during the review process.

---

*Document prepared for NLnet NGI Zero proposal submission. Last updated: March 2026.*
