# OpenAI Cybersecurity Grant Application

| Field | Value |
|-------|-------|
| **URL** | https://openai.com/form/cybersecurity-grant-program |
| **Amount** | $1M grants pool + $10M API credits pool |
| **Deadline** | Rolling |
| **Project** | Prompt-Injection-Firewall |
| **Applicant** | Ogulcan Aydogan |

---

## Project Title

Prompt Injection Firewall: Runtime Detection and Blocking of LLM Prompt Injection Attacks

## Project Description

Prompt-Injection-Firewall is an open-source Go runtime firewall that detects and blocks prompt injection attacks against LLM applications. It sits between user input and the LLM API, scanning requests against configurable detection rules covering the OWASP LLM Top 10. The firewall supports direct injection, indirect injection, jailbreak attempts, role manipulation, and encoding-based evasion techniques.

The project ships as a single Go binary with 4 releases, CodeQL security scanning in CI, and can be deployed as a standalone proxy or a Kubernetes sidecar container. Detection rules are YAML-configurable with severity levels, and the firewall supports allow/deny lists, rate limiting, and structured logging for security monitoring.

## How does this project advance AI cybersecurity?

1. Prompt injection is the #1 risk on the OWASP LLM Top 10. As more applications expose LLMs to user input, injection attacks will become the SQL injection of the AI era. This firewall provides a dedicated defense layer that catches manipulation attempts before they reach the model.

2. The firewall detects multiple attack vectors: direct prompt override, indirect injection via retrieved context, jailbreak patterns, role/system prompt manipulation, and encoding tricks (base64, unicode, leetspeak). Each detection rule has a configurable severity and action (log, block, alert).

3. Unlike prompt-level defenses that depend on the model's own instruction following, this operates at the infrastructure level. It doesn't matter which model you're using, the firewall catches known patterns before the request is forwarded.

4. The project integrates with OpenAI's API directly. Applications using the OpenAI SDK can route through the firewall proxy by changing one URL. No code changes needed.

5. All detection patterns are open source and community-auditable. Security teams can review, modify, and contribute rules rather than trusting a black-box detection service.

## Specific use of funding

**Detection engine expansion ($15,000-25,000):**
- Add ML-based detection alongside rule-based patterns (fine-tuned classifier for injection vs legitimate prompts)
- Expand evasion technique coverage (homoglyph attacks, token boundary manipulation, multi-turn injection)
- Build a public benchmark dataset for prompt injection detection accuracy

**Security audit ($10,000-15,000):**
- Independent audit of the firewall's bypass resistance
- Red-team exercise against the detection rules
- Audit of the proxy's request handling (no data leaks, proper TLS termination)

**OpenAI API integration ($5,000-10,000):**
- Native OpenAI SDK middleware for Python and Node.js
- Real-time detection metrics compatible with OpenAI's usage dashboard
- Documentation and tutorials for OpenAI API users

**API credits ($10,000):**
- Benchmark the firewall against adversarial prompts using GPT-4 and o1
- Generate synthetic injection datasets for training the ML classifier
- Test detection accuracy across different OpenAI models

## Team

Ogulcan Aydogan, sole developer and maintainer. Software engineer with background in LLM infrastructure and AI security. Built the complete firewall: detection engine, proxy, rule system, CI pipeline (CodeQL, unit tests), and deployment configurations. Based in the United Kingdom.

## Repository

https://github.com/ogulcanaydogan/Prompt-Injection-Firewall

## Requested Amount

$25,000 grant + $10,000 API credits

---

## Submission Steps

1. Go to https://openai.com/form/cybersecurity-grant-program
2. Fill in form fields using responses above
3. Submit (rolling deadline)
4. Record confirmation and update tracker

---

*Last updated: 2026-03-14*
