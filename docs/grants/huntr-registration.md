# Huntr Bug Bounty Registration Guide for Prompt Injection Firewall

**Platform:** Huntr (https://huntr.com/)
**Purpose:** Register PIF on Huntr's bug bounty platform to enable coordinated vulnerability disclosure by the security research community
**Repository:** https://github.com/ogulcanaydogan/Prompt-Injection-Firewall
**License:** Apache 2.0

---

## 1. Overview

Huntr is a bug bounty platform focused on open-source software. By registering Prompt Injection Firewall on Huntr, the project gains:

- A structured channel for security researchers to report vulnerabilities
- Triage support from Huntr's security team
- Incentivised security testing by the research community (Huntr provides bounties)
- Public acknowledgement of the project's commitment to security
- CVE assignment for confirmed vulnerabilities

This is particularly valuable for PIF because it's security middleware: vulnerabilities in PIF directly translate to vulnerabilities in every application that depends on it for protection.

---

## 2. Scope Definition

The scope defines what Huntr researchers should and should not test. A clear scope reduces noise from out-of-scope reports and focuses researcher effort on the most impactful areas.

### 2.1 In-Scope Components

The following directories and components are in scope for vulnerability reports.

| Component | Directory | Description | Priority |
|-----------|-----------|-------------|----------|
| **CLI and entry point** | `cmd/` | Application startup, argument parsing, signal handling | Medium |
| **Detection engines** | `pkg/detector/` | Regex engine, ML engine, ensemble scoring, pattern matching | **Critical** |
| **Proxy layer** | `pkg/proxy/` | HTTP reverse proxy, request/response handling, header manipulation, forwarding logic | **Critical** |
| **Configuration** | `pkg/config/` | YAML parsing, environment variable processing, validation, default values | High |
| **Internal utilities** | `internal/` | Shared internal packages, logging, error handling | Medium |

### 2.2 Out-of-Scope Components

The following are explicitly out of scope. Reports against these components will be closed as informational.

| Component | Directory | Reason |
|-----------|-----------|--------|
| **Example configurations** | `examples/` | Demonstration files, not production code |
| **Documentation** | `docs/` | Static content, no executable code |
| **Test files** | `tests/`, `*_test.go` | Test infrastructure, not shipped in production binary |
| **CI/CD workflows** | `.github/` | Infrastructure configuration; report via GitHub Security Advisories instead |
| **Third-party dependencies** | `vendor/`, `go.sum` | Report upstream to the dependency maintainer |

### 2.3 In-Scope Vulnerability Types

Researchers should focus on the following vulnerability categories, which are most relevant to PIF's function as security middleware.

#### Detection Engine Bypass

**This is the highest-priority vulnerability class for PIF.**

- **Regex engine bypass:** Crafted payloads that contain prompt injection content but evade all 129 regex patterns. The payload must be a realistic prompt injection (not a trivially benign string that happens to not match).
- **ML classifier bypass:** Adversarial inputs that cause the DistilBERT ONNX classifier to misclassify a prompt injection payload as benign with high confidence.
- **Ensemble scoring bypass:** Payloads that individually trigger one engine but achieve an ensemble score below all action thresholds, resulting in no detection despite containing injection content.

#### Proxy Vulnerabilities

- **Request smuggling:** Manipulation of HTTP requests to bypass PIF's inspection (e.g., exploiting HTTP/1.1 chunked transfer encoding, content-length mismatches, or pipeline confusion).
- **Response manipulation:** Ability to modify or inject content into LLM responses as they pass through PIF.
- **Authentication bypass:** If PIF is configured with authentication, any method to bypass it.
- **Header injection:** Injection of arbitrary headers through user-controlled input that PIF processes.
- **SSRF (Server-Side Request Forgery):** Manipulating PIF to make requests to unintended internal endpoints.

#### Configuration Vulnerabilities

- **Configuration injection:** Manipulation of configuration values through environment variables or YAML parsing to alter PIF's behaviour.
- **Insecure defaults:** Default configuration values that leave PIF in an insecure state.
- **Path traversal:** File path manipulation in configuration loading to read or include unintended files.

#### ML Inference Vulnerabilities

- **Model file tampering:** If PIF loads the ONNX model from a path that can be influenced by an attacker, substitution of a malicious model.
- **Inference crash:** Inputs that cause the ONNX runtime to crash, panic, or consume excessive resources during inference.
- **Memory corruption:** Inputs that trigger memory safety issues in the CGo boundary between Go and the ONNX C runtime.

#### API Format Parsing

- **OpenAI format parsing bypass:** Malformed OpenAI Chat Completions payloads that PIF fails to parse correctly, causing it to skip inspection while the upstream API accepts them.
- **Anthropic format parsing bypass:** Malformed Anthropic Messages payloads that bypass inspection.
- **Content type confusion:** Sending requests with unexpected Content-Type headers that cause PIF to skip inspection.
- **Encoding bypass:** Using character encodings (e.g., UTF-16, ISO-8859-1) that PIF does not handle but the upstream API does.

---

## 3. Severity Guidelines

Use the following severity classification when submitting reports. Huntr may adjust severity during triage.

### Critical (CVSS 9.0-10.0)

A complete detection bypass that allows a prompt injection payload to pass through PIF undetected (no block, no flag, no log) when detection is enabled and correctly configured.

**Examples:**
- A payload containing clear prompt injection ("Ignore all previous instructions and...") that bypasses both regex and ML detection engines and produces no log entry.
- A request smuggling technique that causes PIF to inspect a different request body than the one forwarded to the upstream API.
- A method to disable PIF's detection entirely through a crafted request (without authentication).

**Impact:** Any application relying on PIF for prompt injection defence is completely unprotected.

### High (CVSS 7.0-8.9)

A partial detection bypass or a vulnerability that significantly degrades PIF's security posture.

**Examples:**
- A bypass that evades the regex engine but is detected by the ML engine (or vice versa), combined with a configuration where only the bypassed engine is enabled.
- Authentication bypass allowing unauthenticated access to PIF's management endpoints (if any).
- A method to force PIF to downgrade from "block" to "flag" or "log" action through request manipulation.
- SSRF allowing an attacker to use PIF as a proxy to reach internal services.

**Impact:** Reduced detection effectiveness or unauthorised access to PIF functionality.

### Medium (CVSS 4.0-6.9)

Denial of service or information disclosure that doesn't directly enable prompt injection bypass.

**Examples:**
- Crafted input that causes PIF to consume excessive CPU or memory (ReDoS in regex patterns, ML inference resource exhaustion).
- A request that causes PIF to crash or panic, temporarily disabling protection until the process restarts.
- Information disclosure of internal configuration, upstream API keys, or system information through error messages or headers.
- Timing side-channel that reveals whether a specific regex pattern matched (information useful for crafting bypasses).

**Impact:** Service disruption or information leakage that aids further attacks.

### Low (CVSS 0.1-3.9)

Hardening recommendations and minor issues that don't have a direct security impact.

**Examples:**
- Missing security headers on PIF's own error responses (e.g., missing `X-Content-Type-Options`).
- Verbose error messages that disclose version information but no sensitive data.
- Race conditions in logging that could result in incomplete audit trails (but don't affect detection).
- Configuration validation improvements that prevent operator misuse.

**Impact:** Minimal direct security impact; improvements to defence in depth.

---

## 4. Reporting Requirements

When submitting a report on Huntr, researchers should include the following information to ensure efficient triage.

### Required Information

| Field | Description |
|-------|-------------|
| **Vulnerability type** | Category from Section 2.3 (e.g., "Regex engine bypass", "Request smuggling") |
| **Affected component** | Directory and file path (e.g., `pkg/detector/regex.go`) |
| **PIF version** | Version or commit hash tested against |
| **Configuration** | Relevant PIF configuration (detection mode, thresholds, enabled engines) |
| **Reproduction steps** | Step-by-step instructions to reproduce the vulnerability |
| **Proof of concept** | Working payload, script, or curl command that demonstrates the issue |
| **Expected behaviour** | What PIF should do (e.g., "block the request") |
| **Actual behaviour** | What PIF actually does (e.g., "forwards the request unmodified") |
| **Impact assessment** | Description of real-world impact if exploited |

### Proof of Concept Requirements for Detection Bypasses

Detection bypass reports must include:

1. **The payload:** the exact string or HTTP request body used.
2. **Why it's prompt injection:** brief explanation of how the payload would manipulate an LLM if it reached the model. Trivially benign strings that happen to not match patterns aren't valid bypasses.
3. **PIF configuration:** the configuration file used, or confirmation that default configuration was used.
4. **Evidence of bypass:** logs, HTTP response, or other evidence showing that PIF didn't detect the payload.
5. **Upstream acceptance:** evidence that the payload is accepted by the target LLM API (OpenAI or Anthropic) as valid input. Malformed requests rejected by the upstream API aren't valid bypasses.

---

## 5. Registration Steps

### 5.1 Create Huntr Account

1. Go to https://huntr.com/
2. Sign up or log in with your GitHub account

### 5.2 Register the Repository

1. Navigate to the repository registration page
2. Enter the repository URL: `https://github.com/ogulcanaydogan/Prompt-Injection-Firewall`
3. Confirm you are the maintainer (Huntr may verify via GitHub permissions)

### 5.3 Configure Scope

Use the scope definition from Section 2 to configure the programme:

**In-scope assets:**
- `cmd/`: CLI and application entry point
- `pkg/detector/`: Detection engines (regex, ML, ensemble)
- `pkg/proxy/`: Reverse proxy layer
- `pkg/config/`: Configuration parsing and validation
- `internal/`: Internal shared utilities

**Out-of-scope assets:**
- `examples/`: Example configurations
- `docs/`: Documentation
- `tests/` and `*_test.go`: Test files
- `.github/`: CI/CD workflows
- Third-party dependencies (report upstream)

### 5.4 Set Severity Guidelines

Configure the severity mapping from Section 3:
- Critical: Full detection bypass allowing complete injection
- High: Partial bypass or significant security degradation
- Medium: Denial of service, information disclosure
- Low: Hardening recommendations

### 5.5 Configure Response Policy

| Setting | Value |
|---------|-------|
| Initial response time | 72 hours |
| Triage time | 7 days |
| Resolution target (Critical) | 14 days |
| Resolution target (High) | 30 days |
| Resolution target (Medium) | 60 days |
| Resolution target (Low) | 90 days |
| Public disclosure | 90 days after fix, or coordinated with researcher |

### 5.6 Add Maintainer Contacts

- **Primary contact:** Ogulcan Aydogan (GitHub: @ogulcanaydogan)
- **Security email:** (configure a dedicated security contact email or use GitHub Security Advisories)

---

## 6. Integration with GitHub Security Advisories

In addition to Huntr, PIF should accept vulnerability reports through GitHub Security Advisories (GHSA). This provides a private channel for reports from researchers who don't use Huntr.

### 6.1 Enable Security Advisories

1. Go to the repository Settings > Security > Advisories
2. Ensure "Private vulnerability reporting" is enabled
3. This allows researchers to submit reports directly through GitHub

### 6.2 SECURITY.md

Ensure the repository contains a `SECURITY.md` file that directs researchers to both channels:

```markdown
# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Prompt Injection Firewall, please report it
through one of the following channels:

1. **Huntr:** https://huntr.com/repos/ogulcanaydogan/Prompt-Injection-Firewall
2. **GitHub Security Advisories:** Use the "Report a vulnerability" button on the
   Security tab of this repository.

Please don't open a public GitHub issue for security vulnerabilities.

## Response Timeline

- Initial acknowledgement: within 72 hours
- Triage and severity assessment: within 7 days
- Fix for Critical severity: within 14 days
- Fix for High severity: within 30 days

## Scope

See our Huntr programme for detailed scope and severity guidelines.
```

---

## 7. Triage Workflow

When a report is submitted on Huntr, follow this workflow:

```
Report Received
      |
      v
[Acknowledge within 72 hours]
      |
      v
[Is it in scope?] --No--> Close as "Out of Scope" with explanation
      |
     Yes
      |
      v
[Can you reproduce it?] --No--> Request more information from researcher
      |
     Yes
      |
      v
[Assign severity per Section 3]
      |
      v
[Create private GitHub issue or security advisory]
      |
      v
[Develop fix on private branch]
      |
      v
[Request researcher to verify fix]
      |
      v
[Merge fix, release patched version]
      |
      v
[Huntr assigns CVE if applicable]
      |
      v
[Public disclosure after coordinated timeline]
```

---

## 8. Special Considerations for PIF

### 8.1 Detection Bypass Validation

Detection bypass reports require careful validation because the definition of "prompt injection" is context-dependent. When triaging bypass reports:

1. **Verify the payload is actually injection.** The payload must contain content that would manipulate an LLM's behaviour (e.g., instruction override, role hijacking, data exfiltration attempt). A random string that doesn't match any pattern isn't a bypass.

2. **Test against default configuration.** First reproduce with default PIF configuration. If the bypass only works with a non-default configuration (e.g., ML engine disabled), note this in the assessment.

3. **Evaluate real-world impact.** A bypass payload that would not actually affect a well-configured LLM application has lower severity than one that reliably manipulates model behaviour.

4. **Consider ensemble behaviour.** A payload that bypasses the regex engine but is caught by the ML engine (or vice versa) is a valid finding (it indicates a gap in one engine) but has lower severity than a full ensemble bypass.

### 8.2 ReDoS in Regex Patterns

Regular expression denial of service (ReDoS) is a known risk for regex-heavy systems. PIF's 129 patterns should be evaluated for catastrophic backtracking. When triaging ReDoS reports:

- Confirm the regex causes measurable CPU consumption (not just theoretical backtracking).
- Measure the actual latency impact (e.g., a pattern that takes 10 seconds vs. one that takes 200ms).
- Severity depends on whether the ReDoS can be triggered by normal user input or only by crafted adversarial input.

### 8.3 CGo / ONNX Runtime Boundary

The boundary between Go and the ONNX C runtime (via CGo) is a potential source of memory safety issues. Reports involving crashes, panics, or memory corruption in the ML inference path should be treated as High severity minimum, as they may be exploitable for code execution.

---

## 9. Checklist Before Going Live

Complete these items before making the Huntr programme public.

- [ ] Verify SECURITY.md is present in the repository with correct contact information
- [ ] Enable GitHub Private Vulnerability Reporting
- [ ] Register repository on Huntr
- [ ] Configure in-scope and out-of-scope assets per Section 2
- [ ] Set severity guidelines per Section 3
- [ ] Configure response timeline per Section 5.5
- [ ] Test the report submission flow (submit a test report yourself)
- [ ] Prepare a private branch or fork for developing security fixes
- [ ] Ensure you have notification channels configured (email, GitHub) for new reports
- [ ] Brief any co-maintainers on the triage workflow (Section 7)

---

## 10. Benefits for Grant Applications

Registering on Huntr strengthens PIF's position in grant applications (AISI Challenge Fund, NLnet NGI Zero) by demonstrating:

1. **Proactive security posture.** The project actively invites security testing rather than relying solely on internal review.
2. **Mature vulnerability management.** A documented triage workflow and response timeline show operational maturity.
3. **Community engagement.** Bug bounty programmes attract security researchers who contribute expertise the maintainer may not have.
4. **Transparent security track record.** Resolved Huntr reports (with CVEs where applicable) provide evidence of responsiveness to security issues.

---

*Document prepared as Huntr bug bounty registration guide for Prompt Injection Firewall. Last updated: March 2026.*
