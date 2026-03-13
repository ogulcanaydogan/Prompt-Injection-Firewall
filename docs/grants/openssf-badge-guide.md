# OpenSSF Best Practices Badge Guide for Prompt Injection Firewall

**Programme:** OpenSSF (Open Source Security Foundation) Best Practices Badge
**URL:** https://www.bestpractices.dev/
**Cost:** Free
**Purpose:** Demonstrate that PIF follows open-source security best practices; strengthens grant applications and adoption by security-conscious organisations
**Repository:** https://github.com/ogulcanaydogan/Prompt-Injection-Firewall

---

## 1. Overview

The OpenSSF Best Practices Badge (formerly CII Best Practices) is a free certification programme that evaluates open-source projects against a set of security, quality, and documentation criteria. Projects that meet the criteria earn a badge that can be displayed in their README, demonstrating adherence to industry best practices.

The badge has three levels:
- **Passing** -- baseline criteria (most important for grant applications)
- **Silver** -- additional criteria around change management and quality
- **Gold** -- highest level, requires reproducible builds and dynamic analysis

This guide maps PIF's current capabilities to the **Passing** level criteria and identifies any gaps that need to be addressed before submission.

---

## 2. Pre-Submission Checklist for PIF

### 2.1 Basics

| Criterion | Requirement | PIF Status | Action Needed |
|-----------|------------|------------|---------------|
| **Website** | Project has a website or README with basic info | README.md exists with project description, installation, usage | None |
| **Description** | Project has a clear description of what it does | README includes description of PIF as prompt injection defence middleware | None |
| **Interaction** | Project provides a mechanism for discussion | GitHub Issues enabled; Discussions can be enabled | Enable GitHub Discussions if not already active |
| **Contribution guide** | CONTRIBUTING.md or equivalent exists | Verify CONTRIBUTING.md exists | Create if missing |
| **License** | OSI-approved license, clearly stated | Apache 2.0; LICENSE file in repo root | None |
| **License in files** | License header or SPDX identifier in source files | Verify Go source files include SPDX headers | Add `// SPDX-License-Identifier: Apache-2.0` to source files if missing |

### 2.2 Change Control

| Criterion | Requirement | PIF Status | Action Needed |
|-----------|------------|------------|---------------|
| **Version control** | Project uses version control (Git) | GitHub repository | None |
| **Unique version numbering** | Each release has a unique version | Semantic versioning with 4 releases | None |
| **Release notes** | Each release has human-readable release notes | GitHub Releases with changelogs | None |
| **Version in a standard place** | Version number accessible programmatically | Verify version is in `go.mod` or a `version.go` constant | Ensure version is defined in code |

### 2.3 Reporting

| Criterion | Requirement | PIF Status | Action Needed |
|-----------|------------|------------|---------------|
| **Bug reporting process** | Project has a documented process for reporting bugs | GitHub Issues | Document in CONTRIBUTING.md |
| **Security vulnerability reporting** | Project has a documented process for reporting security vulnerabilities | Verify SECURITY.md exists | Create SECURITY.md with responsible disclosure policy if missing |
| **Response to vulnerability reports** | Project responds to reports in a timely manner | Policy should state response within 72 hours | Document in SECURITY.md |

### 2.4 Quality

| Criterion | Requirement | PIF Status | Action Needed |
|-----------|------------|------------|---------------|
| **Working build system** | Project can be built from source | `go build` produces binary | None |
| **Automated test suite** | Project has an automated test suite | Go tests with `go test ./...` | None |
| **New functionality tested** | Tests cover new features | CI runs tests on every PR | None |
| **Test coverage** | Coverage is measured and reported | **80%+ coverage** | Add coverage reporting to CI if not already present (e.g., `go test -coverprofile`) |
| **Tests pass** | All tests pass in CI | CI workflow (`ci.yml`) runs on push/PR | None |

### 2.5 Security

| Criterion | Requirement | PIF Status | Action Needed |
|-----------|------------|------------|---------------|
| **Static analysis** | Project uses at least one static analysis tool | **CodeQL** integrated in CI (`codeql.yml`); **golangci-lint** | None |
| **No known critical vulnerabilities** | No unpatched critical vulnerabilities | Verify with `govulncheck` | Run `govulncheck ./...` and address any findings |
| **Secure development knowledge** | Lead developer understands secure development practices | Documented in this guide and SECURITY.md | None |
| **Memory-safe language** | Project uses a memory-safe language or addresses memory safety | **Go is memory-safe** (garbage collected, bounds-checked) | None |

### 2.6 Analysis

| Criterion | Requirement | PIF Status | Action Needed |
|-----------|------------|------------|---------------|
| **Dynamic analysis** | Project uses dynamic analysis (e.g., fuzzing, race detection) | **Go race detector** enabled in CI (`go test -race`) | None |
| **Compiler warnings** | Project builds without warnings | Go compiler is strict; verify clean build | Run `go vet ./...` in CI |

---

## 3. CI Workflows Relevant to Badge Criteria

PIF has three CI workflows that satisfy multiple badge criteria simultaneously.

### 3.1 ci.yml -- Continuous Integration

**File:** `.github/workflows/ci.yml`

This workflow satisfies the following badge criteria:
- Automated test suite execution
- Tests pass on every push and PR
- Race condition detection (`go test -race`)
- Build verification (`go build`)

**Recommended additions for badge compliance:**
```yaml
# Add coverage reporting step
- name: Run tests with coverage
  run: go test -race -coverprofile=coverage.out -covermode=atomic ./...

- name: Report coverage
  run: go tool cover -func=coverage.out
```

### 3.2 codeql.yml -- Static Analysis

**File:** `.github/workflows/codeql.yml`

This workflow satisfies the following badge criteria:
- Static analysis tool usage (CodeQL)
- Automated security scanning
- Known vulnerability detection

CodeQL performs semantic code analysis that detects:
- Injection vulnerabilities
- Authentication issues
- Cryptographic weaknesses
- Data flow problems
- Go-specific security issues

### 3.3 release.yml -- Release Management

**File:** `.github/workflows/release.yml`

This workflow satisfies the following badge criteria:
- Unique version numbering (triggered by Git tags)
- Reproducible releases (automated build and release process)
- Release artifact availability

---

## 4. Security Tooling Summary

| Tool | Purpose | Integration Point | Badge Criterion |
|------|---------|-------------------|-----------------|
| **CodeQL** | Semantic static analysis for security vulnerabilities | `codeql.yml` workflow, runs on push/PR | Static analysis |
| **golangci-lint** | Go linter aggregator (includes gosec, govet, staticcheck, errcheck) | `ci.yml` workflow or pre-commit | Static analysis, compiler warnings |
| **Go race detector** | Dynamic analysis for data race conditions | `go test -race` in `ci.yml` | Dynamic analysis |
| **Go vet** | Static analysis for suspicious constructs | `go vet ./...` in `ci.yml` | Compiler warnings |
| **govulncheck** | Known vulnerability scanning for Go dependencies | Manual or CI step | No known critical vulnerabilities |

---

## 5. Testing Infrastructure

### 5.1 Test Execution

```bash
# Run all tests with race detector and coverage
go test -race -coverprofile=coverage.out -covermode=atomic ./...

# View coverage summary
go tool cover -func=coverage.out

# View coverage in browser
go tool cover -html=coverage.out
```

### 5.2 Coverage Targets

| Package | Minimum Coverage | Notes |
|---------|-----------------|-------|
| `pkg/detector/` | 85% | Core detection logic; highest priority |
| `pkg/proxy/` | 80% | Proxy request handling and forwarding |
| `pkg/config/` | 80% | Configuration parsing and validation |
| `cmd/` | 70% | CLI entry point; lower priority |
| `internal/` | 75% | Internal utilities |
| **Overall** | **80%+** | Current status meets this threshold |

### 5.3 Test Categories

| Category | Description | Location |
|----------|-------------|----------|
| Unit tests | Individual function/method tests | `*_test.go` files adjacent to source |
| Integration tests | End-to-end proxy + detection tests | `tests/` or `*_integration_test.go` |
| Regex pattern tests | Verification of all 129 patterns against known payloads | `pkg/detector/regex_test.go` |
| ML model tests | Verification of ONNX inference pipeline | `pkg/detector/ml_test.go` |
| Race condition tests | Concurrent access tests with `-race` flag | All tests run with race detector |

---

## 6. Gap Analysis and Action Items

The following items should be completed before submitting for the OpenSSF badge.

### Priority 1: Required for Passing

| # | Action | Effort | Status |
|---|--------|--------|--------|
| 1 | Verify SECURITY.md exists with responsible disclosure policy | 30 min | Check repo |
| 2 | Verify CONTRIBUTING.md exists with bug reporting process | 30 min | Check repo |
| 3 | Add SPDX license identifiers to source files (if missing) | 1 hour | Check source files |
| 4 | Run `govulncheck ./...` and address any findings | 30 min | Run locally |
| 5 | Ensure `go vet ./...` passes cleanly | 15 min | Run locally |
| 6 | Add coverage reporting to CI if not present | 30 min | Check `ci.yml` |

### Priority 2: Recommended for Stronger Application

| # | Action | Effort | Status |
|---|--------|--------|--------|
| 7 | Enable GitHub Discussions for community interaction | 5 min | GitHub Settings |
| 8 | Add badge image to README once earned | 5 min | After submission |
| 9 | Document build-from-source instructions in README | 15 min | Check README |
| 10 | Add `govulncheck` to CI pipeline | 15 min | Add workflow step |

---

## 7. Submission Process

### 7.1 Create Account

1. Go to https://www.bestpractices.dev/
2. Sign in with your GitHub account (ogulcanaydogan)

### 7.2 Register Project

1. Click "Get Your Badge Now!"
2. Enter the repository URL: `https://github.com/ogulcanaydogan/Prompt-Injection-Firewall`
3. The system will auto-detect some criteria from the repository

### 7.3 Complete the Questionnaire

The questionnaire has approximately 66 criteria for the Passing level. For each criterion:
- Select "Met" if PIF satisfies it (provide a brief justification)
- Select "Unmet" if it does not (and note what action is needed)
- Select "N/A" if the criterion does not apply

Use this guide's checklist (Section 2) and gap analysis (Section 6) to pre-populate your answers.

### 7.4 Key Answers Reference

Below are suggested responses for criteria where PIF's answer may not be immediately obvious.

**"What is the human language(s) of the project?"**
> English

**"Does the project use a memory-unsafe language?"**
> No. Go is memory-safe (garbage collected, bounds-checked arrays, no pointer arithmetic).

**"Does the project use at least one static analysis tool?"**
> Yes. CodeQL (integrated in CI via codeql.yml) and golangci-lint.

**"Does the project use at least one dynamic analysis tool?"**
> Yes. Go race detector (`go test -race`) is enabled in CI. All tests run with race detection.

**"Is there a documented process for reporting security vulnerabilities?"**
> Yes. See SECURITY.md in the repository root. Reports can be sent via GitHub Security Advisories or direct email.

**"What license(s) does the project use?"**
> Apache-2.0 (SPDX identifier). OSI-approved. LICENSE file in repository root.

---

## 8. Badge Display

Once the Passing badge is earned, add it to the project README:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/XXXXX/badge)](https://www.bestpractices.dev/projects/XXXXX)
```

Replace `XXXXX` with the project ID assigned during registration.

The badge serves as a trust signal for:
- Grant applications (AISI Challenge Fund, NLnet NGI Zero, and others)
- Enterprise adoption decisions
- Open-source security assessments
- Bug bounty programme credibility (Huntr)

---

## 9. Path to Silver and Gold

After achieving Passing, consider pursuing Silver and Gold levels to further strengthen the project's security posture.

### Silver Additional Requirements

| Criterion | Requirement | PIF Path |
|-----------|------------|----------|
| Bus factor >= 2 | At least 2 significant contributors | Recruit contributors or co-maintainer |
| Signed releases | Releases are cryptographically signed | Add GPG signing to release workflow |
| Code review | All changes reviewed before merge | Enable branch protection requiring reviews |

### Gold Additional Requirements

| Criterion | Requirement | PIF Path |
|-----------|------------|----------|
| Reproducible build | Build produces identical output from same source | Go builds are deterministic with pinned dependencies |
| Dynamic analysis on all code | Fuzzing or equivalent covers all code paths | Add Go fuzzing targets for detection engines |
| Formal security audit | Independent security review completed | Covered by AISI/NLnet grant funding |

---

*Document prepared as OpenSSF Best Practices Badge submission guide for Prompt Injection Firewall. Last updated: March 2026.*
