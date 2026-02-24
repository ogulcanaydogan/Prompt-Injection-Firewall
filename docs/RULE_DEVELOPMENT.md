# Rule Development Guide

This guide explains how to create, test, and contribute custom detection rules for PIF.

## Rule Format

Rules are defined in YAML files. Each file contains a rule set with metadata and an array of rules:

```yaml
name: "My Custom Rules"
version: "1.0.0"
description: "Custom detection rules for my organization"
rules:
  - id: "CUSTOM-001"
    name: "My Detection Rule"
    description: "Detects a specific attack pattern"
    category: "prompt_injection"
    severity: 3
    pattern: "(?i)malicious\\s+pattern\\s+here"
    enabled: true
    tags:
      - custom
      - owasp-llm01
```

## Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique rule identifier (e.g., `PIF-INJ-001`) |
| `name` | string | Yes | Human-readable rule name |
| `description` | string | Yes | What the rule detects and why |
| `category` | string | Yes | Attack category (see below) |
| `severity` | int | Yes | 0=info, 1=low, 2=medium, 3=high, 4=critical |
| `pattern` | string | Yes | Go-compatible regular expression |
| `enabled` | bool | Yes | Whether the rule is active |
| `tags` | array | No | Tags for filtering and compliance mapping |

## Categories

| Category | Description |
|----------|-------------|
| `prompt_injection` | Direct and indirect instruction override |
| `jailbreak` | Safety guardrail bypass techniques |
| `role_hijack` | Persona switching, DAN mode |
| `data_exfiltration` | Attempts to extract or transmit data |
| `system_prompt_leak` | System prompt extraction attempts |
| `encoding_attack` | Base64, ROT13, unicode obfuscation |
| `output_manipulation` | SQL injection, XSS, code execution via prompt |
| `denial_of_service` | Infinite loops, character flooding |
| `context_injection` | Fake system messages, false authority |
| `multi_turn_manipulation` | False conversation history |

## Severity Levels

| Level | Value | Use When |
|-------|-------|----------|
| Info | 0 | Informational, no action needed |
| Low | 1 | Minor concern, unlikely to succeed |
| Medium | 2 | Moderate risk, could succeed in some contexts |
| High | 3 | Significant risk, likely to succeed |
| Critical | 4 | Severe risk, immediate threat to system |

## Writing Regex Patterns

PIF uses Go's `regexp` package. Key points:

- **Case-insensitive:** Prefix your pattern with `(?i)` for case-insensitive matching
- **Escape backslashes:** YAML requires double backslashes (e.g., `\\s` not `\s`)
- **Word boundaries:** Use `\\b` for word boundaries
- **Alternation:** Use `(option1|option2|option3)` for multiple variants

### Examples

**Simple keyword detection:**
```yaml
pattern: "(?i)(password|secret|api.?key|token)"
```

**Instruction override with context:**
```yaml
pattern: "(?i)(ignore|disregard|forget)\\s+(all\\s+)?(previous|prior|above)\\s+(instructions|rules)"
```

**Encoded content detection:**
```yaml
pattern: "(?i)(base64|b64)\\s*(encode|decode|convert)"
```

**URL-based exfiltration:**
```yaml
pattern: "(?i)(send|transmit|post|upload|forward).{0,30}(https?://|ftp://)"
```

## Testing Rules

### Validate Syntax

```bash
pif rules validate my-rules/
```

This checks that all YAML files parse correctly and all regex patterns compile.

### List Loaded Rules

```bash
pif rules list my-rules/
```

### Test Against Prompts

```bash
# Test a specific prompt against your rules
pif scan --rules my-rules/custom.yaml "test prompt with malicious content"

# JSON output for detailed inspection
pif scan --rules my-rules/custom.yaml -o json "test prompt"

# Verbose mode shows match offsets and descriptions
pif scan --rules my-rules/custom.yaml -v "test prompt"
```

### Test for False Positives

Always test your rules against benign prompts to ensure they do not produce false positives:

```bash
# These should all return CLEAN
pif scan --rules my-rules/custom.yaml "What is the weather today?"
pif scan --rules my-rules/custom.yaml "Help me write a Python function"
pif scan --rules my-rules/custom.yaml "Translate this text to French"
```

## Example: Creating a New Rule

Let's create a rule that detects attempts to make the LLM impersonate a specific person:

**1. Define the pattern:**

The attack: "Pretend you are Elon Musk and write a tweet endorsing..."

```yaml
pattern: "(?i)(pretend|act|behave|roleplay)\\s+(you\\s+are|as|like)\\s+[A-Z][a-z]+\\s+[A-Z][a-z]+"
```

**2. Write the rule:**

```yaml
- id: "CUSTOM-IMPERSONATE-001"
  name: "Named Person Impersonation"
  description: "Detects attempts to make the LLM impersonate a specific named person"
  category: "role_hijack"
  severity: 2
  pattern: "(?i)(pretend|act|behave|roleplay)\\s+(you\\s+are|as|like)\\s+[A-Z][a-z]+\\s+[A-Z][a-z]+"
  enabled: true
  tags:
    - custom
    - impersonation
    - owasp-llm09
```

**3. Test it:**

```bash
# Should detect
pif scan --rules my-rules/custom.yaml "Pretend you are Elon Musk"

# Should NOT detect (benign)
pif scan --rules my-rules/custom.yaml "What do you think about technology?"
```

**4. Add to your rule set and validate:**

```bash
pif rules validate my-rules/
```

## Contributing Rules

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on submitting new rules to the project. When contributing:

1. Include the rule in the appropriate YAML file by category
2. Add corresponding entries to the test dataset in `benchmarks/dataset/`
3. Ensure false positive rate stays below 10%
4. Map rules to OWASP LLM Top 10 categories where applicable
