# Contributing to Prompt Injection Firewall

Thank you for your interest in contributing to PIF! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/prompt-injection-firewall.git`
3. Create a branch: `git checkout -b feature/your-feature`
4. Make your changes
5. Run tests: `go test -race ./...`
6. Submit a pull request

## Development Setup

```bash
# Install dependencies
go mod download

# Run tests
go test -v -race ./...

# Run linter
golangci-lint run

# Build binaries
go build ./cmd/pif-cli/
go build ./cmd/firewall/
```

## Adding Detection Patterns

1. Add patterns to the appropriate YAML file in `rules/`
2. Follow the existing format (see `rules/jailbreak-patterns.yaml`)
3. Include both true-positive and true-negative test cases
4. Run the benchmark suite to verify accuracy

## Code Guidelines

- Follow standard Go conventions (`gofmt`, `goimports`)
- Write tests for all new functionality
- Maintain >80% test coverage
- Use `log/slog` for structured logging

## Commit Messages

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`

## Reporting Security Issues

See [SECURITY.md](SECURITY.md) for reporting security vulnerabilities.
