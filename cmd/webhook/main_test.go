package main

import "testing"

func TestRun_InvalidFlag(t *testing.T) {
	code := run([]string{"--bad-flag"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRun_InvalidConfigPath(t *testing.T) {
	code := run([]string{"--config", "/nonexistent/config.yaml"})
	if code != 2 {
		t.Fatalf("expected exit code 2, got %d", code)
	}
}

func TestRun_StartServerError(t *testing.T) {
	code := run([]string{"--listen", ":-1"})
	if code != 1 {
		t.Fatalf("expected exit code 1, got %d", code)
	}
}
