//go:build e2e
// +build e2e

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ejagojo/SentryScan/internal/test/e2e"
)

func TestBaselineSuppression(t *testing.T) {
	h := e2e.NewTestHelper(t)

	// Create a test file with a finding
	testFile := filepath.Join(h.workDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("api_key = 'secret123'"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create baseline with the finding's fingerprint
	fingerprint := "api-key-secret123" // This would be the actual fingerprint in real usage
	if err := h.CreateBaseline([]string{fingerprint}); err != nil {
		t.Fatalf("failed to create baseline: %v", err)
	}

	// Run scan with baseline
	stdout, stderr, err := h.RunCommand("sentryscan", "scan", ".")
	h.AssertExitCode(err, 5) // Exit code 5 for suppressed findings
	h.AssertOutput(stdout, stderr, "1 finding suppressed")
}

func TestBaselineList(t *testing.T) {
	h := e2e.NewTestHelper(t)

	// Create baseline with some findings
	fingerprints := []string{"fp1", "fp2"}
	if err := h.CreateBaseline(fingerprints); err != nil {
		t.Fatalf("failed to create baseline: %v", err)
	}

	// List baseline findings
	stdout, stderr, err := h.RunCommand("sentryscan", "baseline", "list")
	h.AssertExitCode(err, 0)
	h.AssertOutput(stdout, stderr, "fp1")
	h.AssertOutput(stdout, stderr, "fp2")
}

func TestNoBaseline(t *testing.T) {
	h := e2e.NewTestHelper(t)

	// Create a test file with a finding
	testFile := filepath.Join(h.workDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("api_key = 'secret123'"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create baseline with the finding's fingerprint
	fingerprint := "api-key-secret123"
	if err := h.CreateBaseline([]string{fingerprint}); err != nil {
		t.Fatalf("failed to create baseline: %v", err)
	}

	// Run scan with --no-baseline
	stdout, stderr, err := h.RunCommand("sentryscan", "scan", "--no-baseline", ".")
	h.AssertExitCode(err, 3) // Exit code 3 for high severity findings
	h.AssertOutput(stdout, stderr, "api_key")
}
