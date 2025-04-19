//go:build e2e
// +build e2e

package main

import (
	"testing"

	"github.com/ejagojo/SentryScan/internal/test/e2e"
)

func TestImageScan(t *testing.T) {
	h := e2e.NewTestHelper(t)

	// Create a test image with no vulnerabilities
	imagePath, err := h.CreateTestImage("test:latest", nil)
	if err != nil {
		t.Fatalf("failed to create test image: %v", err)
	}

	// Run scan with critical severity threshold
	stdout, stderr, err := h.RunCommand("sentryscan", "scan", "--image", imagePath, "--severity=critical")
	h.AssertExitCode(err, 0)
	h.AssertOutput(stdout, stderr, "0 findings")
}

func TestImageCompare(t *testing.T) {
	h := e2e.NewTestHelper(t)

	// Create base image with some vulnerabilities
	basePath, err := h.CreateTestImage("base:latest", []string{"CVE-2023-1234"})
	if err != nil {
		t.Fatalf("failed to create base image: %v", err)
	}

	// Create target image with additional vulnerabilities
	targetPath, err := h.CreateTestImage("target:latest", []string{"CVE-2023-1234", "CVE-2023-5678"})
	if err != nil {
		t.Fatalf("failed to create target image: %v", err)
	}

	// Run scan with comparison
	stdout, stderr, err := h.RunCommand("sentryscan", "scan", "--image", targetPath, "--compare", basePath)
	h.AssertExitCode(err, 3)
	h.AssertOutput(stdout, stderr, "CVE-2023-5678")
	h.AssertOutput(stdout, stderr, "CVE-2023-1234")
}
