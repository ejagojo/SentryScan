package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

// TestHelper provides utilities for end-to-end tests
type TestHelper struct {
	t       *testing.T
	workDir string
}

// NewTestHelper creates a new test helper
func NewTestHelper(t *testing.T) *TestHelper {
	workDir, err := os.MkdirTemp("", "sentryscan-e2e-*")
	if err != nil {
		t.Fatalf("failed to create work dir: %v", err)
	}

	t.Cleanup(func() {
		os.RemoveAll(workDir)
	})

	return &TestHelper{
		t:       t,
		workDir: workDir,
	}
}

// RunCommand runs a command and returns its output
func (h *TestHelper) RunCommand(name string, args ...string) (string, string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = h.workDir

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// CreateTestImage creates a test container image with vulnerabilities
func (h *TestHelper) CreateTestImage(tag string, vulns []string) (string, error) {
	// Create a base image
	img, err := random.Image(1024, 1)
	if err != nil {
		return "", fmt.Errorf("failed to create random image: %w", err)
	}

	// Add vulnerabilities
	config, err := img.ConfigFile()
	if err != nil {
		return "", fmt.Errorf("failed to get config file: %w", err)
	}

	config.Config.Env = append(config.Config.Env, "VULNS="+strings.Join(vulns, ","))
	img, err = mutate.Config(img, config.Config)
	if err != nil {
		return "", fmt.Errorf("failed to mutate config: %w", err)
	}

	// Save to OCI layout
	layoutPath := filepath.Join(h.workDir, "layout")
	if err := crane.SaveOCI(img, layoutPath); err != nil {
		return "", fmt.Errorf("failed to save OCI layout: %w", err)
	}

	return layoutPath, nil
}

// CreateBaseline creates a baseline file
func (h *TestHelper) CreateBaseline(fingerprints []string) error {
	baseline := struct {
		Findings []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"findings"`
	}{
		Findings: make([]struct {
			Fingerprint string `json:"fingerprint"`
		}, len(fingerprints)),
	}

	for i, fp := range fingerprints {
		baseline.Findings[i].Fingerprint = fp
	}

	data, err := json.Marshal(baseline)
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	return os.WriteFile(filepath.Join(h.workDir, ".sentryscan_baseline.json"), data, 0644)
}

// StartWebhookServer starts a test webhook server
func (h *TestHelper) StartWebhookServer() (string, func(), error) {
	mux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":0",
		Handler: mux,
	}

	// Start server
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return "", nil, fmt.Errorf("failed to listen: %w", err)
	}

	go server.Serve(listener)

	// Get server address
	addr := fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)

	// Return cleanup function
	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}

	return addr, cleanup, nil
}

// AssertOutput asserts that the command output matches the expected pattern
func (h *TestHelper) AssertOutput(stdout, stderr string, expectedPattern string) {
	if !strings.Contains(stdout+stderr, expectedPattern) {
		h.t.Errorf("output does not contain expected pattern %q", expectedPattern)
	}
}

// AssertExitCode asserts that the command exited with the expected code
func (h *TestHelper) AssertExitCode(err error, expectedCode int) {
	if err == nil {
		if expectedCode != 0 {
			h.t.Errorf("expected exit code %d, got 0", expectedCode)
		}
		return
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != expectedCode {
			h.t.Errorf("expected exit code %d, got %d", expectedCode, exitErr.ExitCode())
		}
	} else {
		h.t.Errorf("unexpected error: %v", err)
	}
}
