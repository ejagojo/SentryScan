//go:build e2e
// +build e2e

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/ejagojo/SentryScan/internal/test/e2e"
)

func TestWebhook(t *testing.T) {
	h := e2e.NewTestHelper(t)

	// Create a test file with a finding
	testFile := filepath.Join(h.workDir, "test.txt")
	if err := os.WriteFile(testFile, []byte("api_key = 'secret123'"), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Start webhook server
	webhookURL, cleanup, err := h.StartWebhookServer()
	if err != nil {
		t.Fatalf("failed to start webhook server: %v", err)
	}
	defer cleanup()

	// Set up webhook handler
	var receivedPayload struct {
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
		Sign struct {
			Algorithm string `json:"alg"`
			Signature string `json:"sig"`
		} `json:"sign"`
	}

	http.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("failed to decode webhook payload: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Run scan with webhook
	stdout, stderr, err := h.RunCommand("sentryscan", "scan",
		"--webhook-url", webhookURL+"/webhook",
		"--webhook-secret", "test-secret",
		".",
	)
	h.AssertExitCode(err, 3)
	h.AssertOutput(stdout, stderr, "api_key")

	// Verify webhook payload
	if len(receivedPayload.Findings) == 0 {
		t.Error("webhook did not receive any findings")
	}
	if receivedPayload.Sign.Algorithm != "HS256" {
		t.Errorf("unexpected signature algorithm: %s", receivedPayload.Sign.Algorithm)
	}
	if receivedPayload.Sign.Signature == "" {
		t.Error("missing signature in webhook payload")
	}
}
