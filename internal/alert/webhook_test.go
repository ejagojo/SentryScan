package alert

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ejagojo/SentryScan/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestWebhookRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wh := NewWebhook(server.URL, "test-secret")
	payload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
	}

	err := wh.Send(payload)
	assert.NoError(t, err)
	assert.Equal(t, 3, attempts, "Expected 3 attempts before success")
}

func TestWebhookReplayAttack(t *testing.T) {
	receivedNonces := &sync.Map{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if _, exists := receivedNonces.LoadOrStore(payload.Nonce, true); exists {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	wh := NewWebhook(server.URL, "test-secret")

	// Set a fixed nonce for testing
	testNonce = "test-nonce"
	defer func() { testNonce = "" }()

	// First attempt should succeed
	payload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
	}
	err := wh.Send(payload)
	assert.NoError(t, err)

	// Immediate replay should fail
	replayPayload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
	}
	err = wh.Send(replayPayload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "replay attack detected")

	// Wait for nonce to expire
	time.Sleep(time.Second)

	// New attempt with same payload but different timestamp should succeed
	testNonce = "test-nonce-2"
	newPayload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
	}
	err = wh.Send(newPayload)
	assert.NoError(t, err)
}

func TestWebhookSignature(t *testing.T) {
	// Create a test server that verifies signatures
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload Payload
		err := json.NewDecoder(r.Body).Decode(&payload)
		if err != nil {
			t.Logf("Server error decoding payload: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// Verify signature
		wh := NewWebhook("", "test-secret")
		if err := wh.verifySignature(&payload); err != nil {
			t.Logf("Server error verifying signature: %v", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Test 1: Valid signature
	wh1 := NewWebhook(server.URL, "test-secret")
	testNonce = "test-nonce-1"
	defer func() { testNonce = "" }()

	validPayload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
		Nonce:       testNonce,
	}

	t.Log("Sending valid payload")
	err := wh1.Send(validPayload)
	if err != nil {
		t.Logf("Error sending valid payload: %v", err)
	}
	assert.NoError(t, err, "Valid signature should pass verification")

	// Test 2: Tampered payload
	wh2 := NewWebhook(server.URL, "wrong-secret")
	testNonce = "test-nonce-2"

	tamperedPayload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
		Nonce:       testNonce,
	}

	t.Log("Sending tampered payload")
	err = wh2.Send(tamperedPayload)
	if err != nil {
		t.Logf("Error sending tampered payload: %v", err)
	}
	assert.Error(t, err, "Tampered payload should fail verification")
	assert.Contains(t, err.Error(), "server returned status 401", "Error should indicate unauthorized status")

	// Test 3: Expired timestamp
	wh3 := NewWebhook(server.URL, "test-secret")
	testNonce = "test-nonce-3"

	expiredPayload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now().Add(-maxAge - time.Second),
		Nonce:       testNonce,
	}

	t.Log("Sending expired payload")
	err = wh3.Send(expiredPayload)
	if err != nil {
		t.Logf("Error sending expired payload: %v", err)
	}
	assert.Error(t, err, "Expired payload should fail verification")
	assert.Contains(t, err.Error(), "payload timestamp expired", "Error should indicate timestamp expiration")
}

func TestWebhookConcurrency(t *testing.T) {
	// Create a test server that tracks concurrent requests
	var (
		mu           sync.Mutex
		activeConns  int
		maxConns     int
		receivedData [][]byte
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		activeConns++
		if activeConns > maxConns {
			maxConns = activeConns
		}
		mu.Unlock()

		// Simulate processing time
		time.Sleep(50 * time.Millisecond)

		body, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		mu.Lock()
		receivedData = append(receivedData, body)
		activeConns--
		mu.Unlock()

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	wh := NewWebhook(ts.URL, "test-secret")
	var wg sync.WaitGroup
	numRequests := 10

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := &Payload{
				RunID:       fmt.Sprintf("test-run-%d", i),
				Summary:     "test summary",
				Findings:    []scanner.Finding{{RuleID: fmt.Sprintf("RULE-%d", i)}},
				Repo:        "test/repo",
				GitRef:      "main",
				GeneratedAt: time.Now(),
			}
			err := wh.Send(payload)
			if err != nil {
				t.Errorf("concurrent webhook %d failed: %v", i, err)
			}
		}(i)
	}

	wg.Wait()

	if maxConns == 0 {
		t.Error("no concurrent connections detected")
	}

	if len(receivedData) != numRequests {
		t.Errorf("expected %d requests, got %d", numRequests, len(receivedData))
	}

	// Verify all payloads are unique
	seen := make(map[string]bool)
	for _, data := range receivedData {
		var payload Payload
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Errorf("failed to unmarshal payload: %v", err)
			continue
		}
		if seen[payload.RunID] {
			t.Errorf("duplicate runID found: %s", payload.RunID)
		}
		seen[payload.RunID] = true
	}
}

func TestWebhookPayloadValidation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	wh := NewWebhook(ts.URL, "test-secret")

	tests := []struct {
		name      string
		payload   *Payload
		wantError bool
	}{
		{
			name: "empty runID",
			payload: &Payload{
				RunID:       "",
				Summary:     "test summary",
				Findings:    []scanner.Finding{},
				Repo:        "test/repo",
				GitRef:      "main",
				GeneratedAt: time.Now(),
			},
			wantError: false,
		},
		{
			name: "very long runID",
			payload: &Payload{
				RunID:       strings.Repeat("a", 1000),
				Summary:     "test summary",
				Findings:    []scanner.Finding{},
				Repo:        "test/repo",
				GitRef:      "main",
				GeneratedAt: time.Now(),
			},
			wantError: false,
		},
		{
			name: "empty repo",
			payload: &Payload{
				RunID:       "test-run",
				Summary:     "test summary",
				Findings:    []scanner.Finding{},
				Repo:        "",
				GitRef:      "main",
				GeneratedAt: time.Now(),
			},
			wantError: false,
		},
		{
			name: "empty gitRef",
			payload: &Payload{
				RunID:       "test-run",
				Summary:     "test summary",
				Findings:    []scanner.Finding{},
				Repo:        "test/repo",
				GitRef:      "",
				GeneratedAt: time.Now(),
			},
			wantError: false,
		},
		{
			name: "nil findings",
			payload: &Payload{
				RunID:       "test-run",
				Summary:     "test summary",
				Findings:    nil,
				Repo:        "test/repo",
				GitRef:      "main",
				GeneratedAt: time.Now(),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wh.Send(tt.payload)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWebhookTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	wh := NewWebhook(ts.URL, "test-secret")
	payload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test/repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
	}

	err := wh.Send(payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestWebhookInvalidURL(t *testing.T) {
	wh := NewWebhook("invalid-url", "test-secret")
	payload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test/repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
	}

	err := wh.Send(payload)
	assert.Error(t, err)
}

func TestWebhookNonceExpiry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	wh := NewWebhook(ts.URL, "test-secret")
	payload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test/repo",
		GitRef:      "main",
		GeneratedAt: time.Now().Add(-24 * time.Hour),
	}

	err := wh.Send(payload)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}
