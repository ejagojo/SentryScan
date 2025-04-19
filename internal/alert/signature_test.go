package alert

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/ejagojo/SentryScan/internal/scanner"
	"github.com/stretchr/testify/assert"
)

func TestSignatureVerification(t *testing.T) {
	wh := NewWebhook("http://example.com", "test-secret")

	// Set a fixed nonce for testing
	testNonce = "test-nonce"
	defer func() { testNonce = "" }()

	// Create a valid payload
	payload := &Payload{
		RunID:       "test-run",
		Summary:     "Test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
		Nonce:       testNonce,
	}

	// Sign the payload
	signature, err := wh.signPayload(payload)
	assert.NoError(t, err)
	payload.Sign = signature

	// Test 1: Verify valid signature
	err = wh.verifySignature(payload)
	assert.NoError(t, err, "Valid signature should pass verification")

	// Test 2: Verify tampered payload
	tamperedPayload := *payload
	tamperedPayload.Summary = "Tampered summary"
	tamperedPayload.Nonce = "test-nonce-2"
	err = wh.verifySignature(&tamperedPayload)
	assert.Error(t, err, "Tampered payload should fail verification")
	assert.Contains(t, err.Error(), "signature verification failed", "Error should indicate signature verification failure")

	// Test 3: Verify expired timestamp
	expiredPayload := *payload
	expiredPayload.GeneratedAt = time.Now().Add(-maxAge - time.Second)
	expiredPayload.Nonce = "test-nonce-3"
	err = wh.verifySignature(&expiredPayload)
	assert.Error(t, err, "Expired payload should fail verification")
	assert.Contains(t, err.Error(), "timestamp expired", "Error should indicate timestamp expiration")
}

func TestConstantTimeCompare(t *testing.T) {
	wh := NewWebhook("http://example.com", "test-secret")

	// Set a fixed nonce for testing
	testNonce = "test-nonce"
	defer func() { testNonce = "" }()

	payload := &Payload{
		RunID:       "test-run",
		Summary:     "Test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
		Nonce:       testNonce,
	}

	// Generate valid signature
	signature, err := wh.signPayload(payload)
	assert.NoError(t, err)
	payload.Sign = signature

	// Test that verification takes constant time
	start := time.Now()
	err = wh.verifySignature(payload)
	assert.NoError(t, err)
	validTime := time.Since(start)

	// Test with invalid signature
	invalidPayload := &Payload{
		RunID:       "test-run",
		Summary:     "Test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test-repo",
		GitRef:      "main",
		GeneratedAt: payload.GeneratedAt,
		Nonce:       "test-nonce-2",
		Sign: &Signature{
			Algorithm: signature.Algorithm,
			Value:     "invalid-signature",
		},
	}

	start = time.Now()
	err = wh.verifySignature(invalidPayload)
	assert.Error(t, err)
	invalidTime := time.Since(start)

	// Compare times - they should be within 50% of each other
	ratio := float64(validTime) / float64(invalidTime)
	if ratio < 0.5 || ratio > 1.5 {
		t.Errorf("Timing attack possible: valid/invalid ratio = %f", ratio)
	}
}

func BenchmarkSignatureVerification(b *testing.B) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		b.Fatalf("failed to generate secret: %v", err)
	}

	wh := NewWebhook("http://example.com", string(secret))

	// Set a fixed nonce for testing
	testNonce = "test-nonce"
	defer func() { testNonce = "" }()

	payload := &Payload{
		RunID:       "test-run",
		Summary:     "test summary",
		Findings:    []scanner.Finding{},
		Repo:        "test/repo",
		GitRef:      "main",
		GeneratedAt: time.Now(),
		Nonce:       testNonce,
	}

	signature, err := wh.signPayload(payload)
	if err != nil {
		b.Fatalf("failed to sign payload: %v", err)
	}
	payload.Sign = signature

	// Benchmark successful verification
	b.Run("success", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			wh.verifySignature(payload)
		}
	})

	// Benchmark failed verification (single byte difference)
	tamperedPayload := *payload
	tamperedPayload.Summary = "tampered summary"
	tamperedPayload.Nonce = "test-nonce-2"
	b.Run("failure", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			wh.verifySignature(&tamperedPayload)
		}
	})

	// Compare timing difference
	successTime := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			wh.verifySignature(payload)
		}
	}).NsPerOp()

	failureTime := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			wh.verifySignature(&tamperedPayload)
		}
	}).NsPerOp()

	// Calculate timing difference percentage
	diff := float64(failureTime-successTime) / float64(successTime) * 100
	if diff > 25 {
		b.Errorf("timing difference too large: %.2f%%", diff)
	}
}
