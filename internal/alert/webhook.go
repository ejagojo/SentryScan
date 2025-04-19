package alert

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ejagojo/SentryScan/internal/scanner"
)

const (
	maxRetries = 3
	baseDelay  = 500 * time.Millisecond
	maxAge     = 10 * time.Minute
	nonceSize  = 32
)

// For testing purposes
var (
	replayTimeout = maxAge
	testNonce     = ""
)

// Webhook represents a webhook alert configuration
type Webhook struct {
	url      string
	secret   []byte
	client   *http.Client
	nonces   map[string]time.Time
	nonceMux sync.RWMutex
}

// NewWebhook creates a new webhook alert instance
func NewWebhook(url string, secret string) *Webhook {
	return &Webhook{
		url:    url,
		secret: []byte(secret),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		nonces: make(map[string]time.Time),
	}
}

// Payload represents the webhook payload
type Payload struct {
	RunID       string            `json:"run_id"`
	Summary     string            `json:"summary"`
	Findings    []scanner.Finding `json:"findings"`
	Repo        string            `json:"repo"`
	GitRef      string            `json:"git_ref"`
	GeneratedAt time.Time         `json:"generated_at"`
	Nonce       string            `json:"nonce"`
	Sign        *Signature        `json:"signature,omitempty"`
}

// Signature represents the HMAC signature
type Signature struct {
	Algorithm string `json:"alg"`
	Value     string `json:"sig"`
}

// generateNonce creates a new random nonce
func (w *Webhook) generateNonce() (string, error) {
	if testNonce != "" {
		return testNonce, nil
	}
	nonceBytes := make([]byte, nonceSize)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}
	return hex.EncodeToString(nonceBytes), nil
}

// isNonceUsed checks if a nonce has been used and not expired
func (w *Webhook) isNonceUsed(nonce string) bool {
	w.nonceMux.RLock()
	timestamp, exists := w.nonces[nonce]
	w.nonceMux.RUnlock()

	if !exists {
		return false
	}

	// If the nonce has expired, remove it and return false
	if time.Since(timestamp) > maxAge {
		w.nonceMux.Lock()
		delete(w.nonces, nonce)
		w.nonceMux.Unlock()
		return false
	}

	return true
}

// cleanupNonces removes expired nonces
func (w *Webhook) cleanupNonces() {
	w.nonceMux.Lock()
	defer w.nonceMux.Unlock()

	now := time.Now()
	for nonce, timestamp := range w.nonces {
		if now.Sub(timestamp) > maxAge {
			delete(w.nonces, nonce)
		}
	}
}

// storeNonce stores a nonce with its timestamp
func (w *Webhook) storeNonce(nonce string, timestamp time.Time) {
	w.nonceMux.Lock()
	w.nonces[nonce] = timestamp
	w.nonceMux.Unlock()
}

// Send sends a webhook alert with the given findings
func (w *Webhook) Send(payload *Payload) error {
	// Check if payload is too old
	if time.Since(payload.GeneratedAt) > maxAge {
		return fmt.Errorf("payload timestamp expired")
	}

	// Generate and set nonce
	nonce, err := w.generateNonce()
	if err != nil {
		return err
	}
	payload.Nonce = nonce

	// Sign the payload
	signature, err := w.signPayload(payload)
	if err != nil {
		return fmt.Errorf("failed to sign payload: %v", err)
	}
	payload.Sign = signature

	// Check for replay attack
	if w.isNonceUsed(nonce) {
		return fmt.Errorf("replay attack detected")
	}

	// Store nonce
	w.storeNonce(nonce, payload.GeneratedAt)

	// Periodically cleanup old nonces
	go w.cleanupNonces()

	// Marshal payload
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Send with retries
	var lastErr error
	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequest("POST", w.url, bytes.NewReader(jsonPayload))
		if err != nil {
			return fmt.Errorf("failed to create request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := w.client.Do(req)
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration(i+1) * baseDelay)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("server returned status %d", resp.StatusCode)
		time.Sleep(time.Duration(i+1) * baseDelay)
	}

	return fmt.Errorf("failed after %d retries: %v", maxRetries, lastErr)
}

// signPayload creates an HMAC-SHA256 signature for the payload
func (w *Webhook) signPayload(payload *Payload) (*Signature, error) {
	// Clear existing signature for signing
	origSig := payload.Sign
	payload.Sign = nil

	// Marshal payload
	data, err := json.Marshal(payload)
	if err != nil {
		payload.Sign = origSig
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Restore original signature
	payload.Sign = origSig

	// Create HMAC
	mac := hmac.New(sha256.New, w.secret)
	mac.Write(data)
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return &Signature{
		Algorithm: "HMAC-SHA256",
		Value:     signature,
	}, nil
}

// verifySignature verifies the HMAC signature of a payload
func (w *Webhook) verifySignature(payload *Payload) error {
	// Check if payload is too old
	if time.Since(payload.GeneratedAt) > maxAge {
		return fmt.Errorf("timestamp expired")
	}

	if payload.Sign == nil {
		return fmt.Errorf("no signature provided")
	}

	if payload.Sign.Algorithm != "HMAC-SHA256" {
		return fmt.Errorf("unsupported signature algorithm: %s", payload.Sign.Algorithm)
	}

	// Store and clear signature for verification
	origSig := payload.Sign
	payload.Sign = nil

	// Marshal payload
	data, err := json.Marshal(payload)
	if err != nil {
		payload.Sign = origSig
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Restore original signature
	payload.Sign = origSig

	// Create HMAC
	mac := hmac.New(sha256.New, w.secret)
	mac.Write(data)
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Compare signatures using constant time comparison
	if !hmac.Equal([]byte(origSig.Value), []byte(expectedSig)) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
