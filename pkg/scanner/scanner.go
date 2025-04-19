package scanner

import (
	"io"
	"regexp"
)

// Finding represents a detected secret or vulnerability
type Finding struct {
	Type        string
	RuleID      string
	Description string
	Severity    string
	Line        int
	Column      int
	Match       string
	Context     string
}

// Scanner defines the interface for all scanning operations
type Scanner interface {
	ScanFile(path string) ([]Finding, error)
	ScanReader(r io.Reader) ([]Finding, error)
}

// SecretScanner implements the Scanner interface for secret detection
type SecretScanner struct {
	rules []Rule
}

// Rule defines a detection rule
type Rule struct {
	ID          string
	Description string
	Severity    string
	Pattern     *regexp.Regexp
}

// NewSecretScanner creates a new SecretScanner instance
func NewSecretScanner() *SecretScanner {
	return &SecretScanner{
		rules: []Rule{
			{
				ID:          "api-key",
				Description: "API Key detected",
				Severity:    "high",
				Pattern:     regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)[\s:=]+['"]?([a-zA-Z0-9_-]{32,})['"]?`),
			},
			// Add more default rules here
		},
	}
}

// ScanFile scans a file for secrets
func (s *SecretScanner) ScanFile(path string) ([]Finding, error) {
	// TODO: Implement file scanning
	return nil, nil
}

// ScanReader scans content from an io.Reader
func (s *SecretScanner) ScanReader(r io.Reader) ([]Finding, error) {
	// TODO: Implement reader scanning
	return nil, nil
}
