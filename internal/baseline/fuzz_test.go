//go:build fuzz
// +build fuzz

package baseline

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzLoad(f *testing.F) {
	// Add seed corpora
	seeds := []string{
		"{}",
		`{"findings":[]}`,
		`{"findings":[{"path":"test.txt","line":1,"rule_id":"test-rule"}]}`,
		// Invalid JSON
		"{",
		// Huge JSON
		string(make([]byte, 10*1024*1024)), // 10MB
	}

	for _, seed := range seeds {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temporary directory for the test
		dir := t.TempDir()
		filePath := filepath.Join(dir, "baseline.json")

		// Write the fuzzed data to a file
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		// Try to load the baseline
		baseline, err := Load(filePath)
		if err != nil {
			// We expect some errors from invalid JSON, but we want to catch
			// panics and other unexpected errors
			return
		}

		// Basic validation of results
		if baseline == nil {
			t.Error("nil baseline returned")
			return
		}

		// Validate findings if any
		for _, finding := range baseline.Findings {
			if finding.Path == "" {
				t.Error("finding has empty path")
			}
			if finding.RuleID == "" {
				t.Error("finding has empty rule ID")
			}
			if finding.Line < 0 {
				t.Errorf("negative line number: %d", finding.Line)
			}
		}
	})
}
