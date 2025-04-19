//go:build fuzz
// +build fuzz

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzScanFile(f *testing.F) {
	// Add seed corpora
	seedCorpora := []string{
		`{"key": "value"}`,
		`api_key: "1234567890"`,
		`password = "secret123"`,
		`aws_access_key_id = "AKIA1234567890"`,
		`export AWS_SECRET_ACCESS_KEY="abcdefghijklmnopqrstuvwxyz"`,
		`const token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"`,
		`resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  key_name      = "my-key"
}`,
	}

	for _, seed := range seedCorpora {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temporary directory for the test
		dir := t.TempDir()
		filePath := filepath.Join(dir, "testfile")

		// Write the fuzzed data to a file
		if err := os.WriteFile(filePath, data, 0644); err != nil {
			t.Fatalf("failed to write test file: %v", err)
		}

		// Create scanner config
		config := &ScannerConfig{
			Path: dir,
		}

		// Create scanner
		s, err := NewScanner(config)
		if err != nil {
			t.Fatalf("failed to create scanner: %v", err)
		}

		// Scan the file
		results, err := s.Scan()
		if err != nil {
			// We expect some errors from invalid input, but we want to catch
			// panics and other unexpected errors
			return
		}

		// Basic validation of results
		for _, finding := range results.Findings {
			if finding.Path == "" {
				t.Error("finding has empty path")
			}
			if finding.RuleID == "" {
				t.Error("finding has empty rule ID")
			}
			if finding.Severity == "" {
				t.Error("finding has empty severity")
			}
		}
	})
}
