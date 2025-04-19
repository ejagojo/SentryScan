package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestScanner_ScanFile(t *testing.T) {
	// Create a temporary test file
	dir := t.TempDir()
	filePath := filepath.Join(dir, "test.txt")
	content := `aws_access_key_id = "AKIAXXXXXXXXXXXXXXXX"
aws_secret_access_key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
password = "secret123456789012345678901234567890"
`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Initialize scanner
	s := NewScanner()

	// Scan the file
	findings, err := s.ScanFile(filePath)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Verify findings
	if len(findings) != 4 {
		t.Errorf("Expected 4 findings, got %d", len(findings))
	}

	// Check for AWS access key
	foundAccessKey := false
	for _, f := range findings {
		if f.RuleID == "aws-access-key" {
			foundAccessKey = true
			if f.Match != "AKIAXXXXXXXXXXXXXXXX" {
				t.Errorf("Expected AWS access key match, got %s", f.Match)
			}
		}
	}
	if !foundAccessKey {
		t.Error("Did not find AWS access key")
	}
}

func TestScanner_Run(t *testing.T) {
	// Create a temporary directory with test files
	dir := t.TempDir()

	// Create a test file with secrets
	file1 := filepath.Join(dir, "test1.txt")
	content1 := `aws_access_key_id = "AKIAXXXXXXXXXXXXXXXX"`
	if err := os.WriteFile(file1, []byte(content1), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Create another test file
	file2 := filepath.Join(dir, "test2.txt")
	content2 := `password = "secret123456789012345678901234567890"`
	if err := os.WriteFile(file2, []byte(content2), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Initialize scanner
	s := NewScanner()

	// Configure scanner options
	opts := ScannerOptions{
		Threads: 2,
	}

	// Run the scan
	findings, err := s.Run(context.Background(), opts, dir)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Verify findings
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}
}

func TestScanner_ScanReader(t *testing.T) {
	// Initialize scanner
	s := NewScanner()

	// Test content
	content := `aws_access_key_id = "AKIAXXXXXXXXXXXXXXXX"
password = "secret123456789012345678901234567890"
`
	meta := SourceMeta{
		Path: "test.txt",
	}

	// Scan the content
	findings, err := s.ScanReader(strings.NewReader(content), meta)
	if err != nil {
		t.Fatalf("ScanReader failed: %v", err)
	}

	// Verify findings
	if len(findings) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(findings))
	}

	// Check for AWS access key
	foundAccessKey := false
	for _, f := range findings {
		if f.RuleID == "aws-access-key" {
			foundAccessKey = true
			if f.Match != "AKIAXXXXXXXXXXXXXXXX" {
				t.Errorf("Expected AWS access key match, got %s", f.Match)
			}
		}
	}
	if !foundAccessKey {
		t.Error("Did not find AWS access key")
	}
}

func TestFileSizeBoundaries(t *testing.T) {
	dir := t.TempDir()

	// Create files at size boundaries
	sizes := []int64{
		MaxFileSize - 1,
		MaxFileSize,
		MaxFileSize + 1,
	}

	for _, size := range sizes {
		path := filepath.Join(dir, "test-"+string(size))
		f, err := os.Create(path)
		if err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}

		if err := f.Truncate(size); err != nil {
			t.Fatalf("failed to truncate file: %v", err)
		}
		f.Close()

		config := &ScannerConfig{
			Path: dir,
		}

		s, err := NewScanner(config)
		if err != nil {
			t.Fatalf("failed to create scanner: %v", err)
		}

		results, err := s.Scan()
		if err != nil {
			t.Fatalf("scan failed: %v", err)
		}

		// Files at or below MaxFileSize should be included
		if size <= MaxFileSize {
			found := false
			for _, finding := range results.Findings {
				if finding.Path == path {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("file of size %d was not scanned", size)
			}
		} else {
			// Files above MaxFileSize should be skipped
			for _, finding := range results.Findings {
				if finding.Path == path {
					t.Errorf("file of size %d was scanned when it should have been skipped", size)
				}
			}
		}
	}
}

func TestConcurrencySaturation(t *testing.T) {
	dir := t.TempDir()

	// Create 1000 small files to scan
	for i := 0; i < 1000; i++ {
		path := filepath.Join(dir, "file-"+string(i))
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	// Run 500 concurrent scans
	var wg sync.WaitGroup
	errors := make(chan error, 500)
	done := make(chan struct{})

	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			config := &ScannerConfig{
				Path: dir,
			}

			s, err := NewScanner(config)
			if err != nil {
				errors <- err
				return
			}

			if _, err := s.Scan(); err != nil {
				errors <- err
				return
			}
		}()
	}

	// Wait for all scans to complete or timeout
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All scans completed successfully
	case err := <-errors:
		t.Fatalf("scan failed: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("scans timed out - possible deadlock")
	}
}

func TestSignalInterrupt(t *testing.T) {
	dir := t.TempDir()

	// Create a large number of files to ensure scan takes time
	for i := 0; i < 10000; i++ {
		path := filepath.Join(dir, "file-"+string(i))
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatalf("failed to create test file: %v", err)
		}
	}

	config := &ScannerConfig{
		Path: dir,
	}

	s, err := NewScanner(config)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Start scan in background
	done := make(chan struct{})
	var scanErr error
	go func() {
		_, scanErr = s.Scan()
		close(done)
	}()

	// Wait a bit then send interrupt
	time.Sleep(100 * time.Millisecond)
	s.Stop()

	// Wait for graceful shutdown
	select {
	case <-done:
		if scanErr == nil {
			t.Error("scan completed successfully after interrupt")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not shut down within 2 seconds")
	}
}
