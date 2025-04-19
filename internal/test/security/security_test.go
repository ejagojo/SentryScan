package security

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ejagojo/SentryScan/internal/scanner"
)

func TestZipBomb(t *testing.T) {
	// Create a temporary directory for the test
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "bomb.zip")

	// Create a 1GB zip bomb
	CreateZipBomb(t, zipPath, 1<<30)

	// Create scanner config
	config := &scanner.ScannerConfig{
		Path: dir,
	}

	// Create scanner
	s, err := scanner.NewScanner(config)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	// Set a timeout for the scan
	timeout := time.After(5 * time.Second)
	done := make(chan bool)

	go func() {
		_, err := s.Scan()
		if err == nil {
			t.Error("expected error from zip bomb")
		}
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("scan timed out - zip bomb protection failed")
	case <-done:
		// Success - scan completed within timeout
	}
}

func TestSymlinkLoop(t *testing.T) {
	dir := t.TempDir()
	CreateSymlinkLoop(t, dir)

	config := &scanner.ScannerConfig{
		Path: dir,
	}

	s, err := scanner.NewScanner(config)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	_, err = s.Scan()
	if err == nil {
		t.Error("expected error from symlink loop")
	}
}

func TestPathTraversal(t *testing.T) {
	dir := t.TempDir()
	evilPath := CreatePathTraversal(t, dir)

	config := &scanner.ScannerConfig{
		Path: dir,
	}

	s, err := scanner.NewScanner(config)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	results, err := s.Scan()
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// Check that the evil file was not accessed
	if _, err := os.Stat(evilPath); err == nil {
		t.Error("path traversal succeeded - evil file was accessed")
	}

	// Check that the scan results don't include the evil file
	for _, finding := range results.Findings {
		if finding.Path == evilPath {
			t.Error("path traversal succeeded - evil file was included in results")
		}
	}
}

func TestBinaryBomb(t *testing.T) {
	dir := t.TempDir()
	bombPath := filepath.Join(dir, "bomb")
	CreateBinaryBomb(t, bombPath)

	config := &scanner.ScannerConfig{
		Path: dir,
	}

	s, err := scanner.NewScanner(config)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	timeout := time.After(5 * time.Second)
	done := make(chan bool)

	go func() {
		_, err := s.Scan()
		if err == nil {
			t.Error("expected error from binary bomb")
		}
		done <- true
	}()

	select {
	case <-timeout:
		t.Fatal("scan timed out - binary bomb protection failed")
	case <-done:
		// Success - scan completed within timeout
	}
}

func TestPoisonedGit(t *testing.T) {
	dir := t.TempDir()
	CreatePoisonedGit(t, dir)

	config := &scanner.ScannerConfig{
		Path: dir,
	}

	s, err := scanner.NewScanner(config)
	if err != nil {
		t.Fatalf("failed to create scanner: %v", err)
	}

	_, err = s.Scan()
	if err == nil {
		t.Error("expected error from poisoned git repo")
	}
}
