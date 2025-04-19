//go:build fuzz
// +build fuzz

package gitx

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func FuzzChangedFiles(f *testing.F) {
	// Add seed corpora from testdata/fuzz/git
	seedDir := "testdata/fuzz/git"
	if err := os.MkdirAll(seedDir, 0755); err != nil {
		t.Fatalf("failed to create seed directory: %v", err)
	}

	// Create some basic git repo seeds
	seeds := []struct {
		name    string
		content []byte
	}{
		{
			name: "empty.zip",
			content: createZipArchive(t, map[string][]byte{
				".git/HEAD": []byte("ref: refs/heads/main\n"),
			}),
		},
		{
			name: "single_file.zip",
			content: createZipArchive(t, map[string][]byte{
				".git/HEAD":            []byte("ref: refs/heads/main\n"),
				"file.txt":             []byte("content\n"),
				".git/objects/abc":     []byte("dummy object\n"),
				".git/refs/heads/main": []byte("abc\n"),
			}),
		},
	}

	for _, seed := range seeds {
		seedPath := filepath.Join(seedDir, seed.name)
		if err := os.WriteFile(seedPath, seed.content, 0644); err != nil {
			t.Fatalf("failed to write seed file: %v", err)
		}
		f.Add(seed.content)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a temporary directory for the test
		dir := t.TempDir()

		// Try to extract the zip data
		zipReader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			// Invalid zip data, skip this test case
			return
		}

		// Extract the zip to the temp directory
		for _, file := range zipReader.File {
			path := filepath.Join(dir, file.Name)
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}

			rc, err := file.Open()
			if err != nil {
				t.Fatalf("failed to open zip file: %v", err)
			}

			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Fatalf("failed to read zip file: %v", err)
			}

			if err := os.WriteFile(path, content, 0644); err != nil {
				t.Fatalf("failed to write file: %v", err)
			}
		}

		// Try to get changed files
		files, err := ChangedFiles(dir, "HEAD~1", "HEAD")
		if err != nil {
			// We expect some errors from invalid git repos, but we want to catch
			// panics and other unexpected errors
			return
		}

		// Basic validation of results
		for _, file := range files {
			if file == "" {
				t.Error("empty file path in results")
			}
			if !filepath.IsAbs(file) {
				t.Errorf("relative file path in results: %s", file)
			}
		}
	})
}

func createZipArchive(t *testing.T, files map[string][]byte) []byte {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed to create zip entry: %v", err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("failed to write zip entry: %v", err)
		}
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	return buf.Bytes()
}
