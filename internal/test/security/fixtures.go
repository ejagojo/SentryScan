package security

import (
	"archive/zip"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// CreateZipBomb creates a small ZIP file that expands to a large size
func CreateZipBomb(t *testing.T, outputPath string, targetSize int64) {
	t.Helper()

	f, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("failed to create zip bomb: %v", err)
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	// Create a file that will expand to targetSize
	w, err := zw.Create("bomb.txt")
	if err != nil {
		t.Fatalf("failed to create zip entry: %v", err)
	}

	// Write RLE-encoded data that expands to targetSize
	const blockSize = 1024
	block := make([]byte, blockSize)
	if _, err := rand.Read(block); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	// Write count followed by data
	count := targetSize / blockSize
	if err := binary.Write(w, binary.LittleEndian, count); err != nil {
		t.Fatalf("failed to write count: %v", err)
	}
	if _, err := w.Write(block); err != nil {
		t.Fatalf("failed to write block: %v", err)
	}
}

// CreateSymlinkLoop creates a directory with a symlink loop
func CreateSymlinkLoop(t *testing.T, dir string) {
	t.Helper()

	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")

	if err := os.Symlink(b, a); err != nil {
		t.Fatalf("failed to create symlink a: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatalf("failed to create symlink b: %v", err)
	}
}

// CreatePathTraversal creates a file with a path traversal attempt
func CreatePathTraversal(t *testing.T, dir string) string {
	t.Helper()

	evil := filepath.Join(dir, "weird-paths", "..", "..", "evil.txt")
	if err := os.MkdirAll(filepath.Dir(evil), 0755); err != nil {
		t.Fatalf("failed to create directories: %v", err)
	}

	if err := os.WriteFile(evil, []byte("evil content"), 0644); err != nil {
		t.Fatalf("failed to create evil file: %v", err)
	}

	return evil
}

// CreateBinaryBomb creates a file that looks like a binary bomb
func CreateBinaryBomb(t *testing.T, outputPath string) {
	t.Helper()

	f, err := os.Create(outputPath)
	if err != nil {
		t.Fatalf("failed to create binary bomb: %v", err)
	}
	defer f.Close()

	// Write ELF header
	header := []byte{
		0x7f, 0x45, 0x4c, 0x46, // ELF magic
		0x02,                   // 64-bit
		0x01,                   // Little endian
		0x01,                   // Version 1
		0x00,                   // System V ABI
		0x00, 0x00, 0x00, 0x00, // Padding
		0x02, 0x00, // Executable
		0x3e, 0x00, // x86-64
		0x01, 0x00, 0x00, 0x00, // Version 1
	}

	if _, err := f.Write(header); err != nil {
		t.Fatalf("failed to write ELF header: %v", err)
	}

	// Write infinite loop
	loop := []byte{
		0xeb, 0xfe, // jmp -2
	}

	if _, err := f.Write(loop); err != nil {
		t.Fatalf("failed to write infinite loop: %v", err)
	}
}

// CreatePoisonedGit creates a Git repo with malicious content
func CreatePoisonedGit(t *testing.T, dir string) {
	t.Helper()

	// Create a file with null bytes in the name
	nullFile := filepath.Join(dir, "file\x00with\x00nulls.txt")
	if err := os.WriteFile(nullFile, []byte("content"), 0644); err != nil {
		t.Fatalf("failed to create null file: %v", err)
	}

	// Create a deep directory structure
	deepDir := dir
	for i := 0; i < 100; i++ {
		deepDir = filepath.Join(deepDir, "deep")
	}
	if err := os.MkdirAll(deepDir, 0755); err != nil {
		t.Fatalf("failed to create deep directory: %v", err)
	}

	// Create a file in the deep directory
	if err := os.WriteFile(filepath.Join(deepDir, "file.txt"), []byte("deep content"), 0644); err != nil {
		t.Fatalf("failed to create deep file: %v", err)
	}
}
