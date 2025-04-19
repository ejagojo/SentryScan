package gitx

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type repoOp struct {
	commitMsg string
	files     map[string]string
}

// makeRepo creates a temporary Git repository for testing
func makeRepo(t *testing.T, cases ...repoOp) (string, map[string]plumbing.Hash) {
	t.Helper()

	// Create temp directory
	dir, err := os.MkdirTemp("", "gitx-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })

	// Initialize repo
	repo, err := git.PlainInit(dir, false)
	require.NoError(t, err)

	// Create worktree
	wt, err := repo.Worktree()
	require.NoError(t, err)

	commits := make(map[string]plumbing.Hash)

	// Process each case
	for _, op := range cases {
		// Write files
		for name, content := range op.files {
			path := filepath.Join(dir, name)
			err := os.MkdirAll(filepath.Dir(path), 0755)
			require.NoError(t, err)
			err = os.WriteFile(path, []byte(content), 0644)
			require.NoError(t, err)
			_, err = wt.Add(name)
			require.NoError(t, err)
		}

		// Commit
		hash, err := wt.Commit(op.commitMsg, &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test",
				Email: "test@example.com",
			},
		})
		require.NoError(t, err)
		commits[op.commitMsg] = hash
	}

	return dir, commits
}

// addAndCommit adds a file with the given content and commits it
func addAndCommit(t *testing.T, repo *git.Repository, filename, content, message string) plumbing.Hash {
	// Create worktree
	w, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}

	// Write file
	filePath := filepath.Join(w.Filesystem.Root(), filename)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	// Add file
	_, err = w.Add(filename)
	if err != nil {
		t.Fatalf("Failed to add file: %v", err)
	}

	// Commit
	hash, err := w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test User",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Failed to commit: %v", err)
	}

	return hash
}

func TestChangedFiles_EmptyRepo(t *testing.T) {
	dir, _ := makeRepo(t)

	files, err := ChangedFiles(dir, "HEAD")
	if err != nil {
		t.Fatalf("ChangedFiles() error = %v", err)
	}
	if len(files) != 0 {
		t.Errorf("ChangedFiles() = %v, want empty slice", files)
	}
}

func TestChangedFiles_SingleCommit(t *testing.T) {
	dir, repo := makeRepo(t)

	// Add a file
	hash := addAndCommit(t, repo, "test.txt", "test content", "initial commit")

	// Get changed files
	files, err := ChangedFiles(dir, hash.String())
	if err != nil {
		t.Fatalf("ChangedFiles() error = %v", err)
	}
	if len(files) != 0 {
		t.Errorf("ChangedFiles() = %v, want empty slice (no changes since commit)", files)
	}

	// Add another file
	addAndCommit(t, repo, "test2.txt", "more content", "second commit")

	// Get changed files since first commit
	files, err = ChangedFiles(dir, hash.String())
	if err != nil {
		t.Fatalf("ChangedFiles() error = %v", err)
	}
	if len(files) != 1 || files[0] != "test2.txt" {
		t.Errorf("ChangedFiles() = %v, want [test2.txt]", files)
	}
}

func TestChangedFiles_BinaryFile(t *testing.T) {
	dir, repo := makeRepo(t)

	// Add a binary file
	hash := addAndCommit(t, repo, "binary.bin", "\x00\xFF\x00\xFF", "add binary")

	// Get changed files
	files, err := ChangedFiles(dir, hash.String())
	if err != nil {
		t.Fatalf("ChangedFiles() error = %v", err)
	}
	if len(files) != 0 {
		t.Errorf("ChangedFiles() = %v, want empty slice (no changes since commit)", files)
	}
}

func TestFilesInRange(t *testing.T) {
	tests := []struct {
		name    string
		setup   []repoOp
		from    string
		to      string
		want    []string
		wantErr error
	}{
		{
			name: "BasicRange",
			setup: []repoOp{
				{
					commitMsg: "initial",
					files: map[string]string{
						"a.txt": "content a",
					},
				},
				{
					commitMsg: "second",
					files: map[string]string{
						"b.txt": "content b",
					},
				},
			},
			from: "initial",
			to:   "second",
			want: []string{"b.txt"},
		},
		{
			name: "MultiBranch",
			setup: []repoOp{
				{
					commitMsg: "main-1",
					files: map[string]string{
						"main.txt": "main content",
					},
				},
				{
					commitMsg: "feature-1",
					files: map[string]string{
						"feature.txt": "feature content",
					},
				},
				{
					commitMsg: "main-2",
					files: map[string]string{
						"main2.txt": "main2 content",
					},
				},
			},
			from: "main-1",
			to:   "main-2",
			want: []string{"feature.txt", "main2.txt"},
		},
		{
			name: "BinaryIgnored",
			setup: []repoOp{
				{
					commitMsg: "initial",
					files: map[string]string{
						"text.txt": "text content",
					},
				},
				{
					commitMsg: "binary",
					files: map[string]string{
						"binary.pdf": string(make([]byte, 1024*1024)), // 1MB binary content
					},
				},
			},
			from: "initial",
			to:   "binary",
			want: []string{"text.txt"},
		},
		{
			name: "FromEqualsTo",
			setup: []repoOp{
				{
					commitMsg: "single",
					files: map[string]string{
						"file.txt": "content",
					},
				},
			},
			from: "single",
			to:   "single",
			want: []string{},
		},
		{
			name: "OutOfOrderArgs",
			setup: []repoOp{
				{
					commitMsg: "old",
					files: map[string]string{
						"old.txt": "old",
					},
				},
				{
					commitMsg: "new",
					files: map[string]string{
						"new.txt": "new",
					},
				},
			},
			from:    "new",
			to:      "old",
			wantErr: ErrInvalidRange,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoPath, commits := makeRepo(t, tt.setup...)

			fromHash := commits[tt.from].String()
			toHash := commits[tt.to].String()

			got, err := FilesInRange(repoPath, fromHash, toHash)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestChangedFiles(t *testing.T) {
	tests := []struct {
		name    string
		setup   []repoOp
		since   string
		want    []string
		wantErr error
	}{
		{
			name: "SinceInitial",
			setup: []repoOp{
				{
					commitMsg: "initial",
					files: map[string]string{
						"a.txt": "a",
					},
				},
				{
					commitMsg: "second",
					files: map[string]string{
						"b.txt": "b",
					},
				},
			},
			since: "initial",
			want:  []string{"b.txt"},
		},
		{
			name: "NoSince",
			setup: []repoOp{
				{
					commitMsg: "initial",
					files: map[string]string{
						"a.txt": "a",
					},
				},
			},
			since: "",
			want:  []string{"a.txt"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repoPath, commits := makeRepo(t, tt.setup...)

			var sinceHash string
			if tt.since != "" {
				sinceHash = commits[tt.since].String()
			}

			got, err := ChangedFiles(repoPath, sinceHash)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

func TestChangedFiles_NonExistentRepo(t *testing.T) {
	_, err := ChangedFiles("/nonexistent/repo", "")
	if err == nil {
		t.Error("ChangedFiles() expected error for non-existent repo")
	}
}

func TestFilesInRange_NonExistentRepo(t *testing.T) {
	_, err := FilesInRange("/nonexistent/repo", "a", "b")
	if err == nil {
		t.Error("FilesInRange() expected error for non-existent repo")
	}
}
