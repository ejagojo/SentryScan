package gitx

import (
	"errors"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ErrInvalidRange is returned when the from commit is after the to commit
var ErrInvalidRange = errors.New("from commit is after to commit")

// ChangedFiles returns a list of files that have changed since the given revision
func ChangedFiles(repoPath string, since string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	// Get the HEAD commit
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}

	// Get the commit to compare against
	var sinceCommit *object.Commit
	if since != "" {
		hash, err := repo.ResolveRevision(plumbing.Revision(since))
		if err != nil {
			return nil, err
		}
		sinceCommit, err = repo.CommitObject(*hash)
		if err != nil {
			return nil, err
		}
	}

	// Get the current commit
	currentCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, err
	}

	// If no since commit specified, return all files
	if sinceCommit == nil {
		return getAllFiles(repo, currentCommit)
	}

	// Get the diff between commits
	patch, err := sinceCommit.Patch(currentCommit)
	if err != nil {
		return nil, err
	}

	// Extract changed files
	var files []string
	for _, fileStat := range patch.Stats() {
		files = append(files, fileStat.Name)
	}

	return files, nil
}

// FilesInRange returns all files in the given commit range
func FilesInRange(repoPath, from, to string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, err
	}

	// Resolve the commit hashes
	fromHash, err := repo.ResolveRevision(plumbing.Revision(from))
	if err != nil {
		return nil, err
	}

	toHash, err := repo.ResolveRevision(plumbing.Revision(to))
	if err != nil {
		return nil, err
	}

	// Get the commits
	fromCommit, err := repo.CommitObject(*fromHash)
	if err != nil {
		return nil, err
	}

	toCommit, err := repo.CommitObject(*toHash)
	if err != nil {
		return nil, err
	}

	// Check if from is after to
	if fromCommit.Committer.When.After(toCommit.Committer.When) {
		return nil, ErrInvalidRange
	}

	// Get all files in the range
	var files []string
	seen := make(map[string]bool)

	err = object.NewCommitPreorderIter(toCommit, nil, nil).ForEach(func(c *object.Commit) error {
		if c.Hash == fromCommit.Hash {
			// Return nil to stop iteration without error
			return nil
		}

		tree, err := c.Tree()
		if err != nil {
			return err
		}

		err = tree.Files().ForEach(func(f *object.File) error {
			if !seen[f.Name] {
				files = append(files, f.Name)
				seen[f.Name] = true
			}
			return nil
		})

		return err
	})

	return files, err
}

// Helper function to get all files in a commit
func getAllFiles(repo *git.Repository, commit *object.Commit) ([]string, error) {
	var files []string
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}

	err = tree.Files().ForEach(func(f *object.File) error {
		files = append(files, f.Name)
		return nil
	})

	return files, err
}
