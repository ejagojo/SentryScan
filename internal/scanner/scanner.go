package scanner

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
)

// ScannerOptions defines the configuration for scanning
type ScannerOptions struct {
	IncludeExt  []string
	ExcludeExt  []string
	MaxFileSize int64
	SkipHidden  bool
	Threads     int
	Since       string
	Branch      string
	CommitRange string
}

// Scanner defines the interface for all scanning operations
type Scanner interface {
	Run(ctx context.Context, opts ScannerOptions, paths ...string) ([]Finding, error)
	ScanFile(path string) ([]Finding, error)
	ScanReader(r io.Reader, meta SourceMeta) ([]Finding, error)
}

// SourceMeta contains metadata about the source being scanned
type SourceMeta struct {
	Path    string
	Line    int
	Column  int
	Context string
}

// SecretScanner implements the Scanner interface for secret detection
type SecretScanner struct {
	rules []Rule
	mu    sync.RWMutex
}

// Rule defines a detection rule
type Rule struct {
	ID          string
	Description string
	Severity    string
	Pattern     *regexp.Regexp
}

// Finding represents a detected secret or vulnerability
type Finding struct {
	Type        string
	RuleID      string
	Description string
	Severity    string
	Path        string
	Line        int
	Column      int
	Match       string
	Context     string
	Fingerprint string
}

// NewScanner creates a new Scanner instance
func NewScanner() *SecretScanner {
	return &SecretScanner{
		rules: []Rule{
			{
				ID:          "aws-access-key",
				Description: "AWS Access Key detected",
				Severity:    "high",
				Pattern:     regexp.MustCompile(`(?i)aws_access_key_id\s*=\s*['"]?([A-Z0-9]{20})['"]?`),
			},
			{
				ID:          "aws-secret-key",
				Description: "AWS Secret Key detected",
				Severity:    "critical",
				Pattern:     regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"]?([A-Za-z0-9/+=]{40})['"]?`),
			},
			{
				ID:          "generic-token",
				Description: "Generic token detected",
				Severity:    "medium",
				Pattern:     regexp.MustCompile(`(?i)(?:token|key|secret|password)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{32,})['"]?`),
			},
		},
	}
}

// Run executes the scanner with the given options and paths
func (s *SecretScanner) Run(ctx context.Context, opts ScannerOptions, paths ...string) ([]Finding, error) {
	if len(paths) == 0 {
		paths = []string{"."}
	}

	var findings []Finding
	var mu sync.Mutex
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(opts.Threads)

	for _, path := range paths {
		path := path
		g.Go(func() error {
			// Check if path is a git repository
			if isGitRepo(path) {
				return s.scanGitRepo(ctx, path, opts, &findings, &mu)
			}

			// Otherwise scan as filesystem
			return filepath.WalkDir(path, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() {
					if opts.SkipHidden && strings.HasPrefix(d.Name(), ".") {
						return filepath.SkipDir
					}
					return nil
				}

				// Check file extension
				ext := filepath.Ext(path)
				if len(opts.IncludeExt) > 0 && !contains(opts.IncludeExt, ext) {
					return nil
				}
				if contains(opts.ExcludeExt, ext) {
					return nil
				}

				// Check file size
				if info, err := d.Info(); err == nil && opts.MaxFileSize > 0 && info.Size() > opts.MaxFileSize {
					return nil
				}

				// Scan the file
				fileFindings, err := s.ScanFile(path)
				if err != nil {
					return err
				}

				mu.Lock()
				findings = append(findings, fileFindings...)
				mu.Unlock()

				return nil
			})
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return findings, nil
}

// ScanFile scans a file for secrets
func (s *SecretScanner) ScanFile(path string) ([]Finding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return s.ScanReader(file, SourceMeta{Path: path})
}

// ScanReader scans content from an io.Reader
func (s *SecretScanner) ScanReader(r io.Reader, meta SourceMeta) ([]Finding, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	lines := strings.Split(string(content), "\n")

	for i, line := range lines {
		for _, rule := range s.rules {
			matches := rule.Pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 {
					finding := Finding{
						Type:        "secret",
						RuleID:      rule.ID,
						Description: rule.Description,
						Severity:    rule.Severity,
						Path:        meta.Path,
						Line:        i + 1,
						Column:      strings.Index(line, match[1]) + 1,
						Match:       match[1],
						Context:     line,
						Fingerprint: fmt.Sprintf("%x", sha256.Sum256([]byte(match[1]))),
					}
					findings = append(findings, finding)
				}
			}
		}
	}

	return findings, nil
}

// Helper functions
func isGitRepo(path string) bool {
	_, err := os.Stat(filepath.Join(path, ".git"))
	return err == nil
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// scanGitRepo scans a git repository for secrets
func (s *SecretScanner) scanGitRepo(ctx context.Context, path string, opts ScannerOptions, findings *[]Finding, mu *sync.Mutex) error {
	// TODO: Implement git repository scanning
	return nil
}
