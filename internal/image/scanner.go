package image

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/ejagojo/SentryScan/internal/scanner"
)

const (
	trivyCacheDir = "sentryscan/trivy"
	scanTimeout   = 60 * time.Second
)

// Scanner implements container image scanning using Trivy
type Scanner struct {
	cacheDir string
	client   *trivyScanner.Scanner
}

// NewScanner creates a new container image scanner
func NewScanner() (*Scanner, error) {
	cacheDir, err := getCacheDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get cache dir: %w", err)
	}

	client, err := trivyScanner.NewScanner(trivyScanner.ScannerOption{
		CacheDir: cacheDir,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Trivy scanner: %w", err)
	}

	return &Scanner{
		cacheDir: cacheDir,
		client:   client,
	}, nil
}

// Scan scans a container image for vulnerabilities
func (s *Scanner) Scan(ctx context.Context, imageRef string, compareRef string) ([]scanner.Finding, error) {
	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	// Scan the image
	results, err := s.client.ScanImage(ctx, imageRef)
	if err != nil {
		return nil, fmt.Errorf("failed to scan image: %w", err)
	}

	// If comparing with another image, get the diff
	if compareRef != "" {
		baseResults, err := s.client.ScanImage(ctx, compareRef)
		if err != nil {
			return nil, fmt.Errorf("failed to scan base image: %w", err)
		}
		results = diffResults(results, baseResults)
	}

	// Convert to SentryScan findings
	var findings []scanner.Finding
	for _, result := range results {
		if result.Severity == trivyTypes.SeverityCritical || result.Severity == trivyTypes.SeverityHigh {
			findings = append(findings, scanner.Finding{
				RuleID:      result.VulnerabilityID,
				Description: result.Description,
				Severity:    string(result.Severity),
				Path:        result.PkgName,
				Line:        0, // Container findings don't have line numbers
				Match:       fmt.Sprintf("Version: %s, Fixed: %s", result.InstalledVersion, result.FixedVersion),
			})
		}
	}

	return findings, nil
}

// getCacheDir returns the path to the Trivy cache directory
func getCacheDir() (string, error) {
	cacheDir := os.Getenv("XDG_CACHE_HOME")
	if cacheDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		cacheDir = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheDir, trivyCacheDir), nil
}

// diffResults returns only the vulnerabilities that are new in the target image
func diffResults(target, base []types.Result) []types.Result {
	baseVulns := make(map[string]struct{})
	for _, result := range base {
		for _, vuln := range result.Vulnerabilities {
			baseVulns[vuln.VulnerabilityID] = struct{}{}
		}
	}

	var diff []types.Result
	for _, result := range target {
		var newVulns []types.DetectedVulnerability
		for _, vuln := range result.Vulnerabilities {
			if _, exists := baseVulns[vuln.VulnerabilityID]; !exists {
				newVulns = append(newVulns, vuln)
			}
		}
		if len(newVulns) > 0 {
			result.Vulnerabilities = newVulns
			diff = append(diff, result)
		}
	}

	return diff
}
