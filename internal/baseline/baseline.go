package baseline

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ejagojo/SentryScan/internal/scanner"
)

const (
	baselineFileName = ".sentryscan_baseline.json"
)

// Baseline represents the suppression file
type Baseline struct {
	Version   string    `json:"version"`
	CreatedBy string    `json:"createdBy"`
	CreatedAt time.Time `json:"createdAt"`
	Findings  []Finding `json:"findings"`
}

// Finding represents a suppressed finding
type Finding struct {
	RuleID      string `json:"ruleId"`
	Path        string `json:"path"`
	Line        int    `json:"line"`
	Fingerprint string `json:"fingerprint"`
}

// Load loads the baseline file from the given directory
func Load(dir string) (*Baseline, error) {
	path := filepath.Join(dir, baselineFileName)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Baseline{
				Version:   "1.0",
				CreatedAt: time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("failed to read baseline file: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("failed to parse baseline file: %w", err)
	}

	return &baseline, nil
}

// Save saves the baseline file to the given directory
func (b *Baseline) Save(dir string) error {
	path := filepath.Join(dir, baselineFileName)
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// Add adds a finding to the baseline
func (b *Baseline) Add(finding scanner.Finding) error {
	fp := fingerprint(finding)
	for _, f := range b.Findings {
		if f.Fingerprint == fp {
			return fmt.Errorf("finding already in baseline")
		}
	}

	b.Findings = append(b.Findings, Finding{
		RuleID:      finding.RuleID,
		Path:        finding.Path,
		Line:        finding.Line,
		Fingerprint: fp,
	})

	return nil
}

// IsSuppressed checks if a finding is suppressed in the baseline
func (b *Baseline) IsSuppressed(finding scanner.Finding) bool {
	fp := fingerprint(finding)
	for _, f := range b.Findings {
		if f.Fingerprint == fp {
			return true
		}
	}
	return false
}

// Filter filters out suppressed findings
func (b *Baseline) Filter(findings []scanner.Finding) []scanner.Finding {
	var filtered []scanner.Finding
	for _, f := range findings {
		if !b.IsSuppressed(f) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// fingerprint generates a unique fingerprint for a finding
func fingerprint(finding scanner.Finding) string {
	h := sha256.New()
	h.Write([]byte(finding.RuleID))
	h.Write([]byte(finding.Path))
	h.Write([]byte(fmt.Sprintf("%d", finding.Line)))
	return fmt.Sprintf("%x", h.Sum(nil))
}
