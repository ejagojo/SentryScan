package scanner

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ScannerConfig represents the scanner configuration
type ScannerConfig struct {
	Image          string       `yaml:"image,omitempty"`
	CompareImage   string       `yaml:"compare,omitempty"`
	NoBaseline     bool         `yaml:"no_baseline,omitempty"`
	WebhookURL     string       `yaml:"webhook_url,omitempty"`
	WebhookSecret  string       `yaml:"webhook_secret,omitempty"`
	SeverityThresh string       `yaml:"severity,omitempty"`
	Rules          []RuleConfig `yaml:"rules"`
}

// RuleConfig represents a scanning rule
type RuleConfig struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Pattern     string `yaml:"pattern"`
}

// DefaultConfigPath returns the default path to the configuration file
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sentryscan.yaml"
	}
	return filepath.Join(home, ".sentryscan.yaml")
}

// LoadConfig loads the scanner configuration from the given path
func LoadConfig(path string) (*ScannerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &ScannerConfig{
				SeverityThresh: "high",
			}, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config ScannerConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Set defaults
	if config.SeverityThresh == "" {
		config.SeverityThresh = "high"
	}

	return &config, nil
}

// SaveConfig saves the scanner configuration to the given path
func SaveConfig(config *ScannerConfig, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// MergeConfig merges environment variables and flags into the config
func MergeConfig(config *ScannerConfig, flags map[string]interface{}) *ScannerConfig {
	merged := *config

	// Environment variables take precedence over config file
	if url := os.Getenv("SENTRYSCAN_WEBHOOK_URL"); url != "" {
		merged.WebhookURL = url
	}
	if secret := os.Getenv("SENTRYSCAN_WEBHOOK_SECRET"); secret != "" {
		merged.WebhookSecret = secret
	}

	// Command line flags take precedence over everything
	for k, v := range flags {
		switch k {
		case "image":
			if s, ok := v.(string); ok && s != "" {
				merged.Image = s
			}
		case "compare":
			if s, ok := v.(string); ok && s != "" {
				merged.CompareImage = s
			}
		case "no-baseline":
			if b, ok := v.(bool); ok {
				merged.NoBaseline = b
			}
		case "webhook-url":
			if s, ok := v.(string); ok && s != "" {
				merged.WebhookURL = s
			}
		case "webhook-secret":
			if s, ok := v.(string); ok && s != "" {
				merged.WebhookSecret = s
			}
		case "severity":
			if s, ok := v.(string); ok && s != "" {
				merged.SeverityThresh = s
			}
		}
	}

	return &merged
}
