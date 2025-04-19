package rules

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config represents the SentryScan configuration
type Config struct {
	Rules []RuleConfig `yaml:"rules"`
}

// RuleConfig defines a rule in the configuration
type RuleConfig struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
	Severity    string `yaml:"severity"`
	Pattern     string `yaml:"pattern"`
}

// LoadConfig loads the configuration from a file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// DefaultConfigPath returns the default configuration file path
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".sentryscan.yml"
	}
	return filepath.Join(home, ".sentryscan.yml")
}

// SaveConfig saves the configuration to a file
func SaveConfig(config *Config, path string) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
