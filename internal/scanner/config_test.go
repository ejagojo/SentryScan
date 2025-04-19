package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T) string
		want        *Config
		wantErr     bool
		errContains string
	}{
		{
			name: "NoFile",
			setup: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "nonexistent.yaml")
			},
			want: &Config{
				Concurrency: 4,
				Rules: []RuleConfig{
					{
						ID:          "api-key",
						Description: "API Key detected",
						Severity:    "high",
						Pattern:     `(?i)(?:api[_-]?key|apikey)[\s:=]+['"]?([a-zA-Z0-9_-]{32,})['"]?`,
					},
				},
			},
		},
		{
			name: "OverrideConcurrency",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				configPath := filepath.Join(dir, "config.yaml")
				err := os.WriteFile(configPath, []byte(`
concurrency: 8
rules:
  - id: custom-rule
    description: Custom rule
    severity: medium
    pattern: "custom-pattern"
`), 0644)
				require.NoError(t, err)
				return configPath
			},
			want: &Config{
				Concurrency: 8,
				Rules: []RuleConfig{
					{
						ID:          "custom-rule",
						Description: "Custom rule",
						Severity:    "medium",
						Pattern:     "custom-pattern",
					},
				},
			},
		},
		{
			name: "DuplicateRuleIDs",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				configPath := filepath.Join(dir, "config.yaml")
				err := os.WriteFile(configPath, []byte(`
rules:
  - id: duplicate
    description: First
    severity: low
    pattern: "pattern1"
  - id: duplicate
    description: Second
    severity: medium
    pattern: "pattern2"
`), 0644)
				require.NoError(t, err)
				return configPath
			},
			wantErr:     true,
			errContains: "duplicate rule ID",
		},
		{
			name: "InvalidYAML",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				configPath := filepath.Join(dir, "config.yaml")
				err := os.WriteFile(configPath, []byte("invalid: yaml: content"), 0644)
				require.NoError(t, err)
				return configPath
			},
			wantErr:     true,
			errContains: "yaml",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := tt.setup(t)
			got, err := LoadConfig(configPath)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSaveConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "ValidConfig",
			config: &Config{
				Concurrency: 4,
				Rules: []RuleConfig{
					{
						ID:          "test-rule",
						Description: "Test rule",
						Severity:    "low",
						Pattern:     "test-pattern",
					},
				},
			},
		},
		{
			name: "DuplicateRuleIDs",
			config: &Config{
				Rules: []RuleConfig{
					{
						ID:          "duplicate",
						Description: "First",
						Severity:    "low",
						Pattern:     "pattern1",
					},
					{
						ID:          "duplicate",
						Description: "Second",
						Severity:    "medium",
						Pattern:     "pattern2",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			err := SaveConfig(tt.config, configPath)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)

			// Verify the saved config can be loaded
			loaded, err := LoadConfig(configPath)
			assert.NoError(t, err)
			assert.Equal(t, tt.config, loaded)
		})
	}
}

func TestLoadConfig_NonExistentFile(t *testing.T) {
	_, err := LoadConfig("nonexistent.yml")
	if err == nil {
		t.Error("LoadConfig() expected error for non-existent file")
	}
}

func TestDefaultConfigPath(t *testing.T) {
	// Save original home
	origHome := os.Getenv("HOME")
	defer os.Setenv("HOME", origHome)

	// Test with HOME set
	testHome := t.TempDir()
	os.Setenv("HOME", testHome)
	got := DefaultConfigPath()
	want := filepath.Join(testHome, ".sentryscan.yml")
	if got != want {
		t.Errorf("DefaultConfigPath() = %q, want %q", got, want)
	}

	// Test with HOME unset
	os.Unsetenv("HOME")
	got = DefaultConfigPath()
	if got != ".sentryscan.yml" {
		t.Errorf("DefaultConfigPath() = %q, want .sentryscan.yml", got)
	}
}

func TestSaveConfig_InvalidPath(t *testing.T) {
	config := &Config{Rules: []RuleConfig{{ID: "test"}}}
	err := SaveConfig(config, "/nonexistent/dir/config.yml")
	if err == nil {
		t.Error("SaveConfig() expected error for invalid path")
	}
}
