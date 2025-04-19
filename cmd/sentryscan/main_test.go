package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ejagojo/SentryScan/internal/scanner"
)

func TestScanCommand(t *testing.T) {
	// Save original stdout and restore it after tests
	oldStdout := os.Stdout
	defer func() { os.Stdout = oldStdout }()

	tests := []struct {
		name       string
		args       []string
		setupFiles map[string]string
		wantErr    bool
		wantOutput string
		wantExit   int
	}{
		{
			name: "clean directory",
			args: []string{"scan", "--type=json", "."},
			setupFiles: map[string]string{
				"clean.txt": "no secrets here",
			},
			wantErr:    false,
			wantOutput: "{}\n",
			wantExit:   0,
		},
		{
			name: "directory with secrets",
			args: []string{"scan", "--type=json", "."},
			setupFiles: map[string]string{
				"secret.txt": `aws_access_key_id = "AKIAXXXXXXXXXXXXXXXX"`,
			},
			wantErr:  false,
			wantExit: 1,
		},
		{
			name:    "invalid flag",
			args:    []string{"scan", "--bogus"},
			wantErr: true,
		},
		{
			name: "no-fail flag",
			args: []string{"scan", "--type=json", "--no-fail", "."},
			setupFiles: map[string]string{
				"secret.txt": `aws_access_key_id = "AKIAXXXXXXXXXXXXXXXX"`,
			},
			wantErr:  false,
			wantExit: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp directory
			dir := t.TempDir()

			// Create test files
			for name, content := range tt.setupFiles {
				path := filepath.Join(dir, name)
				if err := os.WriteFile(path, []byte(content), 0644); err != nil {
					t.Fatalf("Failed to create test file: %v", err)
				}
			}

			// Change to test directory
			oldWd, err := os.Getwd()
			if err != nil {
				t.Fatalf("Failed to get working directory: %v", err)
			}
			if err := os.Chdir(dir); err != nil {
				t.Fatalf("Failed to change directory: %v", err)
			}
			defer os.Chdir(oldWd)

			// Capture stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Set command args
			rootCmd.SetArgs(tt.args)

			// Run command
			var exitCode int
			exitWith = func(err error, findings []scanner.Finding) {
				if err != nil {
					exitCode = 1
					return
				}
				if !noFail {
					for _, f := range findings {
						if f.Severity == "critical" || f.Severity == "high" {
							exitCode = 1
							return
						}
					}
				}
				exitCode = 0
			}

			err = rootCmd.Execute()
			w.Close()

			// Read captured output
			var buf bytes.Buffer
			io.Copy(&buf, r)
			output := buf.String()

			// Check error
			if (err != nil) != tt.wantErr {
				t.Errorf("Execute() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check exit code
			if tt.wantExit >= 0 && exitCode != tt.wantExit {
				t.Errorf("Execute() exit code = %d, want %d", exitCode, tt.wantExit)
			}

			// Check output
			if tt.wantOutput != "" && !strings.Contains(output, tt.wantOutput) {
				t.Errorf("Execute() output = %q, want to contain %q", output, tt.wantOutput)
			}
		})
	}
}

func TestInitCommand(t *testing.T) {
	// Create temp directory
	dir := t.TempDir()
	configPath := filepath.Join(dir, ".sentryscan.yml")

	// Set command args
	rootCmd.SetArgs([]string{"init", "--config", configPath})

	// Run command
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}

	// Verify config file was created
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("Config file was not created")
	}

	// Try to load config
	config, err := scanner.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify config contents
	if len(config.Rules) == 0 {
		t.Error("Config has no rules")
	}
}

func TestHelpCommand(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	// Set command args
	rootCmd.SetArgs([]string{"--help"})

	// Run command
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	w.Close()

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify help output
	if !strings.Contains(output, "Enterprise-Grade Security Scanner") {
		t.Error("Help output missing expected content")
	}
}
