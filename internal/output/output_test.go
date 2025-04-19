package output

import (
	"bytes"
	"testing"

	"github.com/ejagojo/SentryScan/internal/scanner"
)

func TestWriteFindings_Console(t *testing.T) {
	findings := []scanner.Finding{
		{
			Type:        "secret",
			RuleID:      "aws-access-key",
			Description: "AWS Access Key detected",
			Severity:    "high",
			Path:        "test.txt",
			Line:        1,
			Column:      20,
			Match:       "AKIAXXXXXXXXXXXXXXXX",
			Context:     "aws_access_key_id = \"AKIAXXXXXXXXXXXXXXXX\"",
		},
	}

	var buf bytes.Buffer
	if err := WriteFindings(findings, OutputTypeConsole, &buf); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected non-empty console output")
	}
}

func TestWriteFindings_JSON(t *testing.T) {
	findings := []scanner.Finding{
		{
			Type:        "secret",
			RuleID:      "aws-access-key",
			Description: "AWS Access Key detected",
			Severity:    "high",
			Path:        "test.txt",
			Line:        1,
			Column:      20,
			Match:       "AKIAXXXXXXXXXXXXXXXX",
			Context:     "aws_access_key_id = \"AKIAXXXXXXXXXXXXXXXX\"",
		},
	}

	var buf bytes.Buffer
	if err := WriteFindings(findings, OutputTypeJSON, &buf); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected non-empty JSON output")
	}
}

func TestWriteFindings_SARIF(t *testing.T) {
	findings := []scanner.Finding{
		{
			Type:        "secret",
			RuleID:      "aws-access-key",
			Description: "AWS Access Key detected",
			Severity:    "high",
			Path:        "test.txt",
			Line:        1,
			Column:      20,
			Match:       "AKIAXXXXXXXXXXXXXXXX",
			Context:     "aws_access_key_id = \"AKIAXXXXXXXXXXXXXXXX\"",
		},
	}

	var buf bytes.Buffer
	if err := WriteFindings(findings, OutputTypeSARIF, &buf); err != nil {
		t.Fatalf("WriteFindings failed: %v", err)
	}

	output := buf.String()
	if output == "" {
		t.Error("Expected non-empty SARIF output")
	}
}

func TestMapSeverityToLevel(t *testing.T) {
	tests := []struct {
		severity string
		expected string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"unknown", "none"},
	}

	for _, test := range tests {
		level := mapSeverityToLevel(test.severity)
		if level != test.expected {
			t.Errorf("Expected level %s for severity %s, got %s", test.expected, test.severity, level)
		}
	}
}
