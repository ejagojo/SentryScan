package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ejagojo/SentryScan/internal/scanner"
	"github.com/jedib0t/go-pretty/v6/table"
)

// OutputType defines the supported output formats
type OutputType string

const (
	OutputTypeConsole OutputType = "console"
	OutputTypeJSON    OutputType = "json"
	OutputTypeSARIF   OutputType = "sarif"
)

// WriteFindings writes the findings to the specified output
func WriteFindings(findings []scanner.Finding, outputType OutputType, w io.Writer) error {
	switch outputType {
	case OutputTypeConsole:
		return writeConsole(findings, w)
	case OutputTypeJSON:
		return writeJSON(findings, w)
	case OutputTypeSARIF:
		return writeSARIF(findings, w)
	default:
		return fmt.Errorf("unsupported output type: %s", outputType)
	}
}

// writeConsole writes findings in a human-readable table format
func writeConsole(findings []scanner.Finding, w io.Writer) error {
	t := table.NewWriter()
	t.SetOutputMirror(w)
	t.AppendHeader(table.Row{"Severity", "Rule", "File", "Line", "Description"})

	for _, f := range findings {
		t.AppendRow(table.Row{
			f.Severity,
			f.RuleID,
			f.Path,
			f.Line,
			f.Description,
		})
	}

	t.Render()
	return nil
}

// writeJSON writes findings in JSON format
func writeJSON(findings []scanner.Finding, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

// writeSARIF writes findings in SARIF format
func writeSARIF(findings []scanner.Finding, w io.Writer) error {
	// Create SARIF report structure
	report := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":           "SentryScan",
						"informationUri": "https://github.com/ejagojo/SentryScan",
						"rules":          []map[string]interface{}{},
					},
				},
				"results": []map[string]interface{}{},
			},
		},
	}

	// Add rules
	rules := make(map[string]bool)
	run := report["runs"].([]map[string]interface{})[0]
	driver := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})

	for _, f := range findings {
		if !rules[f.RuleID] {
			rule := map[string]interface{}{
				"id": f.RuleID,
				"shortDescription": map[string]interface{}{
					"text": f.Description,
				},
				"defaultConfiguration": map[string]interface{}{
					"level": mapSeverityToLevel(f.Severity),
				},
			}
			driver["rules"] = append(driver["rules"].([]map[string]interface{}), rule)
			rules[f.RuleID] = true
		}
	}

	// Add results
	for _, f := range findings {
		result := map[string]interface{}{
			"ruleId":  f.RuleID,
			"level":   mapSeverityToLevel(f.Severity),
			"message": map[string]interface{}{"text": f.Description},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]interface{}{
							"uri": f.Path,
						},
						"region": map[string]interface{}{
							"startLine":   f.Line,
							"startColumn": f.Column,
						},
					},
				},
			},
		}
		run["results"] = append(run["results"].([]map[string]interface{}), result)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// mapSeverityToLevel maps our severity levels to SARIF levels
func mapSeverityToLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "none"
	}
}
