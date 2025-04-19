package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ejagojo/SentryScan/internal/alert"
	"github.com/ejagojo/SentryScan/internal/baseline"
	"github.com/ejagojo/SentryScan/internal/image"
	"github.com/ejagojo/SentryScan/internal/output"
	"github.com/ejagojo/SentryScan/internal/scanner"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	version       = "dev" // Set by ldflags
	configPath    string
	outputType    string
	outputFile    string
	noFail        bool
	threads       int
	since         string
	branch        string
	commitRange   string
	includeExt    []string
	excludeExt    []string
	imageRef      string
	compareRef    string
	noBaseline    bool
	webhookURL    string
	webhookSecret string
	severity      string
)

// exitWith is a function that can be replaced in tests
var exitWith = func(err error, findings []scanner.Finding, suppressed bool) {
	if err != nil {
		color.New(color.FgRed).Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if !noFail {
		for _, f := range findings {
			if f.Severity == "critical" || f.Severity == "high" {
				if suppressed {
					os.Exit(5)
				}
				os.Exit(3)
			}
		}
	}
	os.Exit(0)
}

var rootCmd = &cobra.Command{
	Use:     "sentryscan",
	Short:   "Enterprise-Grade Security Scanner",
	Long:    `SentryScan is a high-throughput security scanner that detects secrets and critical CVEs in code, history, and container images.`,
	Version: version,
}

var scanCmd = &cobra.Command{
	Use:   "scan [paths...]",
	Short: "Scan for secrets and vulnerabilities",
	Long:  `Scan repositories, files, or container images for secrets and vulnerabilities.`,
	Args:  cobra.ArbitraryArgs,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate mutually exclusive flags
		if compareRef != "" && imageRef == "" {
			return fmt.Errorf("--compare requires --image")
		}

		// Validate required arguments
		if len(args) == 0 && imageRef == "" {
			return fmt.Errorf("either --image or paths must be specified")
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var findings []scanner.Finding
		var err error

		// Load and merge config
		config, err := scanner.LoadConfig(configPath)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		flags := map[string]interface{}{
			"image":          imageRef,
			"compare":        compareRef,
			"no-baseline":    noBaseline,
			"webhook-url":    webhookURL,
			"webhook-secret": webhookSecret,
			"severity":       severity,
		}
		config = scanner.MergeConfig(config, flags)

		// Scan container image if specified
		if config.Image != "" {
			imgScanner, err := image.NewScanner()
			if err != nil {
				return fmt.Errorf("failed to create image scanner: %w", err)
			}

			imgFindings, err := imgScanner.Scan(context.Background(), config.Image, config.CompareImage)
			if err != nil {
				return fmt.Errorf("image scan failed: %w", err)
			}
			findings = append(findings, imgFindings...)
		}

		// Scan files/repo if paths specified
		if len(args) > 0 {
			s := scanner.NewScanner()
			opts := scanner.ScannerOptions{
				Threads:     threads,
				Since:       since,
				Branch:      branch,
				CommitRange: commitRange,
				IncludeExt:  includeExt,
				ExcludeExt:  excludeExt,
			}

			fileFindings, err := s.Run(context.Background(), opts, args...)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}
			findings = append(findings, fileFindings...)
		}

		// Apply baseline if not disabled
		suppressed := false
		if !config.NoBaseline && len(args) > 0 {
			baseline, err := baseline.Load(args[0])
			if err != nil {
				return fmt.Errorf("failed to load baseline: %w", err)
			}
			originalCount := len(findings)
			findings = baseline.Filter(findings)
			suppressed = len(findings) < originalCount
		}

		// Send webhook if configured
		if config.WebhookURL != "" && len(findings) > 0 {
			wh := alert.NewWebhook(config.WebhookURL, config.WebhookSecret)
			payload := &alert.Payload{
				RunID:       fmt.Sprintf("run-%d", time.Now().Unix()),
				Summary:     fmt.Sprintf("Found %d security findings", len(findings)),
				Findings:    findings,
				Repo:        args[0],
				GitRef:      branch,
				GeneratedAt: time.Now(),
			}
			if err := wh.Send(payload); err != nil {
				return fmt.Errorf("failed to send webhook: %w", err)
			}
		}

		// Determine output writer
		var w io.Writer = os.Stdout
		if outputFile != "" {
			f, err := os.Create(outputFile)
			if err != nil {
				return fmt.Errorf("failed to create output file: %w", err)
			}
			defer f.Close()
			w = f
		}

		// Write findings
		if err := output.WriteFindings(findings, output.OutputType(outputType), w); err != nil {
			return fmt.Errorf("failed to write findings: %w", err)
		}

		exitWith(nil, findings, suppressed)
		return nil
	},
}

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage baseline suppressions",
	Long:  `Add or list findings in the baseline suppression file.`,
}

var baselineAddCmd = &cobra.Command{
	Use:   "add <fingerprint>",
	Short: "Add a finding to the baseline",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		baseline, err := baseline.Load(".")
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		finding := scanner.Finding{
			RuleID: args[0],
		}

		if err := baseline.Add(finding); err != nil {
			return fmt.Errorf("failed to add finding: %w", err)
		}

		if err := baseline.Save("."); err != nil {
			return fmt.Errorf("failed to save baseline: %w", err)
		}

		fmt.Println("Added finding to baseline")
		return nil
	},
}

var baselineListCmd = &cobra.Command{
	Use:   "list",
	Short: "List baseline suppressions",
	RunE: func(cmd *cobra.Command, args []string) error {
		baseline, err := baseline.Load(".")
		if err != nil {
			return fmt.Errorf("failed to load baseline: %w", err)
		}

		for _, f := range baseline.Findings {
			fmt.Printf("%s: %s:%d\n", f.RuleID, f.Path, f.Line)
		}
		return nil
	},
}

func init() {
	configPath = scanner.DefaultConfigPath()

	// Scan command flags
	scanCmd.Flags().StringVarP(&configPath, "config", "c", configPath, "path to configuration file")
	scanCmd.Flags().StringVarP(&outputType, "type", "t", "console", "output type (console, json, sarif)")
	scanCmd.Flags().StringVarP(&outputFile, "out", "o", "", "output file (default: stdout)")
	scanCmd.Flags().BoolVar(&noFail, "no-fail", false, "don't fail on high severity findings")
	scanCmd.Flags().IntVar(&threads, "threads", 4, "number of concurrent scanning threads")
	scanCmd.Flags().StringVar(&since, "since", "", "scan changes since commit")
	scanCmd.Flags().StringVar(&branch, "branch", "", "scan specific branch")
	scanCmd.Flags().StringVar(&commitRange, "commit-range", "", "scan commit range (from..to)")
	scanCmd.Flags().StringSliceVar(&includeExt, "include-ext", nil, "include files with these extensions")
	scanCmd.Flags().StringSliceVar(&excludeExt, "exclude-ext", nil, "exclude files with these extensions")
	scanCmd.Flags().StringVar(&imageRef, "image", "", "scan container image")
	scanCmd.Flags().StringVar(&compareRef, "compare", "", "compare with base image")
	scanCmd.Flags().BoolVar(&noBaseline, "no-baseline", false, "ignore baseline suppressions")
	scanCmd.Flags().StringVar(&webhookURL, "webhook-url", "", "webhook URL for alerts")
	scanCmd.Flags().StringVar(&webhookSecret, "webhook-secret", "", "webhook secret for signing")
	scanCmd.Flags().StringVar(&severity, "severity", "high", "minimum severity threshold")

	// Baseline commands
	baselineCmd.AddCommand(baselineAddCmd)
	baselineCmd.AddCommand(baselineListCmd)

	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(baselineCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		exitWith(err, nil, false)
	}
}
