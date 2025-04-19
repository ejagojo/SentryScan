# SentryScan

Enterprise-Grade Security Scanner

[![Go Report Card](https://goreportcard.com/badge/github.com/ejagojo/SentryScan)](https://goreportcard.com/report/github.com/ejagojo/SentryScan)
[![Coverage](https://img.shields.io/badge/coverage-92%25-brightgreen)](https://github.com/ejagojo/SentryScan/actions)
[![Fuzzed](https://img.shields.io/badge/fuzzed-%E2%9C%94-brightgreen)](https://github.com/ejagojo/SentryScan/actions)
[![Race Safe](https://img.shields.io/badge/race--safe-%E2%9C%94-brightgreen)](https://github.com/ejagojo/SentryScan/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/ejagojo/SentryScan/blob/main/LICENSE)

SentryScan is a high-throughput security scanner that detects secrets and critical CVEs in code, history, and container images.

## Features

- **Secret Detection**: Find hardcoded credentials, API keys, and tokens
- **Vulnerability Scanning**: Identify known CVEs in dependencies and container images
- **Git History Analysis**: Scan entire commit history for secrets and vulnerabilities
- **Container Scanning**: Analyze container images for vulnerabilities and misconfigurations
- **Baseline Suppression**: Manage and suppress known findings
- **Webhook Alerts**: Get real-time notifications of new findings

## Security Features

- **Fuzzing**: Critical components are fuzzed for 30s in CI
- **Race Detection**: All tests run with race detector enabled
- **Crypto-Safe**: Constant-time signature verification and replay prevention
- **Static Analysis**: Regular runs of gosec, govulncheck, and staticcheck
- **SBOM Generation**: CycloneDX SBOM with license compliance checks
- **Hostile Input Protection**: Guards against zip bombs, symlink loops, and path traversal

## Installation

```bash
# Using Go
go install github.com/ejagojo/SentryScan/cmd/sentryscan@latest

# Using Homebrew (macOS/Linux)
brew install ejagojo/tap/sentryscan

# Using Scoop (Windows)
scoop bucket add ejagojo https://github.com/ejagojo/scoop-bucket.git
scoop install sentryscan
```

## Usage

### Basic Scanning

```bash
# Scan current directory
sentryscan scan

# Scan specific directory
sentryscan scan /path/to/dir

# Scan with custom output format
sentryscan scan --type=sarif --out=report.sarif .
```

### Git Integration

```bash
# Scan git repository
sentryscan scan --git /path/to/repo

# Scan changes since commit
sentryscan scan --since HEAD~1

# Scan specific branch
sentryscan scan --branch main

# Scan commit range
sentryscan scan --commit-range v1.0.0..HEAD
```

### Configuration

```bash
# Initialize configuration
sentryscan init

# Use custom configuration file
sentryscan scan --config custom.yml
```

## Configuration File

Example `.sentryscan.yml`:

```yaml
rules:
  - id: aws-access-key
    description: AWS Access Key detected
    severity: high
    pattern: (?i)aws_access_key_id\s*=\s*['"]?([A-Z0-9]{20})['"]?

  - id: aws-secret-key
    description: AWS Secret Key detected
    severity: critical
    pattern: (?i)aws_secret_access_key\s*=\s*['"]?([A-Za-z0-9/+=]{40})['"]?

  - id: generic-token
    description: Generic token detected
    severity: medium
    pattern: (?i)(?:token|key|secret|password)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{32,})['"]?
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Requirements

- Go 1.22 or newer
- `make` (local convenience targets)

### Lint tool

Install **golangci-lint** so local runs match CI:

```bash
go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@v1.57.2
# ensure GOPATH/bin is on PATH
```
