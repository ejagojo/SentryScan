# SentryScan

Enterprise‑grade Go CLI that will scan Git history and container images for secrets and CVEs.

## Requirements
* Go 1.22 or newer
* `make` (local convenience targets)

### Lint tool
Install **golangci‑lint** so local runs match CI:

```bash
go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@v1.57.2
# ensure GOPATH/bin is on PATH
