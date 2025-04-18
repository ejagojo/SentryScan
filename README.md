# SentryScan

Enterprise‑grade Go CLI that will scan Git history and container images for secrets and CVEs.

## Requirements
* Go 1.22 or newer
* `make` (for local convenience targets)
* `golangci-lint` (optional but recommended)

## Quick start

```bash
# clone & enter repo
git clone git@github.com:your-username/sentryscan.git
cd sentryscan

# build binary
make build

# run CLI
make run
