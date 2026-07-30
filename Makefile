
# Installed via `go install` rather than the upstream install.sh, which is
# broken for every release from v2.12.0 onward: those releases added
# `<tarball>.tar.gz.sbom.json` entries to checksums.txt, and install.sh looks
# up the expected hash with a plain `grep <tarball-name>`. That pattern now
# matches the tarball line AND the .sbom.json line, so the "expected" checksum
# resolves to two values and verification can never succeed.
GOLANGCI_LINT_VERSION ?= v2.12.2

install-lint: ## Install go linter `golangci-lint`
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: ## Lint
	golangci-lint --version
	golangci-lint run


check-modtidy: ## Check Modtidy
	go mod tidy
	git diff --exit-code -- go.mod go.sum

mod-tidy: ## Mod tidy
	@go mod tidy

mod-update: ## Mod Update
	@go get -u ./...

build:
	go build .

test:
	go test