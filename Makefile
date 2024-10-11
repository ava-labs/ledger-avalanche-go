
install-lint: ## Install go linter `golangci-lint`
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin latest

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