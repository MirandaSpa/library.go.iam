LINT_VERSION := v2.14.0
COVERAGE_VERSION := v2.19.0

.PHONY: test cover lint vuln check

test: ## Unit tests with race detector
	go test -race -count=1 ./...

cover: ## Tests + coverage threshold (same as CI)
	go test -race -covermode=atomic -coverprofile=cover.out ./...
	go run github.com/vladopajic/go-test-coverage/v2@$(COVERAGE_VERSION) --config=./.testcoverage.yml

lint: ## Static analysis (same as CI)
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(LINT_VERSION) run ./...

vuln: ## Known vulnerabilities in dependencies
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

check: lint vuln cover ## Everything CI runs
