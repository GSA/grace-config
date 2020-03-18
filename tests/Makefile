default: test

test: lint
	go test -v tests_test.go

lint: dependencies
	golangci-lint run ./...

dependencies: golangci go.sum

golangci:
	go get -u github.com/golangci/golangci-lint/cmd/golangci-lint

go.sum: go.mod
	go mod tidy

go.mod:
	go mod init