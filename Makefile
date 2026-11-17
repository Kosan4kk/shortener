.PHONY: run test check build

run:
	go run ./cmd/shortener

test:
	go test ./...

check:
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal; exit 1)
	go vet ./...
	go test -race -cover ./...

build:
	go build -o bin/shortener ./cmd/shortener
