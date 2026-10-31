.PHONY: build test race vet vuln fmt check clean

build:
	go build -o bin/sendscore-app .

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

fmt:
	gofmt -w .

check: vet race vuln
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

clean:
	rm -rf bin/
