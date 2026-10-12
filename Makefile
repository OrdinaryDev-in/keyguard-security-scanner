.PHONY: build test race bench vet demo demo-html self-scan clean

build:
	go build -o bin/keyguard ./cmd/keyguard

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -run '^$$' -bench . -benchmem ./internal/detect/ ./internal/scan/

vet:
	gofmt -l . && go vet ./...

# Builds a fake vulnerable app in /tmp and scans it.
demo: build
	rm -rf /tmp/keyguard-demo && go run ./cmd/mkfixture /tmp/keyguard-demo
	./bin/keyguard scan /tmp/keyguard-demo || true

demo-html: build
	rm -rf /tmp/keyguard-demo && go run ./cmd/mkfixture /tmp/keyguard-demo
	./bin/keyguard scan /tmp/keyguard-demo --format html -o docs/assets/sample-report.html || true

# Dogfooding: keyguard must pass on its own source.
self-scan: build
	./bin/keyguard scan .

clean:
	rm -rf bin
