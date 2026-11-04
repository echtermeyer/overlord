VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/echtermeyer/overlord.Version=$(VERSION)

.PHONY: build test lint install uninstall replay-sample clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o overlord ./cmd/overlord
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o overlord-sink ./cmd/overlord-sink

test:
	go test ./...

lint:
	gofmt -l . | tee /dev/stderr | test -z "$$(cat)"
	go vet ./...
	govulncheck ./... || true

replay-sample: build
	./overlord replay testdata/eslogger_sample.ndjson

install: build
	sudo ./overlord install

uninstall:
	sudo overlord uninstall

clean:
	rm -rf overlord overlord-sink dist
