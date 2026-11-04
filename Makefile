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

# Installs from this checkout without a .pkg. Needs sudo. Hooks are per user: run
# `overlord install-hooks claude` as yourself afterwards.
install: build
	sudo mkdir -p /Library/Overlord/bin /Library/Overlord/rules
	sudo install -m 755 overlord /Library/Overlord/bin/overlord
	sudo install -m 644 rules/*.yaml /Library/Overlord/rules/
	sudo install -m 644 policy.yaml packaging/pf.anchor packaging/com.overlord.daemon.plist packaging/com.overlord.notify.plist /Library/Overlord/
	sudo sh packaging/scripts/postinstall

uninstall:
	sudo sh packaging/scripts/uninstall.sh

clean:
	rm -rf overlord overlord-sink dist
