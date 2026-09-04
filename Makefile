GO ?= go
VERSION ?= development

.PHONY: all test coverage vet build clean
all: test build

test:
	$(GO) test -race ./...

coverage:
	$(GO) test -coverprofile=coverage.out ./internal/...
	$(GO) tool cover -func=coverage.out

vet:
	$(GO) vet ./...

build:
	mkdir -p dist
	$(GO) build -trimpath -ldflags "-X main.version=$(VERSION)" -o dist/dweb-mail-abuse-guard ./cmd/dweb-mail-abuse-guard
	$(GO) build -trimpath -o dist/dweb-mail-abuse-guardctl ./cmd/dweb-mail-abuse-guardctl
	$(GO) build -trimpath -o dist/dweb-mail-abuse-helper ./cmd/dweb-mail-abuse-helper

clean:
	rm -rf dist coverage.out
