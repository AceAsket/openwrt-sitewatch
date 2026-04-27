GO ?= go
DIST ?= dist

.PHONY: build-openwrt-arm64
build-openwrt-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o $(DIST)/sitewatch-linux-arm64 ./cmd/sitewatch

.PHONY: build-openwrt-aarch64
build-openwrt-aarch64: build-openwrt-arm64

.PHONY: build-local
build-local:
	mkdir -p $(DIST)
	$(GO) build -trimpath -o $(DIST)/sitewatch ./cmd/sitewatch
