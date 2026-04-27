GO ?= go
DIST ?= dist
LDFLAGS := -s -w

.PHONY: build-openwrt-all
build-openwrt-all: build-openwrt-arm64 build-openwrt-armv7 build-openwrt-armv6 build-openwrt-amd64 build-openwrt-386 build-openwrt-mips build-openwrt-mipsle
	cd $(DIST) && sha256sum sitewatch-linux-* > SHA256SUMS

.PHONY: build-openwrt-arm64
build-openwrt-arm64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sitewatch-linux-arm64 ./cmd/sitewatch

.PHONY: build-openwrt-aarch64
build-openwrt-aarch64: build-openwrt-arm64

.PHONY: build-openwrt-armv7
build-openwrt-armv7:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sitewatch-linux-armv7 ./cmd/sitewatch

.PHONY: build-openwrt-armv6
build-openwrt-armv6:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sitewatch-linux-armv6 ./cmd/sitewatch

.PHONY: build-openwrt-amd64
build-openwrt-amd64:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sitewatch-linux-amd64 ./cmd/sitewatch

.PHONY: build-openwrt-386
build-openwrt-386:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=386 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sitewatch-linux-386 ./cmd/sitewatch

.PHONY: build-openwrt-mips
build-openwrt-mips:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sitewatch-linux-mips ./cmd/sitewatch

.PHONY: build-openwrt-mipsle
build-openwrt-mipsle:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sitewatch-linux-mipsle ./cmd/sitewatch

.PHONY: build-local
build-local:
	mkdir -p $(DIST)
	$(GO) build -trimpath -o $(DIST)/sitewatch ./cmd/sitewatch
