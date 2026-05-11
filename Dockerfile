FROM golang:1.22-alpine AS build

WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT
COPY go.mod ./
COPY cmd ./cmd
RUN export GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}"; \
	if [ "$GOARCH" = "arm" ]; then export GOARM="${TARGETVARIANT#v}"; fi; \
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sitewatch ./cmd/sitewatch

FROM alpine:3.20

RUN apk add --no-cache ca-certificates curl busybox-extras tcpdump

COPY --from=build /out/sitewatch /usr/bin/sitewatch
COPY files/usr/bin/sitewatch-collect /usr/bin/sitewatch-collect
COPY files/usr/bin/sitewatch-capture /usr/bin/sitewatch-capture
COPY files/usr/bin/sitewatch-scan /usr/bin/sitewatch-scan
COPY files/usr/bin/sitewatch-check-url /usr/bin/sitewatch-check-url
COPY files/usr/bin/sitewatch-detector /usr/bin/sitewatch-detector
COPY files/usr/bin/sitewatch-dns-dump /usr/bin/sitewatch-dns-dump
COPY files/usr/bin/sitewatch-flow-probe /usr/bin/sitewatch-flow-probe
COPY files/usr/bin/sitewatch-net-probe /usr/bin/sitewatch-net-probe
COPY files/usr/bin/sitewatch-reflector /usr/bin/sitewatch-reflector
COPY files/www/cgi-bin/sitewatch /www/sitewatch/cgi-bin/sitewatch
COPY files/www/cgi-bin/metrics /www/sitewatch/cgi-bin/metrics
COPY files/www/sitewatch/favicon.svg /www/sitewatch/favicon.svg
COPY sitewatch.conf /usr/share/sitewatch/sitewatch.conf
COPY scripts/docker-entrypoint.sh /usr/local/bin/sitewatch-docker-entrypoint

RUN chmod +x \
	/usr/bin/sitewatch \
	/usr/bin/sitewatch-collect \
	/usr/bin/sitewatch-capture \
	/usr/bin/sitewatch-scan \
	/usr/bin/sitewatch-check-url \
	/usr/bin/sitewatch-detector \
	/usr/bin/sitewatch-dns-dump \
	/usr/bin/sitewatch-flow-probe \
	/usr/bin/sitewatch-net-probe \
	/usr/bin/sitewatch-reflector \
	/www/sitewatch/cgi-bin/sitewatch \
	/www/sitewatch/cgi-bin/metrics \
	/usr/local/bin/sitewatch-docker-entrypoint \
	&& printf '%s\n' '<!doctype html><meta http-equiv="refresh" content="0; url=/cgi-bin/sitewatch"><a href="/cgi-bin/sitewatch">SiteWatch</a>' > /www/sitewatch/index.html

VOLUME ["/data", "/logs"]
EXPOSE 8095 8096/tcp 8096/udp

ENTRYPOINT ["/usr/local/bin/sitewatch-docker-entrypoint"]
CMD ["httpd", "-f", "-p", "0.0.0.0:8095", "-h", "/www/sitewatch"]
