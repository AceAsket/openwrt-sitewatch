# SiteWatch

SiteWatch is a small OpenWrt web tool for discovering domains that are blocked or heavily slowed down on the direct route and should be routed through v2rayA/Xray.

It is built for routers where permanent DNS logging is undesirable:

- starts DNS capture only when you ask it to;
- records the requesting device and domain from dnsmasq/Pi-hole logs;
- checks domains directly and through a configured v2rayA proxy;
- marks domains as `blocked`, `slow`, `ok`, or `proxy_failed`;
- exports plain domains and v2rayA rules such as `domain(domain: example.com) -> proxy`;
- includes a compact CGI web UI for OpenWrt `uhttpd`;
- can use a static Go binary for HTTP/SOCKS checks without depending on `curl`.

## Release Files

Choose the binary that matches your OpenWrt architecture and copy it to `/usr/bin/sitewatch`.

| OpenWrt target | Release file |
| --- | --- |
| `aarch64_*`, for example `aarch64_cortex-a53` | `sitewatch-linux-arm64` |
| `arm_cortex-a7_*`, most ARMv7 routers | `sitewatch-linux-armv7` |
| older ARMv6 routers | `sitewatch-linux-armv6` |
| `x86_64` | `sitewatch-linux-amd64` |
| `i386_*`, for example `i386_pentium4` | `sitewatch-linux-386` |
| big-endian MIPS | `sitewatch-linux-mips` |
| little-endian MIPS, common on older home routers | `sitewatch-linux-mipsle` |

Verify downloads with `SHA256SUMS`.

## Minimal Install

```sh
opkg update
opkg install ca-bundle
chmod +x /usr/bin/sitewatch
```

For the full web UI, install the repository files with `install-openwrt.sh`; it creates a separate `uhttpd` listener on port `8095`.
