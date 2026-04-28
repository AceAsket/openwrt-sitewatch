#!/bin/ash
set -eu

PURGE_DATA=0
BACKUP_DIR=""

usage() {
	cat <<'USAGE'
Usage: ./uninstall-openwrt.sh [--backup DIR] [--purge-data]

Removes SiteWatch from OpenWrt:
  - stops an active capture window
  - removes the dedicated uhttpd.sitewatch instance
  - removes CGI and helper binaries
  - keeps /etc/sitewatch data by default

Options:
  --backup DIR   Save /etc/sitewatch into DIR before removing files
  --purge-data   Remove /etc/sitewatch after optional backup
  -h, --help     Show this help
USAGE
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--backup)
			shift
			[ "$#" -gt 0 ] || {
				echo "Missing backup directory after --backup" >&2
				exit 2
			}
			BACKUP_DIR="$1"
			;;
		--purge-data)
			PURGE_DATA=1
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "Unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
	shift
done

if [ -x /usr/bin/sitewatch-capture ]; then
	/usr/bin/sitewatch-capture stop >/dev/null 2>&1 || true
fi
if [ -x /usr/bin/sitewatch-agent ]; then
	/usr/bin/sitewatch-agent stop >/dev/null 2>&1 || true
fi

if [ -n "$BACKUP_DIR" ] && [ -d /etc/sitewatch ]; then
	mkdir -p "$BACKUP_DIR"
	backup="$BACKUP_DIR/sitewatch-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
	tar -czf "$backup" -C /etc sitewatch
	echo "Backed up /etc/sitewatch to $backup"
fi

if command -v uci >/dev/null 2>&1 && [ -x /etc/init.d/uhttpd ]; then
	if uci -q get uhttpd.sitewatch >/dev/null 2>&1; then
		uci -q delete uhttpd.sitewatch || true
		uci commit uhttpd
		/etc/init.d/uhttpd restart >/dev/null 2>&1 || true
		echo "Removed uhttpd.sitewatch"
	fi
fi

rm -f \
	/usr/bin/sitewatch \
	/usr/bin/sitewatch-collect \
	/usr/bin/sitewatch-capture \
	/usr/bin/sitewatch-agent \
	/usr/bin/sitewatch-scan \
	/usr/bin/sitewatch-check-url

rm -rf /www/sitewatch
rm -f \
	/tmp/sitewatch-capture.status \
	/tmp/sitewatch-capture.stop \
	/tmp/sitewatch-agent.status \
	/tmp/sitewatch-agent.stop \
	/tmp/sitewatch-agent.pid \
	/tmp/sitewatch-scan.status \
	/tmp/sitewatch-pihole.status
rm -rf \
	/tmp/sitewatch-capture.lock \
	/tmp/sitewatch-scan.lock

if [ "$PURGE_DATA" = "1" ]; then
	rm -rf /etc/sitewatch
	echo "Removed /etc/sitewatch"
else
	echo "Kept /etc/sitewatch. Use --purge-data to remove data after backup/migration."
fi

echo "SiteWatch OpenWrt files removed."
