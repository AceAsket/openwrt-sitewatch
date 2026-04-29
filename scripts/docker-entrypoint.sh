#!/bin/ash
set -eu

DATA_DIR="${SITEWATCH_DATA_DIR:-/data}"
CONF="/etc/sitewatch/sitewatch.conf"
DATA_CONF="$DATA_DIR/sitewatch.conf"

mkdir -p "$DATA_DIR" /etc/sitewatch /logs /tmp/log /var/log/pihole

if [ ! -f "$DATA_CONF" ]; then
	cp /usr/share/sitewatch/sitewatch.conf "$DATA_CONF"
fi

set_config() {
	key="$1"
	value="$2"
	escaped="$(printf "%s" "$value" | sed 's/\\/\\\\/g; s/"/\\"/g')"
	tmp="/tmp/sitewatch-docker-conf.$$"
	awk -v key="$key" -v value="$escaped" '
		BEGIN { done = 0 }
		$0 ~ "^" key "=" { print key "=\"" value "\""; done = 1; next }
		{ print }
		END { if (!done) print key "=\"" value "\"" }
	' "$DATA_CONF" > "$tmp"
	mv "$tmp" "$DATA_CONF"
}

set_config SITEWATCH_GO_BIN "/usr/bin/sitewatch"
set_config SITEWATCH_USE_GO "1"
set_config SITEWATCH_SEEN "$DATA_DIR/seen.tsv"
set_config SITEWATCH_QUEUE "$DATA_DIR/queue.tsv"
set_config SITEWATCH_RESULTS "$DATA_DIR/results.tsv"
set_config SITEWATCH_PROXY_OUT "$DATA_DIR/proxy-domains.txt"
set_config SITEWATCH_AGENTS "$DATA_DIR/agents.tsv"
set_config SITEWATCH_HISTORY "$DATA_DIR/history.tsv"
set_config SITEWATCH_CAPTURE_STATUS "/tmp/sitewatch-capture.status"
set_config SITEWATCH_SCAN_STATUS "/tmp/sitewatch-scan.status"
set_config SITEWATCH_CAPTURE_STOP "/tmp/sitewatch-capture.stop"
set_config SITEWATCH_LOG_FILES "${SITEWATCH_LOG_FILES:-/logs/pihole.log /logs/dnsmasq.log /logs/messages /var/log/pihole/pihole.log /tmp/log/dnsmasq.log}"
set_config SITEWATCH_USE_LOGREAD "${SITEWATCH_USE_LOGREAD:-0}"
set_config SITEWATCH_CLEAR_LOGREAD "${SITEWATCH_CLEAR_LOGREAD:-0}"
set_config SITEWATCH_DNSMASQ_CONTROL "${SITEWATCH_DNSMASQ_CONTROL:-0}"

for key in \
	SITEWATCH_VERSION \
	SITEWATCH_PROXY \
	SITEWATCH_BATCH \
	SITEWATCH_SCAN_WORKERS \
	SITEWATCH_RETENTION_DAYS \
	SITEWATCH_TIMEOUT \
	SITEWATCH_MIN_RESCAN \
	SITEWATCH_SLOW_SECONDS \
	SITEWATCH_SLOW_RATIO \
	SITEWATCH_RUN_MODE \
	SITEWATCH_INGEST_TOKEN \
	SITEWATCH_AGENT_INGEST_URL \
	SITEWATCH_PIHOLE_API_ENABLED \
	SITEWATCH_PIHOLE_URL \
	SITEWATCH_PIHOLE_PASSWORD \
	SITEWATCH_PIHOLE_LOOKBACK \
	SITEWATCH_PIHOLE_DISK \
	SITEWATCH_EXCLUDE_DOMAINS \
	SITEWATCH_CHECK_BASE_DOMAIN \
	SITEWATCH_DPI_DNS_SERVER \
	SITEWATCH_DPI_DOH_URL
do
	eval "value=\${$key:-}"
	[ -n "$value" ] && set_config "$key" "$value"
done

cp "$DATA_CONF" "$CONF"
touch "$DATA_DIR/seen.tsv" "$DATA_DIR/queue.tsv" "$DATA_DIR/results.tsv" "$DATA_DIR/proxy-domains.txt" "$DATA_DIR/agents.tsv" "$DATA_DIR/history.tsv"
ash -n "$CONF"

exec "$@"
