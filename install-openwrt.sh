#!/bin/ash
set -eu

mkdir -p /etc/sitewatch /usr/bin /www/sitewatch/cgi-bin

cp ./sitewatch.conf /etc/sitewatch/sitewatch.conf

arch="$(uname -m 2>/dev/null || true)"
openwrt_arch=""
[ -f /etc/openwrt_release ] && . /etc/openwrt_release && openwrt_arch="${DISTRIB_ARCH:-}"
sitewatch_binary=""
case "$openwrt_arch:$arch" in
	aarch64_*:*|*:aarch64) sitewatch_binary="./dist/sitewatch-linux-arm64" ;;
	x86_64:*|*:x86_64) sitewatch_binary="./dist/sitewatch-linux-amd64" ;;
	i386_*:*|i486_*:*|i686_*:*|*:i386|*:i486|*:i586|*:i686) sitewatch_binary="./dist/sitewatch-linux-386" ;;
	arm_*:armv7*|arm_*:armv8*|*:armv7*) sitewatch_binary="./dist/sitewatch-linux-armv7" ;;
	arm_*:armv6*|*:armv6*) sitewatch_binary="./dist/sitewatch-linux-armv6" ;;
	mipsel_*:*|*:mipsel) sitewatch_binary="./dist/sitewatch-linux-mipsle" ;;
	mips_*:*|*:mips) sitewatch_binary="./dist/sitewatch-linux-mips" ;;
esac

if [ -n "$sitewatch_binary" ] && [ -f "$sitewatch_binary" ]; then
	cp "$sitewatch_binary" /usr/bin/sitewatch
	chmod +x /usr/bin/sitewatch
	echo "Installed Go binary: $sitewatch_binary"
elif [ -f ./dist/sitewatch-linux-arm64 ]; then
	cp ./dist/sitewatch-linux-arm64 /usr/bin/sitewatch
	chmod +x /usr/bin/sitewatch
	echo "Installed fallback Go binary: ./dist/sitewatch-linux-arm64"
fi
cp ./files/usr/bin/sitewatch-collect /usr/bin/sitewatch-collect
cp ./files/usr/bin/sitewatch-capture /usr/bin/sitewatch-capture
cp ./files/usr/bin/sitewatch-scan /usr/bin/sitewatch-scan
cp ./files/usr/bin/sitewatch-check-url /usr/bin/sitewatch-check-url
cp ./files/www/cgi-bin/sitewatch /www/sitewatch/cgi-bin/sitewatch
cp ./files/www/cgi-bin/metrics /www/sitewatch/cgi-bin/metrics

chmod +x /usr/bin/sitewatch-collect /usr/bin/sitewatch-capture /usr/bin/sitewatch-scan /usr/bin/sitewatch-check-url /www/sitewatch/cgi-bin/sitewatch /www/sitewatch/cgi-bin/metrics
touch /etc/sitewatch/seen.tsv /etc/sitewatch/queue.tsv /etc/sitewatch/results.tsv /etc/sitewatch/proxy-domains.txt

if command -v uci >/dev/null 2>&1 && [ -x /etc/init.d/uhttpd ]; then
	uci -q delete uhttpd.sitewatch || true
	uci set uhttpd.sitewatch=uhttpd
	uci set uhttpd.sitewatch.home='/www/sitewatch'
	uci set uhttpd.sitewatch.listen_http='0.0.0.0:8095'
	uci set uhttpd.sitewatch.cgi_prefix='/cgi-bin'
	uci -q delete uhttpd.sitewatch.index_page || true
	uci add_list uhttpd.sitewatch.index_page='cgi-bin/sitewatch'
	uci set uhttpd.sitewatch.script_timeout='3600'
	uci set uhttpd.sitewatch.network_timeout='30'
	uci set uhttpd.sitewatch.http_keepalive='20'
	uci set uhttpd.sitewatch.tcp_keepalive='1'
	uci commit uhttpd
	/etc/init.d/uhttpd restart
fi

echo "Installed. Open: http://<router-ip>:8095/"
echo "Needed packages for shell fallback and Pi-hole API: curl ca-bundle."
echo "If a matching dist/sitewatch-linux-* binary was present, scan/check-url use /usr/bin/sitewatch without curl."
