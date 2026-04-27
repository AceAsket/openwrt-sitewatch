#!/bin/ash
set -eu

mkdir -p /etc/sitewatch /usr/bin /www/sitewatch/cgi-bin

cp ./sitewatch.conf /etc/sitewatch/sitewatch.conf
if [ -f ./dist/sitewatch-linux-arm64 ]; then
	cp ./dist/sitewatch-linux-arm64 /usr/bin/sitewatch
	chmod +x /usr/bin/sitewatch
fi
cp ./files/usr/bin/sitewatch-collect /usr/bin/sitewatch-collect
cp ./files/usr/bin/sitewatch-capture /usr/bin/sitewatch-capture
cp ./files/usr/bin/sitewatch-scan /usr/bin/sitewatch-scan
cp ./files/usr/bin/sitewatch-check-url /usr/bin/sitewatch-check-url
cp ./files/www/cgi-bin/sitewatch /www/sitewatch/cgi-bin/sitewatch

chmod +x /usr/bin/sitewatch-collect /usr/bin/sitewatch-capture /usr/bin/sitewatch-scan /usr/bin/sitewatch-check-url /www/sitewatch/cgi-bin/sitewatch
touch /etc/sitewatch/seen.tsv /etc/sitewatch/queue.tsv /etc/sitewatch/results.tsv /etc/sitewatch/proxy-domains.txt

if command -v uci >/dev/null 2>&1 && [ -x /etc/init.d/uhttpd ]; then
	uci -q delete uhttpd.sitewatch || true
	uci set uhttpd.sitewatch=uhttpd
	uci set uhttpd.sitewatch.home='/www/sitewatch'
	uci set uhttpd.sitewatch.listen_http='0.0.0.0:8095'
	uci set uhttpd.sitewatch.cgi_prefix='/cgi-bin'
	uci set uhttpd.sitewatch.script_timeout='3600'
	uci set uhttpd.sitewatch.network_timeout='30'
	uci set uhttpd.sitewatch.http_keepalive='20'
	uci set uhttpd.sitewatch.tcp_keepalive='1'
	uci commit uhttpd
	/etc/init.d/uhttpd restart
fi

echo "Installed. Open: http://<router-ip>:8095/cgi-bin/sitewatch"
echo "Needed packages for shell fallback and Pi-hole API: curl ca-bundle."
echo "If dist/sitewatch-linux-arm64 was present, scan/check-url use /usr/bin/sitewatch without curl."
