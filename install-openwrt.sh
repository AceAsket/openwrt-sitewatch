#!/bin/ash
set -eu

mkdir -p /etc/sitewatch /usr/bin /www/cgi-bin

cp ./sitewatch.conf /etc/sitewatch/sitewatch.conf
cp ./files/usr/bin/sitewatch-collect /usr/bin/sitewatch-collect
cp ./files/usr/bin/sitewatch-capture /usr/bin/sitewatch-capture
cp ./files/usr/bin/sitewatch-scan /usr/bin/sitewatch-scan
cp ./files/www/cgi-bin/sitewatch /www/cgi-bin/sitewatch

chmod +x /usr/bin/sitewatch-collect /usr/bin/sitewatch-capture /usr/bin/sitewatch-scan /www/cgi-bin/sitewatch
touch /etc/sitewatch/seen.tsv /etc/sitewatch/queue.tsv /etc/sitewatch/results.tsv /etc/sitewatch/proxy-domains.txt

echo "Installed. Open: http://<router-ip>/cgi-bin/sitewatch"
echo "Needed packages: curl ca-bundle. For socks proxy support, install full curl/libcurl with proxy support if BusyBox wget/curl is limited."
