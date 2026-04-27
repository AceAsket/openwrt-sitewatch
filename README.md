# SiteWatch for OpenWrt + v2rayA + Pi-hole

Легкий локальный сканер для OpenWrt:

- включает DNS query logging только на короткое окно наблюдения;
- берет домены и источник запроса из DNS-логов Pi-hole/dnsmasq;
- дозированно проверяет сайты напрямую и через SOCKS/HTTP proxy v2rayA;
- показывает простой UI через `uhttpd` CGI;
- фильтрует и сканирует домены конкретного устройства;
- выгружает готовый список `domain:example.com` для правил v2rayA/Xray.

## Что ставить на роутер

Минимально нужны:

```sh
opkg update
opkg install curl ca-bundle
```

Если `curl` собран без proxy/SOCKS, нужен полный вариант `curl`/`libcurl` с поддержкой proxy. Проверка:

```sh
curl --version
```

В выводе желательно увидеть поддержку `AsynchDNS`, `HTTPS-proxy` или `SOCKS`.

## Установка

Скопировать папку `openwrt-sitewatch` на роутер, например в `/root/openwrt-sitewatch`, и выполнить:

```sh
cd /root/openwrt-sitewatch
chmod +x install-openwrt.sh
./install-openwrt.sh
```

Открыть:

```text
http://192.168.1.1:8095/cgi-bin/sitewatch
```

Установщик создает отдельный `uhttpd` instance `uhttpd.sitewatch` на порту `8095`, чтобы не смешивать SiteWatch с основной админкой OpenWrt/LuCI. CGI ставится только в `/www/sitewatch/cgi-bin/sitewatch`.

Пример секции:

```sh
uhttpd.sitewatch.home='/www/sitewatch'
uhttpd.sitewatch.listen_http='0.0.0.0:8095'
uhttpd.sitewatch.cgi_prefix='/cgi-bin'
```

Если CGI выключен, проверь `/etc/config/uhttpd`: должна быть секция/параметры CGI для `/cgi-bin`.

## Настройка

Основной файл:

```sh
/etc/sitewatch/sitewatch.conf
```

Важные параметры:

```sh
SITEWATCH_PROXY="http://127.0.0.1:20171"
SITEWATCH_BATCH="12"
SITEWATCH_TIMEOUT="7"
SITEWATCH_SLOW_SECONDS="5"
SITEWATCH_SLOW_RATIO="3"
SITEWATCH_PIHOLE_API_ENABLED="0"
SITEWATCH_PIHOLE_URL=""
SITEWATCH_PIHOLE_PASSWORD=""
SITEWATCH_PIHOLE_LOOKBACK="600"
SITEWATCH_EXCLUDE_DOMAINS="connectivitycheck.gstatic.com connectivitycheck.android.com"
SITEWATCH_CHECK_BASE_DOMAIN="1"
```

Если v2rayA слушает другой порт, поменяй `SITEWATCH_PROXY`.
`SITEWATCH_EXCLUDE_DOMAINS` не запрещает проверку домена в UI, но не дает служебным доменам автоматически попадать в VPN-выгрузку.
`SITEWATCH_CHECK_BASE_DOMAIN=1` включает дополнительную проверку базового домена: если `static2.mangapoisk.io` выглядит заблокированным, сканер отдельно проверит `mangapoisk.io`.

Для Pi-hole на отдельном хосте можно включить API-сбор:

```sh
SITEWATCH_PIHOLE_API_ENABLED="1"
SITEWATCH_PIHOLE_URL="http://192.168.50.50:8155"
SITEWATCH_PIHOLE_PASSWORD="<PIHOLE_PASSWORD>"
SITEWATCH_PIHOLE_LOOKBACK="86400"
```

Пароль лучше хранить только на роутере в `/etc/sitewatch/sitewatch.conf`, не в git.

Примеры:

```sh
SITEWATCH_PROXY="http://127.0.0.1:20171"
SITEWATCH_PROXY="socks5h://127.0.0.1:20170"
```

## DNS-источник запроса

Сборщик ищет строки вида:

```text
query[A] youmagine.com from 192.168.1.50
```

По умолчанию читаются:

```sh
/var/log/pihole/pihole.log
/tmp/log/dnsmasq.log
/var/log/messages
```

Также используется `logread -e 'query['`, если включен `SITEWATCH_USE_LOGREAD=1`.

Если Pi-hole пишет лог в другое место, поменяй:

```sh
SITEWATCH_LOG_FILES="/path/to/pihole.log /tmp/log/dnsmasq.log"
```

## Ручной запуск

Снять короткое окно DNS-наблюдения:

```sh
sitewatch-capture 45
```

Скрипт временно включает `dhcp.@dnsmasq[0].logqueries`, собирает домены каждые несколько секунд и возвращает прежнюю настройку DNS-логирования после завершения.

Запуск без таймера:

```sh
sitewatch-capture 0
```

Остановка live-режима:

```sh
sitewatch-capture stop
```

Собрать домены из уже имеющихся логов и Pi-hole API:

```sh
sitewatch-collect
```

Проверить пачку доменов:

```sh
sitewatch-scan
```

Проверить только одно устройство:

```sh
SITEWATCH_SOURCE_FILTER="192.168.50.105" SITEWATCH_FORCE_RESCAN=1 sitewatch-scan
```

Готовый список для v2rayA:

```sh
/etc/sitewatch/proxy-domains.txt
```

Формат:

```text
domain:youmagine.com
domain:myminifactory.com
```

## Фильтр по устройству

Открыть UI с конкретным источником:

```text
http://192.168.50.1:8080/cgi-bin/sitewatch?source=192.168.50.105
```

Запустить скан только для него:

```text
http://192.168.50.1:8080/cgi-bin/sitewatch?action=scan&source=192.168.50.105
```

## Cron

Для приватности и меньшего шума SiteWatch лучше держать в ручном режиме без cron: DNS-логирование включается только кнопкой `Снять DNS 45 сек`.

Если все же нужна автоматика, можно добавить:

```cron
*/10 * * * * /usr/bin/sitewatch-collect >/dev/null 2>&1
7 * * * * /usr/bin/sitewatch-scan >/dev/null 2>&1
```

Так роутер часто собирает DNS-кандидатов, но активно сканирует только одну маленькую пачку в час. В этом режиме DNS-логирование нужно держать включенным отдельно.

Для более слабого роутера:

```sh
SITEWATCH_BATCH="4"
SITEWATCH_TIMEOUT="5"
```

## Как понимать статусы

- `unchecked` - домен видели в DNS, но еще не проверяли.
- `ok` - напрямую открывается примерно нормально.
- `slow` - напрямую заметно медленнее, чем через v2rayA.
- `blocked` - напрямую таймаут/ошибка, через v2rayA открывается.
- `proxy_failed` - через v2rayA тоже не открылось, такой домен не надо автоматически добавлять в VPN-список.

## Как подключить к v2rayA

UI умеет скачать `proxy-domains.txt`, а файл на роутере лежит здесь:

```sh
/etc/sitewatch/proxy-domains.txt
```

Его можно использовать как источник для кастомного routing rule в v2rayA/Xray. Если v2rayA не умеет напрямую читать файл, список удобно открыть в UI и вставить в routing rule.

## Проверка на примере

Добавь домен в очередь вручную:

```sh
now="$(date +%s)"
printf "manual\tyoumagine.com\t%s\t%s\t1\n" "$now" "$now" >> /etc/sitewatch/seen.tsv
cp /etc/sitewatch/seen.tsv /etc/sitewatch/queue.tsv
sitewatch-scan
cat /etc/sitewatch/results.tsv
```

Если напрямую сайт не открывается, а через v2rayA открывается, появится:

```text
youmagine.com    manual    1    blocked    ...
```

И в `/etc/sitewatch/proxy-domains.txt` будет:

```text
domain:youmagine.com
```

Дополнительные выгрузки из UI:

```text
/cgi-bin/sitewatch?action=export
/cgi-bin/sitewatch?action=export_base
/cgi-bin/sitewatch?action=export_v2raya
/cgi-bin/sitewatch?action=export_v2raya_base
```

`export_v2raya` отдаёт строки для вставки в веб-интерфейс v2rayA:

```text
domain(domain: yummyani.me) -> proxy
domain(domain: shikimori.org) -> proxy
```

`export_base` и `export_v2raya_base` предварительно сворачивают поддомены до базового домена, например `static2.mangapoisk.io` -> `mangapoisk.io`.
