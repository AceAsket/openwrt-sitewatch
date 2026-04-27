# SiteWatch for OpenWrt + v2rayA + Pi-hole

Легкий локальный сканер для OpenWrt:

- включает DNS query logging только на короткое окно наблюдения;
- берет домены и источник запроса из DNS-логов Pi-hole/dnsmasq;
- дозированно проверяет сайты напрямую и через SOCKS/HTTP proxy v2rayA;
- показывает простой UI через `uhttpd` CGI;
- фильтрует и сканирует домены конкретного устройства;
- выгружает готовый список `domain:example.com` для правил v2rayA/Xray.

SiteWatch помогает понять, какие домены у конкретных устройств не открываются напрямую или заметно замедляются, и быстро выгрузить эти домены в правила v2rayA/Xray. Он не держит DNS-логирование постоянно включенным: окно наблюдения запускается вручную, затем запросы собираются, проверяются и превращаются в список для VPN.

![SiteWatch light theme](docs/screenshots/sitewatch-light.png)

![SiteWatch dark theme](docs/screenshots/sitewatch-dark.png)

## Что ставить на роутер

Для shell-fallback и Pi-hole API нужны:

```sh
opkg update
opkg install curl ca-bundle
```

Если Go-бинарник не установлен, сканирование использует shell-fallback через `curl`. Тогда нужен полный вариант `curl`/`libcurl` с поддержкой proxy. Проверка:

```sh
curl --version
```

В выводе желательно увидеть поддержку `AsynchDNS`, `HTTPS-proxy` или `SOCKS`.

Если установлен бинарник `/usr/bin/sitewatch`, сканирование и ручная проверка URL работают без `curl`: HTTP/HTTPS, HTTP proxy и SOCKS5/SOCKS5H выполняются внутри Go-бинарника. Shell-скрипты остаются совместимым fallback.

Сборка для GL-MT6000 / `aarch64_cortex-a53`:

```sh
make build-openwrt-arm64
```

Релизная сборка для основных архитектур OpenWrt:

```sh
make build-openwrt-all
```

Без локального Go можно собрать тем же способом через Docker на этом ПК. По умолчанию собираются все релизные цели:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-openwrt-docker.ps1
```

Можно собрать одну архитектуру:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\build-openwrt-docker.ps1 -Arch arm64
```

В GitLab включен pipeline `.gitlab-ci.yml`: job `build-openwrt-release` собирает релизный набор и сохраняет `dist/` в artifacts на 30 дней.

Получится:

```text
dist/sitewatch-linux-arm64
dist/sitewatch-linux-armv7
dist/sitewatch-linux-armv6
dist/sitewatch-linux-amd64
dist/sitewatch-linux-386
dist/sitewatch-linux-mips
dist/sitewatch-linux-mipsle
dist/SHA256SUMS
```

Для OpenWrt `aarch64_cortex-a53` нужен `sitewatch-linux-arm64`; для `x86_64` нужен `sitewatch-linux-amd64`; для `i386_pentium4` чаще всего нужен `sitewatch-linux-386`; для `arm_cortex-a7_*` подойдет `sitewatch-linux-armv7`; для многих старых MIPS-роутеров используются `sitewatch-linux-mips` или `sitewatch-linux-mipsle`.

Установщик сам выберет подходящий `dist/sitewatch-linux-*` по `uname -m` и `/etc/openwrt_release` и положит его в `/usr/bin/sitewatch`. Если автоопределение не подошло, скопируй нужный бинарник вручную как `/usr/bin/sitewatch`.

## Установка

Скопировать папку `openwrt-sitewatch` на роутер, например в `/root/openwrt-sitewatch`, и выполнить:

```sh
cd /root/openwrt-sitewatch
chmod +x install-openwrt.sh
./install-openwrt.sh
```

Открыть:

```text
http://192.168.1.1:8095/
```

Установщик создает отдельный `uhttpd` instance `uhttpd.sitewatch` на порту `8095`, чтобы не смешивать SiteWatch с основной админкой OpenWrt/LuCI. CGI ставится в `/www/sitewatch/cgi-bin/sitewatch`, а корень порта открывает его как index.

Пример секции:

```sh
uhttpd.sitewatch.home='/www/sitewatch'
uhttpd.sitewatch.listen_http='0.0.0.0:8095'
uhttpd.sitewatch.cgi_prefix='/cgi-bin'
uhttpd.sitewatch.index_page='cgi-bin/sitewatch'
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
SITEWATCH_PIHOLE_DISK="0"
SITEWATCH_EXCLUDE_DOMAINS="connectivitycheck.gstatic.com connectivitycheck.android.com"
SITEWATCH_CHECK_BASE_DOMAIN="1"
SITEWATCH_DPI_DNS_SERVER="1.1.1.1"
SITEWATCH_DPI_DOH_URL="https://cloudflare-dns.com/dns-query"
```

Если v2rayA слушает другой порт, поменяй `SITEWATCH_PROXY`.
`SITEWATCH_EXCLUDE_DOMAINS` не запрещает проверку домена в UI, но не дает служебным доменам автоматически попадать в VPN-выгрузку.
`SITEWATCH_CHECK_BASE_DOMAIN=1` включает дополнительную проверку базового домена: если `static2.mangapoisk.io` выглядит заблокированным, сканер отдельно проверит `mangapoisk.io`.
Ручная проверка URL также делает легкие DPI-пробы: сравнивает UDP DNS с DoH, проверяет TLS 1.3/TLS 1.2 напрямую к эталонному IP и делает HTTP probe на порт 80. `SITEWATCH_DPI_DNS_SERVER` и `SITEWATCH_DPI_DOH_URL` задают пару DNS-источников для сравнения.

Для Pi-hole на отдельном хосте можно включить API-сбор:

```sh
SITEWATCH_PIHOLE_API_ENABLED="1"
SITEWATCH_PIHOLE_URL="http://192.168.50.50:8155"
SITEWATCH_PIHOLE_PASSWORD="<PIHOLE_PASSWORD>"
SITEWATCH_PIHOLE_LOOKBACK="86400"
SITEWATCH_PIHOLE_DISK="0"
```

Пароль лучше хранить только на роутере в `/etc/sitewatch/sitewatch.conf`, не в git.
По умолчанию SiteWatch читает свежую live-выдачу Pi-hole API. Если нужна именно долговременная база Pi-hole, включи `SITEWATCH_PIHOLE_DISK="1"`, но новые запросы могут появляться там не сразу.
В статусе Pi-hole показывается количество реально импортированных DNS-пар `source/domain`, а не число сырых записей API. Запросы от `127.0.0.1` и `::1` игнорируются.

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

Разово проверить конкретный URL напрямую и через v2rayA:

```sh
sitewatch-check-url https://youmagine.com/
```

Добавить домен в VPN-выгрузку, если проверка покажет `blocked` или `slow`:

```sh
sitewatch-check-url --add https://youmagine.com/
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
http://192.168.50.1:8095/?source=192.168.50.105
```

Запустить скан только для него:

```text
http://192.168.50.1:8095/?action=scan&source=192.168.50.105
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
/?action=export
/?action=export_base
/?action=export_v2raya
/?action=export_v2raya_base
```

`export_v2raya` отдаёт строки для вставки в веб-интерфейс v2rayA:

```text
domain(domain: yummyani.me) -> proxy
domain(domain: shikimori.org) -> proxy
```

`export_base` и `export_v2raya_base` предварительно сворачивают поддомены до базового домена, например `static2.mangapoisk.io` -> `mangapoisk.io`.
