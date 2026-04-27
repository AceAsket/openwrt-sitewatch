package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type config struct {
	Queue           string
	Results         string
	ProxyOut        string
	Lock            string
	ScanStatus      string
	Proxy           string
	Batch           int
	Timeout         time.Duration
	MinRescan       time.Duration
	SlowSeconds     float64
	SlowRatio       float64
	SourceFilter    string
	ForceRescan     bool
	ExcludeDomains  []string
	CheckBaseDomain bool
	DNSServer       string
	DoHURL          string
}

type measurement struct {
	Code string
	Time float64
}

type checkResult struct {
	Status string
	URL    string
	Domain string
	Direct measurement
	Proxy  measurement
	Added  string
	DPI    dpiProbe
}

type dnsProbe struct {
	Status string
	UDPIP  string
	DoHIP  string
	Detail string
}

type tlsProbe struct {
	Status string
	Time   float64
	Detail string
}

type httpProbe struct {
	Status string
	Code   string
	Time   float64
	Detail string
}

type dpiProbe struct {
	DNS   dnsProbe
	TLS13 tlsProbe
	TLS12 tlsProbe
	HTTP  httpProbe
}

type seenEntry struct {
	Source string
	Domain string
	First  int64
	Last   int64
	Count  int
}

type resultEntry struct {
	Domain     string
	Source     string
	Count      int
	Status     string
	DirectCode string
	DirectTime string
	ProxyCode  string
	ProxyTime  string
	Scanned    int64
	DPIStatus  string
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cfg := loadConfig()
	var err error
	switch os.Args[1] {
	case "check-url":
		err = cmdCheckURL(cfg, os.Args[2:])
	case "scan":
		err = cmdScan(cfg)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sitewatch check-url [--add] <url>")
	fmt.Fprintln(os.Stderr, "       sitewatch scan")
}

func loadConfig() config {
	values := map[string]string{}
	for _, path := range []string{"sitewatch.conf", "/etc/sitewatch/sitewatch.conf"} {
		readShellConfig(path, values)
	}
	for _, env := range os.Environ() {
		if k, v, ok := strings.Cut(env, "="); ok {
			values[k] = v
		}
	}

	return config{
		Queue:           getStr(values, "SITEWATCH_QUEUE", "/etc/sitewatch/queue.tsv"),
		Results:         getStr(values, "SITEWATCH_RESULTS", "/etc/sitewatch/results.tsv"),
		ProxyOut:        getStr(values, "SITEWATCH_PROXY_OUT", "/etc/sitewatch/proxy-domains.txt"),
		Lock:            getStr(values, "SITEWATCH_LOCK", "/tmp/sitewatch-scan.lock"),
		ScanStatus:      getStr(values, "SITEWATCH_SCAN_STATUS", "/tmp/sitewatch-scan.status"),
		Proxy:           getStr(values, "SITEWATCH_PROXY", "socks5h://127.0.0.1:20170"),
		Batch:           getInt(values, "SITEWATCH_BATCH", 12),
		Timeout:         time.Duration(getInt(values, "SITEWATCH_TIMEOUT", 7)) * time.Second,
		MinRescan:       time.Duration(getInt(values, "SITEWATCH_MIN_RESCAN", 86400)) * time.Second,
		SlowSeconds:     getFloat(values, "SITEWATCH_SLOW_SECONDS", 5),
		SlowRatio:       getFloat(values, "SITEWATCH_SLOW_RATIO", 3),
		SourceFilter:    getStr(values, "SITEWATCH_SOURCE_FILTER", ""),
		ForceRescan:     getStr(values, "SITEWATCH_FORCE_RESCAN", "0") == "1",
		ExcludeDomains:  strings.Fields(getStr(values, "SITEWATCH_EXCLUDE_DOMAINS", "connectivitycheck.gstatic.com connectivitycheck.android.com")),
		CheckBaseDomain: getStr(values, "SITEWATCH_CHECK_BASE_DOMAIN", "1") == "1",
		DNSServer:       getStr(values, "SITEWATCH_DPI_DNS_SERVER", "1.1.1.1"),
		DoHURL:          getStr(values, "SITEWATCH_DPI_DOH_URL", "https://cloudflare-dns.com/dns-query"),
	}
}

func readShellConfig(path string, values map[string]string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, val, _ := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		if key != "" {
			values[key] = val
		}
	}
}

func getStr(values map[string]string, key string, fallback string) string {
	if val, ok := values[key]; ok && val != "" {
		return val
	}
	return fallback
}

func getInt(values map[string]string, key string, fallback int) int {
	val, err := strconv.Atoi(getStr(values, key, ""))
	if err != nil {
		return fallback
	}
	return val
}

func getFloat(values map[string]string, key string, fallback float64) float64 {
	val, err := strconv.ParseFloat(getStr(values, key, ""), 64)
	if err != nil {
		return fallback
	}
	return val
}

func cmdCheckURL(cfg config, args []string) error {
	add := false
	filtered := args[:0]
	for _, arg := range args {
		if arg == "--add" {
			add = true
			continue
		}
		filtered = append(filtered, arg)
	}
	if len(filtered) != 1 {
		return errors.New("check-url needs one URL")
	}

	result, err := checkURL(cfg, filtered[0], add)
	if err != nil {
		fmt.Printf("status\terror\n")
		fmt.Printf("error\t%s\n", err.Error())
		return err
	}

	fmt.Printf("status\t%s\n", result.Status)
	fmt.Printf("url\t%s\n", result.URL)
	fmt.Printf("domain\t%s\n", result.Domain)
	fmt.Printf("direct_code\t%s\n", result.Direct.Code)
	fmt.Printf("direct_time\t%.6f\n", result.Direct.Time)
	fmt.Printf("proxy_code\t%s\n", result.Proxy.Code)
	fmt.Printf("proxy_time\t%.6f\n", result.Proxy.Time)
	fmt.Printf("dns_status\t%s\n", result.DPI.DNS.Status)
	fmt.Printf("dns_udp_ip\t%s\n", result.DPI.DNS.UDPIP)
	fmt.Printf("dns_doh_ip\t%s\n", result.DPI.DNS.DoHIP)
	fmt.Printf("dns_detail\t%s\n", result.DPI.DNS.Detail)
	fmt.Printf("tls13_status\t%s\n", result.DPI.TLS13.Status)
	fmt.Printf("tls13_time\t%.6f\n", result.DPI.TLS13.Time)
	fmt.Printf("tls13_detail\t%s\n", result.DPI.TLS13.Detail)
	fmt.Printf("tls12_status\t%s\n", result.DPI.TLS12.Status)
	fmt.Printf("tls12_time\t%.6f\n", result.DPI.TLS12.Time)
	fmt.Printf("tls12_detail\t%s\n", result.DPI.TLS12.Detail)
	fmt.Printf("http_status\t%s\n", result.DPI.HTTP.Status)
	fmt.Printf("http_code\t%s\n", result.DPI.HTTP.Code)
	fmt.Printf("http_time\t%.6f\n", result.DPI.HTTP.Time)
	fmt.Printf("http_detail\t%s\n", result.DPI.HTTP.Detail)
	fmt.Printf("added\t%s\n", result.Added)
	return nil
}

func cmdScan(cfg config) error {
	if err := ensureDataFiles(cfg); err != nil {
		return err
	}
	if err := os.Mkdir(cfg.Lock, 0755); err != nil {
		if os.IsExist(err) {
			fmt.Println("sitewatch scan already running")
			return nil
		}
		return err
	}
	defer os.Remove(cfg.Lock)

	now := time.Now().Unix()
	seen, err := readSeen(cfg.Queue)
	if err != nil {
		return err
	}
	results, err := readResults(cfg.Results)
	if err != nil {
		return err
	}

	best := map[string]seenEntry{}
	for _, item := range seen {
		if item.Domain == "" {
			continue
		}
		if cfg.SourceFilter != "" && item.Source != cfg.SourceFilter {
			continue
		}
		if old, ok := best[item.Domain]; !ok || item.Count > old.Count {
			best[item.Domain] = item
		}
	}

	domains := make([]seenEntry, 0, len(best))
	for _, item := range best {
		last := results[item.Domain].Scanned
		if cfg.ForceRescan || last == 0 || time.Duration(now-last)*time.Second >= cfg.MinRescan {
			domains = append(domains, item)
		}
	}
	sort.Slice(domains, func(i, j int) bool {
		if domains[i].Count == domains[j].Count {
			return domains[i].Domain < domains[j].Domain
		}
		return domains[i].Count > domains[j].Count
	})
	if len(domains) > cfg.Batch {
		domains = domains[:cfg.Batch]
	}

	writeScanStatus(cfg, "running", now, len(domains), 0, "")
	if len(domains) == 0 {
		writeScanStatus(cfg, "done", now, 0, 0, "")
		return nil
	}

	for idx, item := range domains {
		writeScanStatus(cfg, "running", now, len(domains), idx, item.Domain)
		result, err := checkURL(cfg, "https://"+item.Domain+"/", false)
		if err != nil {
			continue
		}
		results[result.Domain] = resultEntry{
			Domain:     result.Domain,
			Source:     item.Source,
			Count:      item.Count,
			Status:     result.Status,
			DirectCode: result.Direct.Code,
			DirectTime: fmt.Sprintf("%.6f", result.Direct.Time),
			ProxyCode:  result.Proxy.Code,
			ProxyTime:  fmt.Sprintf("%.6f", result.Proxy.Time),
			Scanned:    now,
			DPIStatus:  dpiSummary(result.DPI),
		}
		maybeAddProxyDomain(cfg, result.Domain, result.Status)

		if cfg.CheckBaseDomain && (result.Status == "blocked" || result.Status == "slow") {
			base := baseDomain(result.Domain)
			if base != "" && base != result.Domain {
				baseResult, err := checkURL(cfg, "https://"+base+"/", false)
				if err == nil {
					results[baseResult.Domain] = resultEntry{
						Domain:     baseResult.Domain,
						Source:     item.Source,
						Count:      item.Count,
						Status:     baseResult.Status,
						DirectCode: baseResult.Direct.Code,
						DirectTime: fmt.Sprintf("%.6f", baseResult.Direct.Time),
						ProxyCode:  baseResult.Proxy.Code,
						ProxyTime:  fmt.Sprintf("%.6f", baseResult.Proxy.Time),
						Scanned:    now,
						DPIStatus:  dpiSummary(baseResult.DPI),
					}
					maybeAddProxyDomain(cfg, baseResult.Domain, baseResult.Status)
				}
			}
		}
		writeScanStatus(cfg, "running", now, len(domains), idx+1, item.Domain)
	}

	if err := writeResults(cfg.Results, results); err != nil {
		writeScanStatus(cfg, "error", now, len(domains), len(domains), "")
		return err
	}
	writeScanStatus(cfg, "done", now, len(domains), len(domains), "")
	return nil
}

func writeScanStatus(cfg config, state string, started int64, total int, done int, current string) {
	if cfg.ScanStatus == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(cfg.ScanStatus), 0755)
	tmp := cfg.ScanStatus + ".tmp"
	line := fmt.Sprintf("%s\t%d\t%d\t%d\t%s\t%d\n", state, started, total, done, current, time.Now().Unix())
	if err := os.WriteFile(tmp, []byte(line), 0644); err == nil {
		_ = os.Rename(tmp, cfg.ScanStatus)
	}
}

func dpiSummary(dpi dpiProbe) string {
	switch {
	case dpi.DNS.Status == "spoofed" || dpi.DNS.Status == "intercepted" || dpi.DNS.Status == "blocked":
		return dpi.DNS.Status
	case dpi.TLS13.Status != "" && dpi.TLS13.Status != "ok":
		return "tls13_" + dpi.TLS13.Status
	case dpi.TLS12.Status != "" && dpi.TLS12.Status != "ok":
		return "tls12_" + dpi.TLS12.Status
	case dpi.HTTP.Status != "" && dpi.HTTP.Status != "ok":
		return "http_" + dpi.HTTP.Status
	case dpi.DNS.Status != "":
		return dpi.DNS.Status
	default:
		return "-"
	}
}

func ensureDataFiles(cfg config) error {
	for _, path := range []string{cfg.Queue, cfg.Results, cfg.ProxyOut} {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return err
		}
		file, err := os.OpenFile(path, os.O_CREATE, 0644)
		if err != nil {
			return err
		}
		file.Close()
	}
	return nil
}

func checkURL(cfg config, input string, add bool) (checkResult, error) {
	checkedURL, host, err := normalizeURL(input)
	if err != nil {
		return checkResult{}, err
	}

	direct := measureURL(cfg, checkedURL, "")
	proxy := measureURL(cfg, checkedURL, cfg.Proxy)
	dpi := probeDPI(cfg, host)
	status := classify(cfg, direct, proxy)
	added := "no"
	if add {
		added = maybeAddProxyDomain(cfg, host, status)
	}

	return checkResult{
		Status: status,
		URL:    checkedURL,
		Domain: host,
		Direct: direct,
		Proxy:  proxy,
		Added:  added,
		DPI:    dpi,
	}, nil
}

func normalizeURL(input string) (string, string, error) {
	raw := cleanManualInput(input)
	if raw == "" {
		return "", "", errors.New("empty_url")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", "", errors.New("bad_url")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", errors.New("unsupported_scheme")
	}
	host := strings.ToLower(parsed.Hostname())
	if !validDomain(host) {
		return "", host, errors.New("bad_domain")
	}
	return parsed.String(), host, nil
}

func cleanManualInput(input string) string {
	raw := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(input))
	raw = strings.Trim(raw, `"'`+"`"+`<>[]{}(),;`)

	if idx := strings.Index(strings.ToLower(raw), "domain:"); idx >= 0 {
		raw = raw[idx+len("domain:"):]
		raw = strings.Trim(raw, `"'`+"`"+`<>[]{}(),;`)
		for i, r := range raw {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
				continue
			}
			raw = raw[:i]
			break
		}
	}

	return raw
}

func validDomain(host string) bool {
	if host == "" || !strings.Contains(host, ".") || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func measureURL(cfg config, target string, proxyRaw string) measurement {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	client, err := httpClient(cfg, proxyRaw)
	if err != nil {
		return measurement{Code: "000", Time: cfg.Timeout.Seconds()}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return measurement{Code: "000", Time: cfg.Timeout.Seconds()}
	}
	req.Header.Set("User-Agent", "SiteWatch/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return measurement{Code: "000", Time: cfg.Timeout.Seconds()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512*1024))
	return measurement{Code: fmt.Sprintf("%03d", resp.StatusCode), Time: elapsed}
}

func probeDPI(cfg config, domain string) dpiProbe {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout*3)
	defer cancel()

	dns := probeDNS(ctx, cfg, domain)
	probeIP := dns.DoHIP
	if net.ParseIP(probeIP) == nil {
		probeIP = dns.UDPIP
	}
	if net.ParseIP(probeIP) == nil {
		return dpiProbe{
			DNS:   dns,
			TLS13: tlsProbe{Status: "skipped", Detail: "no_probe_ip"},
			TLS12: tlsProbe{Status: "skipped", Detail: "no_probe_ip"},
			HTTP:  httpProbe{Status: "skipped", Detail: "no_probe_ip"},
		}
	}

	return dpiProbe{
		DNS:   dns,
		TLS13: probeTLS(ctx, cfg, domain, probeIP, tls.VersionTLS13),
		TLS12: probeTLS(ctx, cfg, domain, probeIP, tls.VersionTLS12),
		HTTP:  probeHTTP(ctx, cfg, domain, probeIP),
	}
}

type dohResponse struct {
	Answer []struct {
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func probeDNS(ctx context.Context, cfg config, domain string) dnsProbe {
	dohIPs, dohErr := resolveDoHAll(ctx, cfg, domain)
	udpIPs, udpErr := resolveUDPAll(ctx, cfg, domain)
	dohIP := strings.Join(dohIPs, ",")
	udpIP := strings.Join(udpIPs, ",")

	result := dnsProbe{
		Status: "ok",
		UDPIP:  valueOrError(udpIP, udpErr),
		DoHIP:  valueOrError(dohIP, dohErr),
	}

	switch {
	case dohErr != nil && udpErr != nil:
		result.Status = "blocked"
		result.Detail = "doh_and_udp_failed"
	case dohErr != nil:
		result.Status = "doh_failed"
		result.Detail = cleanDetail(dohErr.Error())
	case udpErr != nil:
		result.Status = "intercepted"
		result.Detail = cleanDetail(udpErr.Error())
	case len(dohIPs) > 0 && len(udpIPs) > 0 && !anyIPOverlap(dohIPs, udpIPs):
		result.Status = "spoofed"
		result.Detail = "udp_doh_mismatch"
	default:
		result.Detail = "udp_matches_doh"
	}

	return result
}

func resolveDoH(ctx context.Context, cfg config, domain string) (string, error) {
	ips, err := resolveDoHAll(ctx, cfg, domain)
	if err != nil {
		return "", err
	}
	return ips[0], nil
}

func resolveDoHAll(ctx context.Context, cfg config, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	endpoint, err := url.Parse(cfg.DoHURL)
	if err != nil {
		return nil, err
	}
	query := endpoint.Query()
	query.Set("name", domain)
	query.Set("type", "A")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", "SiteWatch/1.0")

	client := &http.Client{Timeout: cfg.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("doh_http_%d", resp.StatusCode)
	}

	var data dohResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&data); err != nil {
		return nil, err
	}
	var ips []string
	for _, answer := range data.Answer {
		if answer.Type == 1 && net.ParseIP(answer.Data).To4() != nil {
			ips = appendUnique(ips, answer.Data)
		}
	}
	if len(ips) == 0 {
		return nil, errors.New("doh_no_a_record")
	}
	return ips, nil
}

func resolveUDP(ctx context.Context, cfg config, domain string) (string, error) {
	ips, err := resolveUDPAll(ctx, cfg, domain)
	if err != nil {
		return "", err
	}
	return ips[0], nil
}

func resolveUDPAll(ctx context.Context, cfg config, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	server := cfg.DNSServer
	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: cfg.Timeout}
			return dialer.DialContext(ctx, "udp", server)
		},
	}
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, item := range ips {
		if ip4 := item.IP.To4(); ip4 != nil {
			out = appendUnique(out, ip4.String())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("udp_no_a_record")
	}
	return out, nil
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func anyIPOverlap(left []string, right []string) bool {
	seen := map[string]bool{}
	for _, item := range left {
		seen[item] = true
	}
	for _, item := range right {
		if seen[item] {
			return true
		}
	}
	return false
}

func probeTLS(ctx context.Context, cfg config, domain string, ip string, version uint16) tlsProbe {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	start := time.Now()
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "443"))
	if err != nil {
		return tlsProbe{Status: classifyProbeError(err), Time: cfg.Timeout.Seconds(), Detail: cleanDetail(err.Error())}
	}
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,
		MinVersion:         version,
		MaxVersion:         version,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return tlsProbe{Status: classifyProbeError(err), Time: time.Since(start).Seconds(), Detail: cleanDetail(err.Error())}
	}
	_, _ = tlsConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + domain + "\r\nConnection: close\r\n\r\n"))
	_, _ = io.CopyN(io.Discard, tlsConn, 1)
	return tlsProbe{Status: "ok", Time: time.Since(start).Seconds(), Detail: tlsVersionLabel(version)}
}

func probeHTTP(ctx context.Context, cfg config, domain string, ip string) httpProbe {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: cfg.Timeout}
			return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, "80"))
		},
		ResponseHeaderTimeout: cfg.Timeout,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+domain+"/", nil)
	if err != nil {
		return httpProbe{Status: "error", Code: "000", Time: 0, Detail: cleanDetail(err.Error())}
	}
	req.Header.Set("User-Agent", "SiteWatch/1.0")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return httpProbe{Status: classifyProbeError(err), Code: "000", Time: elapsed, Detail: cleanDetail(err.Error())}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	status := "ok"
	detail := resp.Status
	location := resp.Header.Get("Location")
	if looksLikeISPBlock(location, string(body)) {
		status = "isp_page"
		detail = "block_marker_or_cross_redirect"
	}
	return httpProbe{Status: status, Code: fmt.Sprintf("%03d", resp.StatusCode), Time: elapsed, Detail: cleanDetail(detail)}
}

func valueOrError(value string, err error) string {
	if err != nil {
		return "error"
	}
	if value == "" {
		return "-"
	}
	return value
}

func classifyProbeError(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "timeout"
	case strings.Contains(msg, "reset"):
		return "reset"
	case strings.Contains(msg, "refused"):
		return "refused"
	case strings.Contains(msg, "certificate"):
		return "mitm"
	default:
		return "error"
	}
}

func cleanDetail(raw string) string {
	raw = strings.ReplaceAll(raw, "\t", " ")
	raw = strings.ReplaceAll(raw, "\r", " ")
	raw = strings.ReplaceAll(raw, "\n", " ")
	if len(raw) > 120 {
		return raw[:120]
	}
	return raw
}

func tlsVersionLabel(version uint16) string {
	if version == tls.VersionTLS13 {
		return "tls1.3"
	}
	return "tls1.2"
}

func looksLikeISPBlock(location string, body string) bool {
	lower := strings.ToLower(location + "\n" + body)
	markers := []string{
		"blocked",
		"access denied",
		"forbidden by",
		"заблок",
		"доступ огранич",
		"решению суда",
		"роскомнадзор",
	}
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func httpClient(cfg config, proxyRaw string) (*http.Client, error) {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: cfg.Timeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   cfg.Timeout,
		ResponseHeaderTimeout: cfg.Timeout,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}

	if proxyRaw != "" {
		proxyURL, err := url.Parse(proxyRaw)
		if err != nil {
			return nil, err
		}
		switch proxyURL.Scheme {
		case "http", "https":
			transport.Proxy = http.ProxyURL(proxyURL)
		case "socks5", "socks5h":
			dialer := &socksDialer{proxy: proxyURL, timeout: cfg.Timeout}
			transport.Proxy = nil
			transport.DialContext = dialer.DialContext
		default:
			return nil, fmt.Errorf("unsupported_proxy_scheme")
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}, nil
}

func classify(cfg config, direct measurement, proxy measurement) string {
	if proxy.Code == "000" {
		return "proxy_failed"
	}
	if direct.Code == "000" && proxy.Code != "000" {
		return "blocked"
	}
	if direct.Code != "000" && proxy.Code != "000" && direct.Time >= cfg.SlowSeconds && direct.Time >= proxy.Time*cfg.SlowRatio {
		return "slow"
	}
	return "ok"
}

func domainExcluded(cfg config, domain string) bool {
	for _, excluded := range cfg.ExcludeDomains {
		if domain == excluded || strings.HasSuffix(domain, "."+excluded) {
			return true
		}
	}
	return false
}

func maybeAddProxyDomain(cfg config, domain string, status string) string {
	if status != "blocked" && status != "slow" {
		return "no"
	}
	if domainExcluded(cfg, domain) {
		return "excluded"
	}
	if err := os.MkdirAll(filepath.Dir(cfg.ProxyOut), 0755); err != nil {
		return "error"
	}
	existing, _ := readProxyDomains(cfg.ProxyOut)
	if existing[domain] {
		return "already"
	}
	file, err := os.OpenFile(cfg.ProxyOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return "error"
	}
	defer file.Close()
	if _, err := fmt.Fprintf(file, "domain:%s\n", domain); err != nil {
		return "error"
	}
	return "yes"
}

func readProxyDomains(path string) (map[string]bool, error) {
	out := map[string]bool{}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		domain := strings.TrimPrefix(line, "domain:")
		if domain != "" {
			out[domain] = true
		}
	}
	return out, scanner.Err()
}

func readSeen(path string) ([]seenEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	var out []seenEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 5 {
			continue
		}
		out = append(out, seenEntry{
			Source: parts[0],
			Domain: parts[1],
			First:  parseInt64(parts[2]),
			Last:   parseInt64(parts[3]),
			Count:  parseInt(parts[4]),
		})
	}
	return out, scanner.Err()
}

func readResults(path string) (map[string]resultEntry, error) {
	out := map[string]resultEntry{}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return out, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 9 {
			continue
		}
		out[parts[0]] = resultEntry{
			Domain:     parts[0],
			Source:     parts[1],
			Count:      parseInt(parts[2]),
			Status:     parts[3],
			DirectCode: parts[4],
			DirectTime: parts[5],
			ProxyCode:  parts[6],
			ProxyTime:  parts[7],
			Scanned:    parseInt64(parts[8]),
		}
		if len(parts) >= 10 {
			item := out[parts[0]]
			item.DPIStatus = parts[9]
			out[parts[0]] = item
		}
	}
	return out, scanner.Err()
}

func writeResults(path string, results map[string]resultEntry) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	items := make([]resultEntry, 0, len(results))
	for _, item := range results {
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Status == items[j].Status {
			return items[i].Domain < items[j].Domain
		}
		return items[i].Status < items[j].Status
	})
	writer := bufio.NewWriter(file)
	for _, item := range items {
		fmt.Fprintf(writer, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			item.Domain, item.Source, item.Count, item.Status, item.DirectCode, item.DirectTime, item.ProxyCode, item.ProxyTime, item.Scanned, item.DPIStatus)
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parseInt(raw string) int {
	val, _ := strconv.Atoi(raw)
	return val
}

func parseInt64(raw string) int64 {
	val, _ := strconv.ParseInt(raw, 10, 64)
	return val
}

func baseDomain(domain string) string {
	parts := strings.Split(domain, ".")
	if len(parts) <= 2 {
		return domain
	}
	suffix := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if len(parts) >= 3 && isThreePartSuffix(suffix) {
		return parts[len(parts)-3] + "." + suffix
	}
	return suffix
}

func isThreePartSuffix(suffix string) bool {
	switch suffix {
	case "co.uk", "com.uk", "net.uk", "org.uk", "ac.uk", "gov.uk", "edu.uk",
		"co.jp", "com.jp", "net.jp", "org.jp", "ac.jp", "gov.jp", "edu.jp",
		"co.kr", "com.kr", "net.kr", "org.kr", "ac.kr", "gov.kr", "edu.kr",
		"co.nz", "com.nz", "net.nz", "org.nz", "ac.nz", "gov.nz", "edu.nz",
		"co.za", "com.za", "net.za", "org.za", "ac.za", "gov.za", "edu.za",
		"co.br", "com.br", "net.br", "org.br", "ac.br", "gov.br", "edu.br":
		return true
	default:
		return false
	}
}

type socksDialer struct {
	proxy   *url.URL
	timeout time.Duration
}

func (d *socksDialer) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", d.proxy.Host)
	if err != nil {
		return nil, err
	}
	if err := conn.SetDeadline(time.Now().Add(d.timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	if err := d.handshake(conn, address); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func (d *socksDialer) handshake(conn net.Conn, address string) error {
	host, portRaw, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil {
		return err
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return errors.New("socks_auth_failed")
	}

	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks_host_too_long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(port))
	req = append(req, portBuf...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x05 || header[1] != 0x00 {
		return fmt.Errorf("socks_connect_failed_%d", header[1])
	}
	var skip int
	switch header[3] {
	case 0x01:
		skip = net.IPv4len + 2
	case 0x04:
		skip = net.IPv6len + 2
	case 0x03:
		lenBuf := []byte{0}
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		skip = int(lenBuf[0]) + 2
	default:
		return errors.New("socks_bad_atyp")
	}
	_, err = io.CopyN(io.Discard, conn, int64(skip))
	return err
}
