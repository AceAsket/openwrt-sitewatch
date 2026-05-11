package main

import (
	"bufio"
	"context"
	"crypto/rand"
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
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

type config struct {
	Queue           string
	Results         string
	NetResults      string
	FlowResults     string
	ProxyOut        string
	Lock            string
	ScanStatus      string
	CaptureStatus   string
	DetectorStatus  string
	DetectorHistory string
	DetectorBin     string
	FlowProbeBin    string
	DNSDumpIface    string
	DNSDumpEvents   string
	AgentIngestURL  string
	IngestToken     string
	FlowUDPPorts    []portRange
	FlowTCPPorts    []portRange
	Proxy           string
	Batch           int
	Workers         int
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
	ProbeTarget     string
	ProbePorts      []int
	ProbeMode       string
	ReflectorListen string
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

type apiStatus struct {
	Capture  string `json:"capture"`
	Scan     string `json:"scan"`
	Detector string `json:"detector"`
	Seen     int    `json:"seen"`
	Results  int    `json:"results"`
	Pending  int    `json:"pending"`
	Proxy    int    `json:"proxy"`
}

type apiDomainRow struct {
	Status     string `json:"status"`
	Domain     string `json:"domain"`
	Source     string `json:"source"`
	Queries    int    `json:"queries"`
	DirectCode string `json:"direct_code,omitempty"`
	DirectTime string `json:"direct_time,omitempty"`
	ProxyCode  string `json:"proxy_code,omitempty"`
	ProxyTime  string `json:"proxy_time,omitempty"`
	DPI        string `json:"dpi,omitempty"`
	Scanned    int64  `json:"scanned,omitempty"`
}

type flowEntry struct {
	Time    int64  `json:"time"`
	Mode    string `json:"mode"`
	Source  string `json:"source"`
	Target  string `json:"target"`
	Port    string `json:"port"`
	Status  string `json:"status"`
	Packets int    `json:"packets"`
	Bytes   int    `json:"bytes"`
	Detail  string `json:"detail"`
}

type portRange struct {
	Start int
	End   int
}

type conntrackFlow struct {
	Proto   string
	Source  string
	Target  string
	Port    int
	Assured bool
	Packets int
	Bytes   int
}

type detectorHistoryEntry struct {
	RunID   string `json:"run_id"`
	Time    int64  `json:"time"`
	Profile string `json:"profile"`
	Target  string `json:"target"`
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
	Source  string `json:"source"`
}

type detectorRun struct {
	cfg      config
	runID    string
	profile  string
	url      string
	target   string
	ports    []int
	duration int
	source   string
	started  int64
	total    int
	done     int
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
	case "probe":
		err = cmdProbe(cfg, os.Args[2:])
	case "reflector":
		err = cmdReflector(cfg, os.Args[2:])
	case "serve":
		err = cmdServe(cfg, os.Args[2:])
	case "detector":
		err = cmdDetector(cfg, os.Args[2:])
	case "flow-probe":
		err = cmdFlowProbe(cfg, os.Args[2:])
	case "dns-dump":
		err = cmdDNSDump(cfg, os.Args[2:])
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
	fmt.Fprintln(os.Stderr, "       sitewatch probe [udp|tcp|both] host:port[,port...]")
	fmt.Fprintln(os.Stderr, "       sitewatch reflector [listen]")
	fmt.Fprintln(os.Stderr, "       sitewatch serve [listen]")
	fmt.Fprintln(os.Stderr, "       sitewatch detector [quick|site|discord|full] [url] [target] [ports] [duration] [source]")
	fmt.Fprintln(os.Stderr, "       sitewatch flow-probe [duration]")
	fmt.Fprintln(os.Stderr, "       sitewatch dns-dump [stdout|local|ingest] [duration]")
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
		NetResults:      getStr(values, "SITEWATCH_NET_RESULTS", "/etc/sitewatch/net-probes.tsv"),
		FlowResults:     getStr(values, "SITEWATCH_FLOW_RESULTS", "/etc/sitewatch/flow-probes.tsv"),
		ProxyOut:        getStr(values, "SITEWATCH_PROXY_OUT", "/etc/sitewatch/proxy-domains.txt"),
		Lock:            getStr(values, "SITEWATCH_LOCK", "/tmp/sitewatch-scan.lock"),
		ScanStatus:      getStr(values, "SITEWATCH_SCAN_STATUS", "/tmp/sitewatch-scan.status"),
		CaptureStatus:   getStr(values, "SITEWATCH_CAPTURE_STATUS", "/tmp/sitewatch-capture.status"),
		DetectorStatus:  getStr(values, "SITEWATCH_DETECTOR_STATUS", "/tmp/sitewatch-detector.status"),
		DetectorHistory: getStr(values, "SITEWATCH_DETECTOR_HISTORY", "/etc/sitewatch/detector-history.tsv"),
		DetectorBin:     getStr(values, "SITEWATCH_DETECTOR_BIN", "/usr/bin/sitewatch"),
		FlowProbeBin:    getStr(values, "SITEWATCH_FLOW_PROBE_BIN", "/usr/bin/sitewatch-flow-probe"),
		DNSDumpIface:    getStr(values, "SITEWATCH_DNS_DUMP_IFACE", "br-lan"),
		DNSDumpEvents:   getStr(values, "SITEWATCH_DNS_DUMP_EVENTS", "/tmp/sitewatch-dns-dump.tsv"),
		AgentIngestURL:  getStr(values, "SITEWATCH_AGENT_INGEST_URL", ""),
		IngestToken:     getStr(values, "SITEWATCH_INGEST_TOKEN", ""),
		FlowUDPPorts:    parsePortRanges(getStr(values, "SITEWATCH_FLOW_UDP_PORTS", "50000-65535 3478 443")),
		FlowTCPPorts:    parsePortRanges(getStr(values, "SITEWATCH_FLOW_TCP_PORTS", "443 50000-65535")),
		Proxy:           getStr(values, "SITEWATCH_PROXY", "socks5h://127.0.0.1:20170"),
		Batch:           getInt(values, "SITEWATCH_BATCH", 12),
		Workers:         getInt(values, "SITEWATCH_SCAN_WORKERS", 4),
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
		ProbeTarget:     getStr(values, "SITEWATCH_PROBE_TARGET", ""),
		ProbePorts:      parsePorts(getStr(values, "SITEWATCH_PROBE_PORTS", "3478,443,50000,55000,60000,65000")),
		ProbeMode:       getStr(values, "SITEWATCH_PROBE_MODE", "both"),
		ReflectorListen: getStr(values, "SITEWATCH_REFLECTOR_LISTEN", ":8096"),
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

func parsePorts(raw string) []int {
	seen := map[int]bool{}
	var ports []int
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		port, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports
}

func parsePortRanges(raw string) []portRange {
	seen := map[portRange]bool{}
	var ranges []portRange
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || unicode.IsSpace(r) }) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		startRaw, endRaw, hasRange := strings.Cut(part, "-")
		start, err := strconv.Atoi(strings.TrimSpace(startRaw))
		if err != nil || start < 1 || start > 65535 {
			continue
		}
		end := start
		if hasRange {
			end, err = strconv.Atoi(strings.TrimSpace(endRaw))
			if err != nil || end < 1 || end > 65535 {
				continue
			}
		}
		if end < start {
			start, end = end, start
		}
		item := portRange{Start: start, End: end}
		if seen[item] {
			continue
		}
		seen[item] = true
		ranges = append(ranges, item)
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].Start == ranges[j].Start {
			return ranges[i].End < ranges[j].End
		}
		return ranges[i].Start < ranges[j].Start
	})
	return ranges
}

func portInRanges(port int, ranges []portRange) bool {
	for _, item := range ranges {
		if port >= item.Start && port <= item.End {
			return true
		}
	}
	return false
}

type netProbeResult struct {
	Time   int64
	Mode   string
	Target string
	Port   int
	Status string
	RTT    float64
	Detail string
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

	workers := cfg.Workers
	if workers < 1 {
		workers = 1
	}
	if workers > len(domains) {
		workers = len(domains)
	}
	jobs := make(chan seenEntry)
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range jobs {
				mu.Lock()
				writeScanStatus(cfg, "running", now, len(domains), done, item.Domain)
				mu.Unlock()

				result, err := checkURL(cfg, "https://"+item.Domain+"/", false)
				if err == nil {
					mu.Lock()
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
					mu.Unlock()

					if cfg.CheckBaseDomain && (result.Status == "blocked" || result.Status == "slow") {
						base := baseDomain(result.Domain)
						if base != "" && base != result.Domain {
							baseResult, err := checkURL(cfg, "https://"+base+"/", false)
							if err == nil {
								mu.Lock()
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
								mu.Unlock()
							}
						}
					}
				}

				mu.Lock()
				done++
				writeScanStatus(cfg, "running", now, len(domains), done, item.Domain)
				mu.Unlock()
			}
		}()
	}
	for _, item := range domains {
		jobs <- item
	}
	close(jobs)
	wg.Wait()

	if err := writeResults(cfg.Results, results); err != nil {
		writeScanStatus(cfg, "error", now, len(domains), len(domains), "")
		return err
	}
	writeScanStatus(cfg, "done", now, len(domains), len(domains), "")
	return nil
}

func cmdProbe(cfg config, args []string) error {
	mode := cfg.ProbeMode
	target := cfg.ProbeTarget
	ports := append([]int(nil), cfg.ProbePorts...)
	if len(args) > 0 && (args[0] == "udp" || args[0] == "tcp" || args[0] == "both") {
		mode = args[0]
		args = args[1:]
	}
	if len(args) > 0 {
		target = args[0]
	}
	if len(args) > 1 {
		ports = parsePorts(args[1])
	}
	host, portFromTarget, err := splitProbeTarget(target)
	if err != nil {
		return err
	}
	if portFromTarget > 0 {
		ports = []int{portFromTarget}
	}
	if len(ports) == 0 {
		return errors.New("no probe ports configured")
	}
	var results []netProbeResult
	for _, port := range ports {
		if mode == "udp" || mode == "both" {
			results = append(results, probeUDP(cfg, host, port))
		}
		if mode == "tcp" || mode == "both" {
			results = append(results, probeTCP(cfg, host, port))
		}
	}
	if err := appendNetResults(cfg.NetResults, results); err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func splitProbeTarget(target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, errors.New("SITEWATCH_PROBE_TARGET is not configured")
	}
	if host, port, err := net.SplitHostPort(target); err == nil {
		p, _ := strconv.Atoi(port)
		return host, p, nil
	}
	if strings.Count(target, ":") == 0 {
		return target, 0, nil
	}
	return "", 0, fmt.Errorf("invalid probe target %q", target)
}

func probeUDP(cfg config, host string, port int) netProbeResult {
	res := netProbeResult{Time: time.Now().Unix(), Mode: "udp", Target: host, Port: port}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("udp", addr, cfg.Timeout)
	if err != nil {
		res.Status = "connect_failed"
		res.Detail = err.Error()
		return res
	}
	defer conn.Close()
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		copy(token, []byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	}
	start := time.Now()
	if _, err := conn.Write(append([]byte("sitewatch-udp:"), token...)); err != nil {
		res.Status = "send_failed"
		res.Detail = err.Error()
		return res
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfg.Timeout))
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	res.RTT = secondsSince(start)
	if err != nil {
		res.Status = "timeout"
		res.Detail = err.Error()
		return res
	}
	if !strings.HasPrefix(string(buf[:n]), "sitewatch-udp:") {
		res.Status = "mismatch"
		res.Detail = fmt.Sprintf("unexpected reply %d bytes", n)
		return res
	}
	res.Status = "ok"
	res.Detail = fmt.Sprintf("%d bytes", n)
	return res
}

func probeTCP(cfg config, host string, port int) netProbeResult {
	res := netProbeResult{Time: time.Now().Unix(), Mode: "tcp", Target: host, Port: port}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	res.RTT = secondsSince(start)
	if err != nil {
		res.Status = "connect_failed"
		res.Detail = err.Error()
		return res
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	if _, err := conn.Write([]byte("sitewatch-tcp\n")); err != nil {
		res.Status = "send_failed"
		res.Detail = err.Error()
		return res
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		res.Status = "read_failed"
		res.Detail = err.Error()
		return res
	}
	if !strings.HasPrefix(string(buf[:n]), "sitewatch-tcp") {
		res.Status = "mismatch"
		res.Detail = fmt.Sprintf("unexpected reply %d bytes", n)
		return res
	}
	res.Status = "ok"
	res.Detail = fmt.Sprintf("%d bytes", n)
	return res
}

func secondsSince(start time.Time) float64 {
	return float64(time.Since(start).Microseconds()) / 1_000_000
}

func appendNetResults(path string, results []netProbeResult) error {
	if path == "" || len(results) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, r := range results {
		if _, err := fmt.Fprintf(file, "%d\t%s\t%s\t%d\t%s\t%.6f\t%s\n", r.Time, r.Mode, r.Target, r.Port, r.Status, r.RTT, strings.ReplaceAll(r.Detail, "\t", " ")); err != nil {
			return err
		}
	}
	return nil
}

func cmdFlowProbe(cfg config, args []string) error {
	duration := 0
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		duration = parseInt(args[0])
	}
	if duration < 0 {
		duration = 0
	}
	if duration > 300 {
		duration = 300
	}

	start, err := readConntrackSnapshot(cfg)
	if err != nil {
		return appendFlowResults(cfg.FlowResults, []flowEntry{{
			Time:   time.Now().Unix(),
			Mode:   "passive",
			Source: "-",
			Target: "-",
			Port:   "-",
			Status: "not_available",
			Detail: "conntrack is not available",
		}})
	}
	if duration > 0 {
		time.Sleep(time.Duration(duration) * time.Second)
	}
	end := start
	if duration > 0 {
		if snapshot, err := readConntrackSnapshot(cfg); err == nil {
			end = snapshot
		} else {
			end = nil
		}
	}

	rows := diffFlowSnapshots(start, end, duration, time.Now().Unix())
	return appendFlowResults(cfg.FlowResults, rows)
}

func cmdDNSDump(cfg config, args []string) error {
	mode := "stdout"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		mode = strings.TrimSpace(args[0])
	}
	switch mode {
	case "stdout", "local", "ingest":
	default:
		mode = "stdout"
	}
	duration := 0
	if len(args) > 1 && strings.TrimSpace(args[1]) != "" {
		duration = parseInt(args[1])
	}
	if duration < 0 {
		duration = 0
	}
	if duration > 3600 {
		duration = 3600
	}
	tcpdumpPath, err := exec.LookPath("tcpdump")
	if err != nil {
		return errors.New("tcpdump is required")
	}

	ctx := context.Background()
	cancel := func() {}
	if duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(duration)*time.Second)
	}
	defer cancel()

	cmd := exec.CommandContext(ctx, tcpdumpPath, "-l", "-n", "-i", cfg.DNSDumpIface, "(udp port 53 or tcp port 53)")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		event, ok := parseTCPDumpDNSLine(scanner.Text())
		if !ok {
			continue
		}
		if err := emitDNSEvent(cfg, mode, event); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return err
		}
	}
	if err := scanner.Err(); err != nil && ctx.Err() == nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}
	err = cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	return err
}

type dnsDumpEvent struct {
	Source string
	Domain string
	TS     int64
}

func parseTCPDumpDNSLine(line string) (dnsDumpEvent, bool) {
	fields := strings.Fields(line)
	source := ""
	domain := ""
	for i, field := range fields {
		if field == ">" && i > 0 {
			source = stripTCPDumpPort(fields[i-1])
		}
		if strings.HasSuffix(field, "?") && i+1 < len(fields) {
			domain = cleanDNSDomain(fields[i+1])
		}
	}
	if source == "" || domain == "" || !isLANIP(source) || source == "127.0.0.1" || source == "::1" {
		return dnsDumpEvent{}, false
	}
	return dnsDumpEvent{Source: source, Domain: domain, TS: time.Now().Unix()}, true
}

func stripTCPDumpPort(addr string) string {
	addr = strings.TrimRight(addr, ":")
	idx := strings.LastIndex(addr, ".")
	if idx < 0 {
		return addr
	}
	if _, err := strconv.Atoi(addr[idx+1:]); err != nil {
		return addr
	}
	return addr[:idx]
}

func cleanDNSDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(strings.TrimRight(domain, ".")))
	switch {
	case domain == "",
		strings.HasPrefix(domain, "."),
		strings.HasSuffix(domain, ".local"),
		strings.HasSuffix(domain, ".lan"),
		strings.HasSuffix(domain, ".arpa"),
		strings.HasPrefix(domain, "_"),
		!strings.Contains(domain, "."):
		return ""
	}
	for _, r := range domain {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			continue
		}
		return ""
	}
	return domain
}

func emitDNSEvent(cfg config, mode string, event dnsDumpEvent) error {
	switch mode {
	case "local":
		if err := os.MkdirAll(filepath.Dir(cfg.DNSDumpEvents), 0o755); err != nil {
			return err
		}
		file, err := os.OpenFile(cfg.DNSDumpEvents, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = fmt.Fprintf(file, "%s\t%s\n", cleanTSVField(event.Source), cleanTSVField(event.Domain))
		return err
	case "ingest":
		target := normalizeContainerAddr(cfg.AgentIngestURL)
		if target == "" {
			return nil
		}
		values := url.Values{}
		values.Set("action", "ingest")
		values.Set("source", event.Source)
		values.Set("domain", event.Domain)
		values.Set("ts", strconv.FormatInt(event.TS, 10))
		if cfg.IngestToken != "" {
			values.Set("token", cfg.IngestToken)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+"/cgi-bin/sitewatch?"+values.Encode(), nil)
		if err != nil {
			return nil
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil
		}
		_ = resp.Body.Close()
		return nil
	default:
		_, err := fmt.Fprintf(os.Stdout, "%s\t%s\n", event.Source, event.Domain)
		return err
	}
}

func normalizeContainerAddr(value string) string {
	value = strings.Join(strings.Fields(value), "")
	value = strings.TrimPrefix(value, "http://")
	value = strings.TrimPrefix(value, "https://")
	for _, sep := range []string{"/", "?", "#"} {
		if idx := strings.Index(value, sep); idx >= 0 {
			value = value[:idx]
		}
	}
	return value
}

func readConntrackSnapshot(cfg config) ([]conntrackFlow, error) {
	if path, err := exec.LookPath("conntrack"); err == nil {
		output, err := exec.Command(path, "-L").Output()
		if err == nil {
			return parseConntrackLines(cfg, string(output)), nil
		}
	}
	for _, path := range []string{"/proc/net/nf_conntrack", "/proc/net/ip_conntrack"} {
		output, err := os.ReadFile(path)
		if err == nil {
			return parseConntrackLines(cfg, string(output)), nil
		}
	}
	return nil, errors.New("conntrack is not available")
}

func parseConntrackLines(cfg config, raw string) []conntrackFlow {
	var flows []conntrackFlow
	for _, line := range strings.Split(raw, "\n") {
		if flow, ok := parseConntrackLine(cfg, line); ok {
			flows = append(flows, flow)
		}
	}
	return flows
}

func parseConntrackLine(cfg config, line string) (conntrackFlow, bool) {
	fields := strings.Fields(line)
	proto := ""
	for _, field := range fields {
		if field == "udp" || field == "tcp" {
			proto = field
			break
		}
	}
	if proto == "" {
		return conntrackFlow{}, false
	}
	value := func(name string) string {
		prefix := name + "="
		for _, field := range fields {
			if strings.HasPrefix(field, prefix) {
				return strings.TrimPrefix(field, prefix)
			}
		}
		return ""
	}
	source := value("src")
	target := value("dst")
	port := parseInt(value("dport"))
	packets := parseInt(value("packets"))
	bytes := parseInt(value("bytes"))
	if source == "" || target == "" || port < 1 || !isLANIP(source) || isNoiseTarget(target) {
		return conntrackFlow{}, false
	}
	switch proto {
	case "udp":
		if !portInRanges(port, cfg.FlowUDPPorts) {
			return conntrackFlow{}, false
		}
	case "tcp":
		if !portInRanges(port, cfg.FlowTCPPorts) {
			return conntrackFlow{}, false
		}
	}
	return conntrackFlow{
		Proto:   proto,
		Source:  source,
		Target:  target,
		Port:    port,
		Assured: strings.Contains(line, "ASSURED"),
		Packets: packets,
		Bytes:   bytes,
	}, true
}

func isLANIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "fd") || strings.HasPrefix(ip, "fe80:") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) > 1 {
			second := parseInt(parts[1])
			return second >= 16 && second <= 31
		}
	}
	return false
}

func isNoiseTarget(ip string) bool {
	return isLANIP(ip) ||
		strings.HasPrefix(ip, "127.") ||
		strings.HasPrefix(ip, "0.") ||
		strings.HasPrefix(ip, "169.254.") ||
		strings.HasPrefix(ip, "224.") ||
		strings.HasPrefix(ip, "239.") ||
		ip == "255.255.255.255" ||
		strings.HasSuffix(ip, ".255") ||
		strings.HasPrefix(ip, "ff")
}

func diffFlowSnapshots(start []conntrackFlow, end []conntrackFlow, duration int, now int64) []flowEntry {
	startByKey := map[string]conntrackFlow{}
	for _, flow := range start {
		startByKey[flowKey(flow)] = flow
	}
	var rows []flowEntry
	for _, flow := range end {
		base := startByKey[flowKey(flow)]
		deltaPackets := flow.Packets - base.Packets
		deltaBytes := flow.Bytes - base.Bytes
		detail := fmt.Sprintf("delta %ds", duration)
		if duration == 0 {
			deltaPackets = flow.Packets
			deltaBytes = flow.Bytes
			detail = "snapshot"
		}
		if deltaPackets <= 0 && deltaBytes <= 0 {
			continue
		}
		status := "observed"
		if !flow.Assured && deltaPackets > 2 {
			status = "suspect"
			detail += ", no ASSURED state"
		}
		rows = append(rows, flowEntry{
			Time:    now,
			Mode:    "passive-" + flow.Proto,
			Source:  flow.Source,
			Target:  flow.Target,
			Port:    strconv.Itoa(flow.Port),
			Status:  status,
			Packets: deltaPackets,
			Bytes:   deltaBytes,
			Detail:  detail,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Packets == rows[j].Packets {
			return rows[i].Target < rows[j].Target
		}
		return rows[i].Packets > rows[j].Packets
	})
	return rows
}

func flowKey(flow conntrackFlow) string {
	return fmt.Sprintf("%s\t%s\t%s\t%d", flow.Proto, flow.Source, flow.Target, flow.Port)
}

func appendFlowResults(path string, rows []flowEntry) error {
	if path == "" || len(rows) == 0 {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()
	for _, row := range rows {
		if _, err := fmt.Fprintf(file, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n",
			row.Time,
			cleanTSVField(row.Mode),
			cleanTSVField(row.Source),
			cleanTSVField(row.Target),
			cleanTSVField(row.Port),
			cleanTSVField(row.Status),
			row.Packets,
			row.Bytes,
			cleanTSVField(row.Detail),
		); err != nil {
			return err
		}
	}
	return nil
}

func cmdDetector(cfg config, args []string) error {
	run := newDetectorRun(cfg, args)
	return run.run()
}

func newDetectorRun(cfg config, args []string) *detectorRun {
	profile := "quick"
	if len(args) > 0 && args[0] != "" {
		profile = cleanAPIArg(args[0])
	}
	switch profile {
	case "quick", "site", "discord", "full":
	default:
		profile = "quick"
	}
	value := func(index int) string {
		if len(args) > index {
			return cleanAPIArg(args[index])
		}
		return ""
	}
	durationRaw := value(4)
	duration := 45
	if durationRaw != "" {
		duration = parseInt(durationRaw)
	}
	if duration < 0 {
		duration = 45
	}
	if duration > 300 {
		duration = 300
	}
	target := value(2)
	if target == "" {
		target = cfg.ProbeTarget
	}
	ports := parsePorts(value(3))
	if len(ports) == 0 {
		ports = append([]int(nil), cfg.ProbePorts...)
	}
	run := &detectorRun{
		cfg:      cfg,
		runID:    fmt.Sprintf("%d-%d", time.Now().Unix(), os.Getpid()),
		profile:  profile,
		url:      value(1),
		target:   target,
		ports:    ports,
		duration: duration,
		source:   value(5),
		started:  time.Now().Unix(),
	}
	run.total = run.estimateTotal()
	if run.total < 1 {
		run.total = 1
	}
	return run
}

func (d *detectorRun) estimateTotal() int {
	total := 0
	switch d.profile {
	case "quick", "site":
		if d.url != "" {
			total++
		}
	case "discord":
		if d.target != "" {
			total++
		}
		total++
	case "full":
		if d.url != "" {
			total++
		}
		if d.target != "" {
			total++
		}
		total++
	}
	return total
}

func (d *detectorRun) run() error {
	if err := os.MkdirAll(filepath.Dir(d.cfg.DetectorHistory), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.cfg.DetectorStatus), 0o755); err != nil {
		return err
	}
	d.writeStatus("running", "Старт", "")

	switch d.profile {
	case "quick", "site":
		d.runSiteCheck()
		d.done++
	case "discord":
		d.runNetCheck()
		d.done++
		d.runFlowCheck()
		d.done++
	case "full":
		if d.url != "" {
			d.runSiteCheck()
			d.done++
		}
		if d.target != "" {
			d.runNetCheck()
			d.done++
		}
		d.runFlowCheck()
		d.done++
	}

	target := d.url
	if target == "" {
		target = d.target
	}
	if target == "" {
		target = "проверка"
	}
	d.appendHistory("summary", "done", target, "Профиль завершен")
	d.done = d.total
	d.writeStatus("done", "Готово", "Профиль завершен, результаты сохранены в истории")
	return nil
}

func (d *detectorRun) writeStatus(state string, current string, summary string) {
	line := fmt.Sprintf("%s\t%d\t%d\t%d\t%s\t%d\t%s\t%s\n",
		cleanTSVField(state), d.started, d.total, d.done, cleanTSVField(current), time.Now().Unix(), cleanTSVField(d.profile), cleanTSVField(summary))
	_ = os.WriteFile(d.cfg.DetectorStatus, []byte(line), 0o644)
}

func (d *detectorRun) appendHistory(kind string, status string, item string, detail string) {
	_ = os.MkdirAll(filepath.Dir(d.cfg.DetectorHistory), 0o755)
	file, err := os.OpenFile(d.cfg.DetectorHistory, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	fmt.Fprintf(file, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
		cleanTSVField(d.runID), time.Now().Unix(), cleanTSVField(d.profile), cleanTSVField(item), cleanTSVField(kind), cleanTSVField(status), cleanTSVField(detail), cleanTSVField(d.source))
}

func (d *detectorRun) runSiteCheck() {
	if d.url == "" {
		d.appendHistory("error", "error", "-", "URL не задан")
		return
	}
	d.writeStatus("running", "Проверка сайта "+d.url, "")
	result, err := checkURL(d.cfg, d.url, false)
	if err != nil {
		d.appendHistory("site", "error", d.url, err.Error())
		return
	}
	detail := fmt.Sprintf("direct %s/%.6fs; proxy %s/%.6fs; DNS %s; TLS1.3 %s; TLS1.2 %s; HTTP %s",
		result.Direct.Code, result.Direct.Time, result.Proxy.Code, result.Proxy.Time, result.DPI.DNS.Status, result.DPI.TLS13.Status, result.DPI.TLS12.Status, result.DPI.HTTP.Status)
	d.appendHistory("site", result.Status, result.Domain, detail)
}

func (d *detectorRun) runNetCheck() {
	if d.target == "" {
		d.appendHistory("error", "error", "-", "Цель UDP/TCP не задана")
		return
	}
	host, portFromTarget, err := splitProbeTarget(d.target)
	if err != nil {
		d.appendHistory("net", "error", d.target, err.Error())
		return
	}
	ports := append([]int(nil), d.ports...)
	if portFromTarget > 0 {
		ports = []int{portFromTarget}
	}
	if len(ports) == 0 {
		d.appendHistory("net", "error", d.target, "Порты не заданы")
		return
	}
	d.writeStatus("running", "Активная UDP/TCP проверка "+host, "")
	var results []netProbeResult
	for _, port := range ports {
		results = append(results, probeUDP(d.cfg, host, port))
		results = append(results, probeTCP(d.cfg, host, port))
	}
	_ = appendNetResults(d.cfg.NetResults, results)
	for _, result := range results {
		detail := fmt.Sprintf("%s; rtt %.6fs; %s", result.Mode, result.RTT, result.Detail)
		d.appendHistory("net", result.Status, fmt.Sprintf("%s:%d", result.Target, result.Port), detail)
	}
}

func (d *detectorRun) runFlowCheck() {
	d.writeStatus("running", fmt.Sprintf("Пассивное наблюдение conntrack %d с", d.duration), "")
	mark := time.Now().Unix()
	_ = cmdFlowProbe(d.cfg, []string{strconv.Itoa(d.duration)})
	rows, err := readFlowEntries(d.cfg.FlowResults, d.source, 0)
	if err != nil {
		d.appendHistory("flow", "error", "-", err.Error())
		return
	}
	count := 0
	for _, row := range rows {
		if row.Time < mark {
			continue
		}
		detail := fmt.Sprintf("%s; %s; packets %d; bytes %d; %s", row.Mode, row.Source, row.Packets, row.Bytes, row.Detail)
		d.appendHistory("flow", row.Status, row.Target+":"+row.Port, detail)
		count++
		if count >= 18 {
			break
		}
	}
	if count == 0 {
		d.appendHistory("flow", "observed", "-", "Новых flow за окно не найдено")
	}
}

func cmdReflector(cfg config, args []string) error {
	listen := cfg.ReflectorListen
	if len(args) > 0 && args[0] != "" {
		listen = args[0]
	}
	errCh := make(chan error, 2)
	go func() { errCh <- serveUDPReflector(listen) }()
	go func() { errCh <- serveTCPReflector(listen) }()
	return <-errCh
}

func cmdServe(cfg config, args []string) error {
	listen := ":8095"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		listen = args[0]
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		source := strings.TrimSpace(r.URL.Query().Get("source"))
		status, err := buildAPIStatus(cfg, source)
		writeJSON(w, status, err)
	})
	mux.HandleFunc("/api/domains", func(w http.ResponseWriter, r *http.Request) {
		source := strings.TrimSpace(r.URL.Query().Get("source"))
		rows, err := buildDomainRows(cfg, source, 250)
		writeJSON(w, rows, err)
	})
	mux.HandleFunc("/api/network", func(w http.ResponseWriter, r *http.Request) {
		source := strings.TrimSpace(r.URL.Query().Get("source"))
		rows, err := readFlowEntries(cfg.FlowResults, source, 250)
		writeJSON(w, rows, err)
	})
	mux.HandleFunc("/api/detector/status", func(w http.ResponseWriter, r *http.Request) {
		raw, err := readSmallFile(cfg.DetectorStatus)
		writeJSON(w, map[string]string{"raw": raw}, err)
	})
	mux.HandleFunc("/api/detector/history", func(w http.ResponseWriter, r *http.Request) {
		rows, err := readDetectorHistory(cfg.DetectorHistory, 100)
		writeJSON(w, rows, err)
	})
	mux.HandleFunc("/api/detector/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			writeJSON(w, nil, err)
			return
		}
		args := []string{
			cleanAPIArg(r.Form.Get("profile")),
			cleanAPIArg(r.Form.Get("url")),
			cleanAPIArg(r.Form.Get("target")),
			cleanAPIArg(r.Form.Get("ports")),
			cleanAPIArg(r.Form.Get("duration")),
			cleanAPIArg(r.Form.Get("source")),
		}
		if args[0] == "" {
			args[0] = "quick"
		}
		cmdArgs := detectorCommandArgs(cfg, args)
		cmd := exec.Command(cfg.DetectorBin, cmdArgs...)
		if err := cmd.Start(); err != nil {
			writeJSON(w, nil, err)
			return
		}
		pid := cmd.Process.Pid
		_ = cmd.Process.Release()
		writeJSON(w, map[string]any{"started": true, "pid": pid}, nil)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		writeMetrics(w, cfg)
	})
	server := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server.ListenAndServe()
}

func detectorCommandArgs(cfg config, args []string) []string {
	if filepath.Base(cfg.DetectorBin) == "sitewatch-detector" {
		return args
	}
	return append([]string{"detector"}, args...)
}

func serveUDPReflector(listen string) error {
	addr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		_, _ = conn.WriteToUDP(buf[:n], remote)
	}
}

func serveTCPReflector(listen string) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(15 * time.Second))
			buf := make([]byte, 1500)
			n, err := c.Read(buf)
			if err == nil && n > 0 {
				_, _ = c.Write(buf[:n])
			}
		}(conn)
	}
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

func buildAPIStatus(cfg config, source string) (apiStatus, error) {
	seen, err := readSeen(cfg.Queue)
	if err != nil {
		return apiStatus{}, err
	}
	results, err := readResults(cfg.Results)
	if err != nil {
		return apiStatus{}, err
	}
	proxy, err := readProxyDomains(cfg.ProxyOut)
	if err != nil {
		return apiStatus{}, err
	}
	status := apiStatus{
		Capture:  mustReadSmallFile(cfg.CaptureStatus),
		Scan:     mustReadSmallFile(cfg.ScanStatus),
		Detector: mustReadSmallFile(cfg.DetectorStatus),
		Proxy:    len(proxy),
	}
	resultByDomain := map[string]bool{}
	for _, item := range results {
		if source == "" || item.Source == source {
			status.Results++
			resultByDomain[item.Domain] = true
		}
	}
	pendingSeen := map[string]bool{}
	for _, item := range seen {
		if source != "" && item.Source != source {
			continue
		}
		status.Seen++
		if !resultByDomain[item.Domain] && !pendingSeen[item.Domain] {
			pendingSeen[item.Domain] = true
			status.Pending++
		}
	}
	return status, nil
}

func buildDomainRows(cfg config, source string, limit int) ([]apiDomainRow, error) {
	seen, err := readSeen(cfg.Queue)
	if err != nil {
		return nil, err
	}
	results, err := readResults(cfg.Results)
	if err != nil {
		return nil, err
	}
	queries := map[string]int{}
	sourceByDomain := map[string]string{}
	bestCountByDomain := map[string]int{}
	for _, item := range seen {
		if source != "" && item.Source != source {
			continue
		}
		queries[item.Domain] += item.Count
		if item.Count > bestCountByDomain[item.Domain] {
			sourceByDomain[item.Domain] = item.Source
			bestCountByDomain[item.Domain] = item.Count
		}
	}
	rows := make([]apiDomainRow, 0, len(queries)+len(results))
	done := map[string]bool{}
	for _, result := range results {
		if source != "" && result.Source != source {
			continue
		}
		rows = append(rows, apiDomainRow{
			Status:     result.Status,
			Domain:     result.Domain,
			Source:     result.Source,
			Queries:    result.Count,
			DirectCode: result.DirectCode,
			DirectTime: result.DirectTime,
			ProxyCode:  result.ProxyCode,
			ProxyTime:  result.ProxyTime,
			DPI:        result.DPIStatus,
			Scanned:    result.Scanned,
		})
		done[result.Domain] = true
	}
	for domain, count := range queries {
		if done[domain] {
			continue
		}
		rows = append(rows, apiDomainRow{
			Status:  "unchecked",
			Domain:  domain,
			Source:  sourceByDomain[domain],
			Queries: count,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Status == rows[j].Status {
			if rows[i].Queries == rows[j].Queries {
				return rows[i].Domain < rows[j].Domain
			}
			return rows[i].Queries > rows[j].Queries
		}
		return rows[i].Status < rows[j].Status
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func readFlowEntries(path string, source string, limit int) ([]flowEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()
	var rows []flowEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 9 || (source != "" && parts[2] != source) {
			continue
		}
		rows = append(rows, flowEntry{
			Time:    parseInt64(parts[0]),
			Mode:    parts[1],
			Source:  parts[2],
			Target:  parts[3],
			Port:    parts[4],
			Status:  parts[5],
			Packets: parseInt(parts[6]),
			Bytes:   parseInt(parts[7]),
			Detail:  parts[8],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Time > rows[j].Time })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
}

func readDetectorHistory(path string, limit int) ([]detectorHistoryEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()
	var rows []detectorHistoryEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) < 8 {
			continue
		}
		rows = append(rows, detectorHistoryEntry{
			RunID:   parts[0],
			Time:    parseInt64(parts[1]),
			Profile: parts[2],
			Target:  parts[3],
			Kind:    parts[4],
			Status:  parts[5],
			Detail:  parts[6],
			Source:  parts[7],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Time > rows[j].Time })
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}
	return rows, nil
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

func readSmallFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func mustReadSmallFile(path string) string {
	out, _ := readSmallFile(path)
	return out
}

func writeJSON(w http.ResponseWriter, value any, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(value)
}

func cleanAPIArg(raw string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\r', '\n':
			return -1
		default:
			return r
		}
	}, strings.TrimSpace(raw))
}

func cleanTSVField(raw string) string {
	raw = strings.Map(func(r rune) rune {
		switch r {
		case '\t', '\r', '\n':
			return ' '
		default:
			return r
		}
	}, strings.TrimSpace(raw))
	return strings.Join(strings.Fields(raw), " ")
}

func writeMetrics(w http.ResponseWriter, cfg config) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	status, err := buildAPIStatus(cfg, "")
	if err != nil {
		fmt.Fprintf(w, "# sitewatch metrics error: %s\n", promEscape(err.Error()))
		return
	}
	fmt.Fprintln(w, "# HELP sitewatch_seen_pairs_total Observed source/domain pairs.")
	fmt.Fprintln(w, "# TYPE sitewatch_seen_pairs_total gauge")
	fmt.Fprintf(w, "sitewatch_seen_pairs_total %d\n", status.Seen)
	fmt.Fprintln(w, "# HELP sitewatch_results_count Scan result rows.")
	fmt.Fprintln(w, "# TYPE sitewatch_results_count gauge")
	fmt.Fprintf(w, "sitewatch_results_count %d\n", status.Results)
	fmt.Fprintln(w, "# HELP sitewatch_pending_domains Domains waiting for scan.")
	fmt.Fprintln(w, "# TYPE sitewatch_pending_domains gauge")
	fmt.Fprintf(w, "sitewatch_pending_domains %d\n", status.Pending)
	fmt.Fprintln(w, "# HELP sitewatch_proxy_domains Domains in VPN export list.")
	fmt.Fprintln(w, "# TYPE sitewatch_proxy_domains gauge")
	fmt.Fprintf(w, "sitewatch_proxy_domains %d\n", status.Proxy)
	fmt.Fprintln(w, "# HELP sitewatch_component_status Raw status line by component.")
	fmt.Fprintln(w, "# TYPE sitewatch_component_status gauge")
	fmt.Fprintf(w, "sitewatch_component_status{component=\"capture\",raw=\"%s\"} 1\n", promEscape(status.Capture))
	fmt.Fprintf(w, "sitewatch_component_status{component=\"scan\",raw=\"%s\"} 1\n", promEscape(status.Scan))
	fmt.Fprintf(w, "sitewatch_component_status{component=\"detector\",raw=\"%s\"} 1\n", promEscape(status.Detector))
	fmt.Fprintln(w, "# HELP sitewatch_last_scrape_timestamp_seconds SiteWatch metrics render time.")
	fmt.Fprintln(w, "# TYPE sitewatch_last_scrape_timestamp_seconds gauge")
	fmt.Fprintf(w, "sitewatch_last_scrape_timestamp_seconds %d\n", time.Now().Unix())
}

func promEscape(raw string) string {
	raw = strings.ReplaceAll(raw, `\`, `\\`)
	raw = strings.ReplaceAll(raw, `"`, `\"`)
	raw = strings.ReplaceAll(raw, "\n", " ")
	raw = strings.ReplaceAll(raw, "\t", " ")
	return raw
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
