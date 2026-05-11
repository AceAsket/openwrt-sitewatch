package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeURLCleansManualInput(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantURL    string
		wantDomain string
	}{
		{
			name:       "spaces and trailing comma",
			input:      "  https://youmagine.com/,  ",
			wantURL:    "https://youmagine.com/",
			wantDomain: "youmagine.com",
		},
		{
			name:       "quoted domain",
			input:      `"shikimori.org"`,
			wantURL:    "https://shikimori.org",
			wantDomain: "shikimori.org",
		},
		{
			name:       "unicode spaces",
			input:      "\u00a0https://youmagine.com/\u00a0",
			wantURL:    "https://youmagine.com/",
			wantDomain: "youmagine.com",
		},
		{
			name:       "v2raya domain rule",
			input:      "domain(domain: yummyani.me) -> proxy",
			wantURL:    "https://yummyani.me",
			wantDomain: "yummyani.me",
		},
		{
			name:       "angle wrapped url",
			input:      "<https://static2.mangapoisk.io/>",
			wantURL:    "https://static2.mangapoisk.io/",
			wantDomain: "static2.mangapoisk.io",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURL, gotDomain, err := normalizeURL(tt.input)
			if err != nil {
				t.Fatalf("normalizeURL() error = %v", err)
			}
			if gotURL != tt.wantURL || gotDomain != tt.wantDomain {
				t.Fatalf("normalizeURL() = (%q, %q), want (%q, %q)", gotURL, gotDomain, tt.wantURL, tt.wantDomain)
			}
		})
	}
}

func TestBuildAPIStatusAndDomainRows(t *testing.T) {
	dir := t.TempDir()
	queue := filepath.Join(dir, "queue.tsv")
	results := filepath.Join(dir, "results.tsv")
	proxy := filepath.Join(dir, "proxy.txt")
	if err := os.WriteFile(queue, []byte(
		"192.168.50.80\tyoumagine.com\t1\t2\t3\n"+
			"192.168.50.81\tunchecked.example\t1\t2\t4\n",
	), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(results, []byte("youmagine.com\t192.168.50.80\t3\tslow\t200\t6.0\t200\t0.6\t1778505297\tok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(proxy, []byte("domain:youmagine.com\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := config{Queue: queue, Results: results, ProxyOut: proxy}
	status, err := buildAPIStatus(cfg, "")
	if err != nil {
		t.Fatalf("buildAPIStatus() error = %v", err)
	}
	if status.Seen != 2 || status.Results != 1 || status.Pending != 1 || status.Proxy != 1 {
		t.Fatalf("status = %+v", status)
	}

	rows, err := buildDomainRows(cfg, "", 0)
	if err != nil {
		t.Fatalf("buildDomainRows() error = %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("len(rows) = %d, want 2", len(rows))
	}
	foundUnchecked := false
	for _, row := range rows {
		if row.Domain == "unchecked.example" && row.Status == "unchecked" && row.Queries == 4 {
			foundUnchecked = true
		}
	}
	if !foundUnchecked {
		t.Fatalf("unchecked row not found in %+v", rows)
	}
}

func TestReadFlowEntriesAndDetectorHistory(t *testing.T) {
	dir := t.TempDir()
	flow := filepath.Join(dir, "flow.tsv")
	history := filepath.Join(dir, "detector.tsv")
	if err := os.WriteFile(flow, []byte("1778505297\tpassive-udp\t192.168.50.80\t1.2.3.4\t50000\tsuspect\t5\t600\tdelta 45s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(history, []byte("run1\t1778505297\tsite\tyoumagine.com\tsite\tslow\tdetail\t192.168.50.80\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	flows, err := readFlowEntries(flow, "192.168.50.80", 10)
	if err != nil {
		t.Fatalf("readFlowEntries() error = %v", err)
	}
	if len(flows) != 1 || flows[0].Status != "suspect" || flows[0].Packets != 5 {
		t.Fatalf("flows = %+v", flows)
	}

	entries, err := readDetectorHistory(history, 10)
	if err != nil {
		t.Fatalf("readDetectorHistory() error = %v", err)
	}
	if len(entries) != 1 || entries[0].Profile != "site" || entries[0].Status != "slow" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestParsePortRanges(t *testing.T) {
	got := parsePortRanges("50000-65535 3478,443 443 bad 70000")
	if len(got) != 3 {
		t.Fatalf("len(ranges) = %d, want 3: %+v", len(got), got)
	}
	if !portInRanges(55000, got) || !portInRanges(3478, got) || portInRanges(80, got) {
		t.Fatalf("unexpected range matching: %+v", got)
	}
}

func TestParseConntrackLineAndDiff(t *testing.T) {
	cfg := config{
		FlowUDPPorts: parsePortRanges("50000-65535 3478 443"),
		FlowTCPPorts: parsePortRanges("443 50000-65535"),
	}
	line := "ipv4 2 udp 17 29 src=192.168.50.80 dst=1.2.3.4 sport=51000 dport=55000 packets=5 bytes=600 [UNREPLIED] src=1.2.3.4 dst=192.168.50.80 sport=55000 dport=51000 packets=0 bytes=0 mark=0 use=1"
	flow, ok := parseConntrackLine(cfg, line)
	if !ok {
		t.Fatalf("parseConntrackLine() rejected sample")
	}
	if flow.Proto != "udp" || flow.Source != "192.168.50.80" || flow.Target != "1.2.3.4" || flow.Port != 55000 || flow.Assured {
		t.Fatalf("flow = %+v", flow)
	}
	rows := diffFlowSnapshots(nil, []conntrackFlow{flow}, 0, 1778505297)
	if len(rows) != 1 {
		t.Fatalf("len(rows) = %d, want 1: %+v", len(rows), rows)
	}
	if rows[0].Status != "suspect" || rows[0].Packets != 5 || !strings.Contains(rows[0].Detail, "no ASSURED") {
		t.Fatalf("row = %+v", rows[0])
	}
}

func TestParseTCPDumpDNSLine(t *testing.T) {
	line := "16:03:12.123456 IP 192.168.50.80.54839 > 8.8.8.8.53: 12345+ A? YouMagine.COM. (29)"
	event, ok := parseTCPDumpDNSLine(line)
	if !ok {
		t.Fatalf("parseTCPDumpDNSLine() rejected sample")
	}
	if event.Source != "192.168.50.80" || event.Domain != "youmagine.com" {
		t.Fatalf("event = %+v", event)
	}
}

func TestParseTCPDumpDNSLineRejectsNoise(t *testing.T) {
	tests := []string{
		"16:03:12 IP 127.0.0.1.12345 > 8.8.8.8.53: 1+ A? example.com. (29)",
		"16:03:12 IP 192.168.50.80.12345 > 8.8.8.8.53: 1+ PTR? 1.168.192.in-addr.arpa. (29)",
		"16:03:12 IP 1.2.3.4.12345 > 8.8.8.8.53: 1+ A? example.com. (29)",
	}
	for _, tt := range tests {
		if event, ok := parseTCPDumpDNSLine(tt); ok {
			t.Fatalf("parseTCPDumpDNSLine(%q) = %+v, want reject", tt, event)
		}
	}
}

func TestNormalizeContainerAddr(t *testing.T) {
	got := normalizeContainerAddr(" https://192.168.50.50:8095/cgi-bin/sitewatch?action=x ")
	if got != "192.168.50.50:8095" {
		t.Fatalf("normalizeContainerAddr() = %q", got)
	}
}

func TestDetectorCommandArgsSupportsWrapper(t *testing.T) {
	args := []string{"quick"}
	if got := detectorCommandArgs(config{DetectorBin: "/usr/bin/sitewatch"}, args); len(got) != 2 || got[0] != "detector" {
		t.Fatalf("native args = %+v", got)
	}
	if got := detectorCommandArgs(config{DetectorBin: "/usr/bin/sitewatch-detector"}, args); len(got) != 1 || got[0] != "quick" {
		t.Fatalf("wrapper args = %+v", got)
	}
}

func TestDetectorMissingURLWritesHistory(t *testing.T) {
	dir := t.TempDir()
	cfg := config{
		DetectorStatus:  filepath.Join(dir, "status.tsv"),
		DetectorHistory: filepath.Join(dir, "history.tsv"),
		ProxyOut:        filepath.Join(dir, "proxy.txt"),
		NetResults:      filepath.Join(dir, "net.tsv"),
		FlowResults:     filepath.Join(dir, "flow.tsv"),
	}
	run := newDetectorRun(cfg, []string{"site"})
	if err := run.run(); err != nil {
		t.Fatalf("run detector: %v", err)
	}
	status, err := readSmallFile(cfg.DetectorStatus)
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	if !strings.Contains(status, "done") {
		t.Fatalf("status = %q, want done", status)
	}
	entries, err := readDetectorHistory(cfg.DetectorHistory, 10)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("len(entries) = %d, want 2: %+v", len(entries), entries)
	}
	foundError := false
	for _, entry := range entries {
		if entry.Kind == "error" && entry.Status == "error" {
			foundError = true
		}
	}
	if !foundError {
		t.Fatalf("error history entry not found: %+v", entries)
	}
}

func TestCleanTSVField(t *testing.T) {
	got := cleanTSVField(" a\tb\n c  ")
	if got != "a b c" {
		t.Fatalf("cleanTSVField() = %q", got)
	}
}
