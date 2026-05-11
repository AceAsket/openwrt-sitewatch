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
