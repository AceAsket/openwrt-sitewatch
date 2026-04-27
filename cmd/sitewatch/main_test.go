package main

import "testing"

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
