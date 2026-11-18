package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSIEMSinks_FormatAndWebhookBatch(t *testing.T) {
	q := Query{
		Time:       time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC),
		Domain:     "example.org",
		Type:       "A",
		Status:     StatusAllowed,
		ClientIP:   "192.168.1.20",
		DurationMs: 1.25,
	}

	line := formatRFC5424Syslog(q)
	if !strings.HasPrefix(line, "<14>1 2026-11-18T10:00:00Z shielddns dns-query") || !strings.Contains(line, `"domain":"example.org"`) {
		t.Fatalf("unexpected RFC5424 syslog format: %s", line)
	}

	var gotAuth string
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	sendWebhookSink(srv.URL, "secret-token", []Query{q})
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("expected Bearer secret-token, got %q", gotAuth)
	}
	if !strings.Contains(gotBody, `"domain":"example.org"`) {
		t.Fatalf("expected NDJSON body containing domain, got %q", gotBody)
	}
}
