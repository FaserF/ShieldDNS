package main

import (
	"testing"
	"time"
)

func TestResolveUpstreamTarget_IPLiteral(t *testing.T) {
	got := resolveUpstreamTarget("35.186.224.24:443", "89.168.74.120", 2*time.Second)
	if got != "35.186.224.24:443" {
		t.Fatalf("expected IP literal unchanged, got %q", got)
	}
}

func TestResolveUpstreamTarget_InvalidAddr(t *testing.T) {
	got := resolveUpstreamTarget("not-a-host-port", "89.168.74.120", 2*time.Second)
	if got != "not-a-host-port" {
		t.Fatalf("expected invalid addr unchanged, got %q", got)
	}
}
