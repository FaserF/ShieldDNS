package main

import (
	"testing"
)

func TestAuditLog_HashChainAndTamperDetection(t *testing.T) {
	auditLock.Lock()
	origMem := auditMemLog
	origDB := db
	auditMemLog = nil
	db = nil
	auditLock.Unlock()
	defer func() {
		auditLock.Lock()
		auditMemLog = origMem
		db = origDB
		auditLock.Unlock()
	}()

	RecordAuditEventExplicit("admin", "192.168.1.5", "login", "session", "MFA verified")
	RecordAuditEventExplicit("admin", "192.168.1.5", "rule.add", "ads.example.com", "blocked")
	RecordAuditEventExplicit("api_key", "10.0.0.2", "cluster.maintenance", "enabled", "patching")

	valid, count, errMsg := VerifyAuditChain()
	if !valid || count != 3 || errMsg != "" {
		t.Fatalf("expected valid audit chain of 3, got valid=%v count=%d err=%q", valid, count, errMsg)
	}

	// Tamper with middle entry
	auditLock.Lock()
	auditMemLog[1].Target = "tampered.example.com"
	auditLock.Unlock()

	valid, _, errMsg = VerifyAuditChain()
	if valid || errMsg == "" {
		t.Fatalf("expected tampered audit chain to fail verification")
	}
}
