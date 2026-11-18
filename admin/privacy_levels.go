package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
)

var (
	privacyKeyOnce sync.Once
	privacyKey     []byte
)

func getPrivacyKey() []byte {
	privacyKeyOnce.Do(func() {
		keyPath := filepath.Join(DataDir, "privacy.key")
		if b, err := os.ReadFile(keyPath); err == nil && len(b) == 32 {
			privacyKey = b
			return
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err == nil {
			_ = os.MkdirAll(DataDir, 0o700)
			_ = os.WriteFile(keyPath, b, 0o600)
			privacyKey = b
		}
	})
	return privacyKey
}

// HashDomainForPrivacy returns a keyed HMAC-SHA256 prefix for PrivacyLevel 1.
func HashDomainForPrivacy(domain string) string {
	key := getPrivacyKey()
	if len(key) == 0 {
		return "hashed.invalid"
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(domain))
	sum := mac.Sum(nil)
	return "h-" + hex.EncodeToString(sum[:8]) + ".redacted"
}

// ApplyPrivacyLevel redacts a Query in-place according to PrivacyLevel (0..3).
// Returns false if the query should NOT be persisted to the query log (level 3 = counters only).
func ApplyPrivacyLevel(q *Query, level int, rawClientIP string) bool {
	if q == nil {
		return false
	}
	switch level {
	case 0:
		return true
	case 1:
		q.ClientIP = AnonymizeIP(rawClientIP)
		q.ClientAlias = ""
		q.Domain = HashDomainForPrivacy(q.Domain)
		return true
	case 2:
		q.ClientIP = "redacted"
		q.ClientAlias = ""
		q.Domain = "redacted"
		return true
	case 3:
		return false
	default:
		return true
	}
}
