package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestMFAMultiMethod(t *testing.T) {
	// 1. Setup minimal environment
	configLock.Lock()
	config = Config{
		AdminPasswordHashed: "dummy",
		SetupDone:           true,
	}
	configLock.Unlock()

	// Mock session
	sessionToken := "test-session-token"
	sessionStore.Store(sessionToken, Session{
		CreatedAt:   time.Now(),
		MFAVerified: false,
	})

	// Helper to create request with cookie
	createReq := func(method, path string, body interface{}) *http.Request {
		var buf bytes.Buffer
		if body != nil {
			json.NewEncoder(&buf).Encode(body)
		}
		req := httptest.NewRequest(method, path, &buf)
		req.AddCookie(&http.Cookie{Name: CookieName, Value: sessionToken})
		return req
	}

	// 2. Test TOTP Setup
	t.Run("TOTP Setup", func(t *testing.T) {
		req := createReq("POST", "/api/mfa/totp/setup", nil)
		rr := httptest.NewRecorder()
		handleTOTPSetup(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Setup failed: %v", rr.Body.String())
		}

		var res map[string]string
		json.Unmarshal(rr.Body.Bytes(), &res)
		if res["secret"] == "" || res["qr"] == "" {
			t.Errorf("Incomplete setup response: %v", res)
		}
	})

	// 3. Test TOTP Verify (Success)
	var secret1 string
	t.Run("TOTP Verify Success", func(t *testing.T) {
		// Generate a fresh secret
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "ShieldDNS",
			AccountName: "admin",
		})
		secret1 = key.Secret()

		code, _ := totp.GenerateCode(secret1, time.Now())

		body := map[string]string{
			"code":   code,
			"secret": secret1,
			"name":   "My Phone",
		}
		req := createReq("POST", "/api/mfa/totp/verify", body)
		rr := httptest.NewRecorder()
		handleTOTPVerify(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Verify failed: %v", rr.Body.String())
		}

		configLock.RLock()
		if len(config.TOTPConfigs) != 1 || config.TOTPConfigs[0].Name != "My Phone" {
			t.Errorf("TOTP config not saved correctly: %v", config.TOTPConfigs)
		}
		configLock.RUnlock()
	})

	// 4. Test adding a second TOTP method
	t.Run("Add Second TOTP", func(t *testing.T) {
		key, _ := totp.Generate(totp.GenerateOpts{
			Issuer:      "ShieldDNS",
			AccountName: "admin",
		})
		secret2 := key.Secret()
		code, _ := totp.GenerateCode(secret2, time.Now())

		body := map[string]string{
			"code":   code,
			"secret": secret2,
			"name":   "Backup App",
		}
		req := createReq("POST", "/api/mfa/totp/verify", body)
		rr := httptest.NewRecorder()
		handleTOTPVerify(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Second verify failed: %v", rr.Body.String())
		}

		configLock.RLock()
		if len(config.TOTPConfigs) != 2 {
			t.Errorf("Should have 2 TOTP configs, got %d", len(config.TOTPConfigs))
		}
		configLock.RUnlock()
	})

	// 5. Test MFA Challenge (Verify against first secret)
	t.Run("MFA Challenge Success", func(t *testing.T) {
		code, _ := totp.GenerateCode(secret1, time.Now())
		body := map[string]string{"code": code}
		req := createReq("POST", "/api/mfa/challenge", body)
		rr := httptest.NewRecorder()
		handleMFAChallenge(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Challenge failed: %v", rr.Body.String())
		}

		// Check session status
		val, _ := sessionStore.Load(sessionToken)
		sess := val.(Session)
		if !sess.MFAVerified {
			t.Error("Session should be MFA verified")
		}
	})

	// 6. Test Deletion
	t.Run("Delete MFA Method", func(t *testing.T) {
		configLock.RLock()
		idToDelete := config.TOTPConfigs[0].ID
		configLock.RUnlock()

		body := map[string]string{
			"type": "totp",
			"id":   idToDelete,
		}
		req := createReq("POST", "/api/mfa/delete", body)
		rr := httptest.NewRecorder()
		handleMFADelete(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Delete failed: %v", rr.Body.String())
		}

		configLock.RLock()
		if len(config.TOTPConfigs) != 1 {
			t.Errorf("Should have 1 TOTP config left, got %d", len(config.TOTPConfigs))
		}
		configLock.RUnlock()
	})

	// 7. Test Disable All
	t.Run("Disable All MFA", func(t *testing.T) {
		req := createReq("POST", "/api/mfa/disable", nil)
		rr := httptest.NewRecorder()
		handleMFADisable(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Disable failed: %v", rr.Body.String())
		}

		configLock.RLock()
		if config.MFAEnabled || len(config.TOTPConfigs) != 0 {
			t.Error("MFA should be fully disabled and cleared")
		}
		configLock.RUnlock()
	})
}

func TestWebAuthnSmoke(t *testing.T) {
	configLock.Lock()
	config = Config{AdminDomain: "localhost"}
	configLock.Unlock()

	sessionToken := "wa-session"
	sessionStore.Store(sessionToken, Session{CreatedAt: time.Now()})

	t.Run("WebAuthn Register Start", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/mfa/webauthn/register/start", nil)
		req.AddCookie(&http.Cookie{Name: CookieName, Value: sessionToken})
		rr := httptest.NewRecorder()

		handleWebAuthnRegisterStart(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("WA Start failed: %v", rr.Body.String())
		}
	})
}
