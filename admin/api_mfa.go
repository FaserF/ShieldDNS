package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

var (
	// Temporary store for registration secrets until they are verified
	pendingTOTPSecrets sync.Map // sessionToken -> secret
)

func handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	configLock.RLock()
	if config.ClusterRole == "replica" {
		configLock.RUnlock()
		http.Error(w, "Forbidden: Multi-Factor Authentication is managed centrally on the Primary node", http.StatusForbidden)
		return
	}
	configLock.RUnlock()

	// 1. Authenticate (Session must be valid)
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if _, found := sessionStore.Load(cookie.Value); !found {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 2. Generate new TOTP Secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "ShieldDNS",
		AccountName: "admin",
	})
	if err != nil {
		http.Error(w, "Failed to generate TOTP secret", http.StatusInternalServerError)
		return
	}

	secret := key.Secret()
	pendingTOTPSecrets.Store(cookie.Value, secret)

	// 3. Generate QR Code as PNG
	qr, err := qrcode.Encode(key.URL(), qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"secret": secret,
		"qr":     fmt.Sprintf("data:image/png;base64,%s", base64.StdEncoding.EncodeToString(qr)),
	})
}

func handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Code   string `json:"code"`
		Secret string `json:"secret"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Retrieve the server-stored pending secret for this session
	val, ok := pendingTOTPSecrets.Load(cookie.Value)
	if !ok {
		http.Error(w, "TOTP setup session not found or expired", http.StatusBadRequest)
		return
	}
	serverSecret := val.(string)

	// Verify the code against the SERVER secret
	valid := totp.Validate(req.Code, serverSecret)
	if !valid {
		http.Error(w, "Invalid TOTP code", http.StatusUnauthorized)
		return
	}

	// Code is valid! Add to config
	configLock.Lock()
	if req.Name == "" {
		req.Name = fmt.Sprintf("Authenticator %s", time.Now().Format("2006-01-02"))
	}
	config.TOTPConfigs = append(config.TOTPConfigs, TOTPConfig{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Secret:    serverSecret, // Persist the server secret
		CreatedAt: time.Now(),
	})
	config.MFAEnabled = true
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleTOTPVerify", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		configLock.Unlock()
		return
	}
	configLock.Unlock()

	// Also mark current session as MFA verified
	if val, found := sessionStore.Load(cookie.Value); found {
		sess := val.(Session)
		sess.MFAVerified = true
		sessionStore.Store(cookie.Value, sess)
	}

	pendingTOTPSecrets.Delete(cookie.Value)

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"success"}`)
}

func handleMFADelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Type string `json:"type"` // "totp" or "webauthn"
		ID   string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	if config.ClusterRole == "replica" {
		http.Error(w, "Forbidden: Multi-Factor Authentication is managed centrally on the Primary node", http.StatusForbidden)
		return
	}

	if req.Type == "totp" {
		var newTOTP []TOTPConfig
		for _, c := range config.TOTPConfigs {
			if c.ID != req.ID {
				newTOTP = append(newTOTP, c)
			}
		}
		config.TOTPConfigs = newTOTP
	} else if req.Type == "webauthn" {
		var newWA []WebAuthnCredential
		for _, c := range config.WebAuthnCredentials {
			// WebAuthn ID is []byte, so we compare base64
			if base64.StdEncoding.EncodeToString(c.ID) != req.ID {
				newWA = append(newWA, c)
			}
		}
		config.WebAuthnCredentials = newWA
	}

	// If no methods left, disable MFA
	if len(config.TOTPConfigs) == 0 && len(config.WebAuthnCredentials) == 0 {
		config.MFAEnabled = false
	}

	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleMFADelete", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"deleted"}`)
}

func handleMFADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	configLock.Lock()
	defer configLock.Unlock()

	if config.ClusterRole == "replica" {
		http.Error(w, "Forbidden: Multi-Factor Authentication is managed centrally on the Primary node", http.StatusForbidden)
		return
	}
	config.MFAEnabled = false
	config.TOTPConfigs = nil
	config.WebAuthnCredentials = nil
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleMFADisable", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"disabled"}`)
}

func handleMFAChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	val, found := sessionStore.Load(cookie.Value)
	if !found {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	sess := val.(Session)

	configLock.RLock()
	totps := config.TOTPConfigs
	enabled := config.MFAEnabled
	configLock.RUnlock()

	if !enabled {
		sess.MFAVerified = true
		sessionStore.Store(cookie.Value, sess)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Verify against any registered TOTP
	verified := false
	for _, c := range totps {
		if totp.Validate(req.Code, c.Secret) {
			verified = true
			break
		}
	}

	if verified {
		sess.MFAVerified = true
		sessionStore.Store(cookie.Value, sess)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"success"}`)
	} else {
		http.Error(w, "Invalid MFA code", http.StatusUnauthorized)
	}
}

