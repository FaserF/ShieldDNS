package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct{}

func (u WebAuthnUser) WebAuthnID() []byte {
	return []byte("admin-user-id") // Static ID for the single admin user
}

func (u WebAuthnUser) WebAuthnName() string {
	return "admin"
}

func (u WebAuthnUser) WebAuthnDisplayName() string {
	return "ShieldDNS Administrator"
}

func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	configLock.RLock()
	defer configLock.RUnlock()

	res := make([]webauthn.Credential, len(config.WebAuthnCredentials))
	for i, c := range config.WebAuthnCredentials {
		transports := make([]protocol.AuthenticatorTransport, len(c.Transport))
		for j, t := range c.Transport {
			transports[j] = protocol.AuthenticatorTransport(t)
		}

		res[i] = webauthn.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Transport:       transports,
			Authenticator: webauthn.Authenticator{
				AAGUID:       c.Authenticator.AAGUID,
				SignCount:    c.Authenticator.SignCount,
				CloneWarning: c.Authenticator.CloneWarning,
			},
		}
	}
	return res
}

func (u WebAuthnUser) WebAuthnIcon() string {
	return ""
}

var (
	wa *webauthn.WebAuthn
	// Temporary store for registration/authentication sessions
	waSessionStore sync.Map // sessionToken -> webauthn.SessionData
)

func initWebAuthn() {
	configLock.RLock()
	domain := config.AdminDomain
	configLock.RUnlock()

	if domain == "" {
		domain = "localhost"
	}

	var err error
	wa, err = webauthn.New(&webauthn.Config{
		RPDisplayName: "ShieldDNS",
		RPID:          domain,
		RPOrigins:     []string{fmt.Sprintf("https://%s", domain)},
	})
	if err != nil {
		fmt.Printf("failed to create webauthn: %v\n", err)
	}
}

var (
	// Temporary store for registration secrets until they are verified
	pendingTOTPSecrets sync.Map // sessionToken -> secret
)

func handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

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

	// Verify the code
	valid := totp.Validate(req.Code, req.Secret)
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
		Secret:    req.Secret,
		CreatedAt: time.Now(),
	})
	config.MFAEnabled = true
	saveConfigNoLock()
	configLock.Unlock()

	// Also mark current session as MFA verified
	if val, found := sessionStore.Load(cookie.Value); found {
		sess := val.(Session)
		sess.MFAVerified = true
		sessionStore.Store(cookie.Value, sess)
	}

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

	saveConfigNoLock()
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
	config.MFAEnabled = false
	config.TOTPConfigs = nil
	config.WebAuthnCredentials = nil
	saveConfigNoLock()
	configLock.Unlock()

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

func handleWebAuthnRegisterStart(w http.ResponseWriter, r *http.Request) {
	if wa == nil {
		initWebAuthn()
	}

	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	options, session, err := wa.BeginRegistration(WebAuthnUser{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	waSessionStore.Store(cookie.Value, *session)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// We need the name from a custom header or query param since wa.FinishRegistration reads the body
	name := r.Header.Get("X-Passkey-Name")

	val, found := waSessionStore.Load(cookie.Value)
	if !found {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}
	session := val.(webauthn.SessionData)

	credential, err := wa.FinishRegistration(WebAuthnUser{}, session, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}

	configLock.Lock()
	if name == "" {
		name = fmt.Sprintf("Passkey %s", time.Now().Format("2006-01-02"))
	}
	config.WebAuthnCredentials = append(config.WebAuthnCredentials, WebAuthnCredential{
		ID:              credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transport:       transports,
		Authenticator: Authenticator{
			AAGUID:       credential.Authenticator.AAGUID,
			SignCount:    credential.Authenticator.SignCount,
			CloneWarning: credential.Authenticator.CloneWarning,
		},
		Name:      name,
		CreatedAt: time.Now(),
	})
	config.MFAEnabled = true
	saveConfigNoLock()
	configLock.Unlock()

	waSessionStore.Delete(cookie.Value)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"success"}`)
}

func handleWebAuthnLoginStart(w http.ResponseWriter, r *http.Request) {
	if wa == nil {
		initWebAuthn()
	}

	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	options, session, err := wa.BeginLogin(WebAuthnUser{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	waSessionStore.Store(cookie.Value, *session)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	val, found := waSessionStore.Load(cookie.Value)
	if !found {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}
	session := val.(webauthn.SessionData)

	_, err = wa.FinishLogin(WebAuthnUser{}, session, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if val, found := sessionStore.Load(cookie.Value); found {
		sess := val.(Session)
		sess.MFAVerified = true
		sessionStore.Store(cookie.Value, sess)
	}

	waSessionStore.Delete(cookie.Value)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"success"}`)
}
