package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// WebAuthnUser implements webauthn.User interface
type WebAuthnUser struct {
	// CurrentRequest is used for "smart healing" of legacy credentials
	// where backup flags were not previously stored.
	CurrentRequest *http.Request
}

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
	// Smart Healing: If this is a login request, we try to detect if the stored
	// credential is "legacy" (no backup flags) and temporarily align them
	// with the incoming assertion to pass the consistency check.
	var incomingID []byte
	var incomingFlags protocol.AuthenticatorFlags
	hasIncoming := false

	if u.CurrentRequest != nil {
		parsed, err := protocol.ParseCredentialRequestResponse(u.CurrentRequest)
		if err == nil && parsed != nil {
			incomingID = parsed.RawID
			incomingFlags = parsed.Response.AuthenticatorData.Flags
			hasIncoming = true
		}
	}

	for i, c := range config.WebAuthnCredentials {
		transports := make([]protocol.AuthenticatorTransport, len(c.Transport))
		for j, t := range c.Transport {
			transports[j] = protocol.AuthenticatorTransport(t)
		}

		flags := webauthn.CredentialFlags{
			UserPresent:    c.UserPresent,
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		}

		// Smart Healing: If this is a legacy credential (both backup flags false),
		// we temporarily align it with the incoming assertion to pass the consistency check.
		if hasIncoming && string(c.ID) == string(incomingID) && !c.BackupEligible && !c.BackupState {
			flags.BackupEligible = incomingFlags.HasBackupEligible()
			flags.BackupState = incomingFlags.HasBackupState()
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
			Flags: flags,
		}
	}
	return res
}

func (u WebAuthnUser) WebAuthnIcon() string {
	return ""
}

var (
	wa          *webauthn.WebAuthn
	webauthnMu  sync.RWMutex
	currentRPID string
	// Temporary store for registration/authentication sessions
	waSessionStore sync.Map // sessionToken -> webauthn.SessionData
)

func initWebAuthn() error {
	configLock.RLock()
	domain := config.AdminDomain
	configLock.RUnlock()

	if domain == "" {
		domain = "localhost"
	}

	webauthnMu.RLock()
	if wa != nil && currentRPID == domain {
		webauthnMu.RUnlock()
		return nil
	}
	webauthnMu.RUnlock()

	webauthnMu.Lock()
	defer webauthnMu.Unlock()

	// Double-check under lock
	if wa != nil && currentRPID == domain {
		return nil
	}

	newWa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "ShieldDNS",
		RPID:          domain,
		RPOrigins:     []string{fmt.Sprintf("https://%s", domain)},
	})
	if err != nil {
		slog.Error("failed to create webauthn", "error", err)
		return err
	}

	wa = newWa
	currentRPID = domain
	return nil
}

func handleWebAuthnRegisterStart(w http.ResponseWriter, r *http.Request) {
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
	if err := initWebAuthn(); err != nil {
		http.Error(w, "WebAuthn initialization failed", http.StatusInternalServerError)
		return
	}

	webauthnMu.RLock()
	currentWA := wa
	webauthnMu.RUnlock()

	if currentWA == nil {
		http.Error(w, "WebAuthn not initialized", http.StatusServiceUnavailable)
		return
	}

	cookie, err := r.Cookie(CookieName)
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	options, session, err := currentWA.BeginRegistration(WebAuthnUser{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	waSessionStore.Store(cookie.Value, *session)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func handleWebAuthnRegisterFinish(w http.ResponseWriter, r *http.Request) {
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

	webauthnMu.RLock()
	currentWA := wa
	webauthnMu.RUnlock()

	if currentWA == nil {
		http.Error(w, "WebAuthn not initialized", http.StatusServiceUnavailable)
		return
	}

	credential, err := currentWA.FinishRegistration(&WebAuthnUser{CurrentRequest: r}, session, r)
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
		UserPresent:    credential.Flags.UserPresent,
		UserVerified:   credential.Flags.UserVerified,
		BackupEligible: credential.Flags.BackupEligible,
		BackupState:    credential.Flags.BackupState,
		Name:           name,
		CreatedAt:      time.Now(),
	})
	config.MFAEnabled = true
	if err := saveConfigNoLock(); err != nil {
		slog.Error("Failed to save config in handleWebAuthnRegisterFinish", "error", err)
		http.Error(w, "Failed to save configuration", http.StatusInternalServerError)
		configLock.Unlock()
		return
	}
	configLock.Unlock()

	// Mark session as MFA verified
	if val, found := sessionStore.Load(cookie.Value); found {
		sess := val.(Session)
		sess.MFAVerified = true
		sessionStore.Store(cookie.Value, sess)
	}

	waSessionStore.Delete(cookie.Value)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"success"}`)
}

func handleWebAuthnLoginStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := initWebAuthn(); err != nil {
		http.Error(w, "WebAuthn initialization failed", http.StatusInternalServerError)
		return
	}

	webauthnMu.RLock()
	currentWA := wa
	webauthnMu.RUnlock()

	if currentWA == nil {
		http.Error(w, "WebAuthn not initialized", http.StatusServiceUnavailable)
		return
	}

	cookie, err := r.Cookie(CookieName)
	var sessionKey string
	if err != nil || cookie.Value == "" {
		sessionKey = generateToken()
		isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    sessionKey,
			Path:     "/",
			HttpOnly: true,
			Secure:   isSecure,
			MaxAge:   int(SessionDuration.Seconds()),
			SameSite: http.SameSiteLaxMode,
		})
	} else {
		sessionKey = cookie.Value
	}

	options, session, err := currentWA.BeginLogin(WebAuthnUser{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	waSessionStore.Store(sessionKey, *session)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func handleWebAuthnLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie(CookieName)
	if err != nil || cookie.Value == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	val, found := waSessionStore.Load(cookie.Value)
	if !found {
		http.Error(w, "Session not found", http.StatusBadRequest)
		return
	}
	session := val.(webauthn.SessionData)

	// Buffer body to allow multiple reads for "smart healing"
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	webauthnMu.RLock()
	currentWA := wa
	webauthnMu.RUnlock()

	if currentWA == nil {
		http.Error(w, "WebAuthn not initialized", http.StatusServiceUnavailable)
		return
	}

	credential, err := currentWA.FinishLogin(&WebAuthnUser{CurrentRequest: r}, session, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Update the stored credential with new metadata (SignCount, CloneWarning)
	configLock.Lock()
	foundCred := false
	for i, c := range config.WebAuthnCredentials {
		if string(c.ID) == string(credential.ID) {
			config.WebAuthnCredentials[i].Authenticator.SignCount = credential.Authenticator.SignCount
			config.WebAuthnCredentials[i].Authenticator.CloneWarning = credential.Authenticator.CloneWarning
			config.WebAuthnCredentials[i].UserPresent = credential.Flags.UserPresent
			config.WebAuthnCredentials[i].UserVerified = credential.Flags.UserVerified
			config.WebAuthnCredentials[i].BackupEligible = credential.Flags.BackupEligible
			config.WebAuthnCredentials[i].BackupState = credential.Flags.BackupState
			foundCred = true
			break
		}
	}

	if foundCred {
		if err := saveConfigNoLock(); err != nil {
			slog.Error("Failed to save config in handleWebAuthnLoginFinish", "error", err)
		}
	}
	configLock.Unlock()

	ip := getClientIP(r)
	if val, found := sessionStore.Load(cookie.Value); found {
		sess := val.(Session)
		sess.MFAVerified = true
		sessionStore.Store(cookie.Value, sess)
	} else {
		sess := Session{
			Token:       cookie.Value,
			RemoteIP:    ip,
			UserAgent:   r.UserAgent(),
			CreatedAt:   time.Now(),
			ExpiresAt:   time.Now().Add(SessionDuration),
			MFAVerified: true,
		}
		sessionStore.Store(cookie.Value, sess)
	}

	configLock.Lock()
	if !config.LastLogin.IsZero() {
		config.PreviousLogin = config.LastLogin
	}
	config.LastLogin = time.Now()
	_ = saveConfigNoLock()
	configLock.Unlock()

	waSessionStore.Delete(cookie.Value)
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `{"status":"success"}`)
}
