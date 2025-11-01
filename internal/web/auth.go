// ./internal/web/auth.go

package web

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"net/http"
	"proxy-gateway/internal/config"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
)

func init() {
	gob.Register(&oidc.IDToken{})
	gob.Register(&oauth2.Token{})
}

// Authenticator is the OIDC authenticator.
type Authenticator struct {
	provider      *oidc.Provider
	config        oauth2.Config
	sessionStore  sessions.Store
	allowedEmails []string
}

// NewAuthenticator creates a new authenticator.
func NewAuthenticator(ctx context.Context, oidcCfg config.OIDCConfig, allowedEmails []string, sessionDBPath string, sessionKey []byte) (*Authenticator, error) {
	provider, err := oidc.NewProvider(ctx, oidcCfg.Issuer)
	if err != nil {
		return nil, err
	}

	config := oauth2.Config{
		ClientID:     oidcCfg.ClientID,
		ClientSecret: oidcCfg.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  oidcCfg.RedirectURL,
		Scopes:       []string{oidc.ScopeOpenID, "email"},
	}

	// Open the SQLite database. It will be created if it doesn't exist.
	// Using WAL mode is recommended for concurrent access.
	db, err := sql.Open("sqlite3", sessionDBPath+"?_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	// The sqlitestore will create the sessions table for us.
	// Create the custom SQLite session store
	sessionStore, err := NewSQLiteStore(db, sessionKey)
	if err != nil {
		return nil, err
	}
	sessionStore.MaxLength(8192)
	log.Info().Str("path", sessionDBPath).Msg("Using SQLite3 for web UI session storage")

	return &Authenticator{
		provider:      provider,
		config:        config,
		sessionStore:  sessionStore,
		allowedEmails: allowedEmails,
	}, nil
}

// CallbackHandler handles the OIDC callback.
func (a *Authenticator) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, err := a.sessionStore.Get(r, "proxy-gateway-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	oauthToken, err := a.config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth token", http.StatusInternalServerError)
		return
	}

	verifier := a.provider.Verifier(&oidc.Config{ClientID: a.config.ClientID})
	idToken, err := verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = oauthToken.AccessToken
	session.Values["email"] = claims.Email
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

// LoginHandler handles the OIDC login.
func (a *Authenticator) LoginHandler(w http.ResponseWriter, r *http.Request) {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	session, err := a.sessionStore.Get(r, "proxy-gateway-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["state"] = state
	if err := session.Save(r, w); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, a.config.AuthCodeURL(state), http.StatusFound)
}

// LogoutHandler handles the OIDC logout.
func (a *Authenticator) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	session, _ := a.sessionStore.Get(r, "proxy-gateway-session")
	session.Options.MaxAge = -1 // delete
	_ = session.Save(r, w)
	http.Redirect(w, r, "/login-page", http.StatusFound)
}

// Middleware checks if the user is authenticated.
// If not authenticated, it redirects to the /login-page.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := a.sessionStore.Get(r, "proxy-gateway-session")
		// If session is invalid or doesn't exist, redirect to login page.
		if err != nil {
			http.Redirect(w, r, "/login-page", http.StatusFound)
			return
		}

		// Check if the user is authenticated
		if _, ok := session.Values["id_token"]; !ok {
			http.Redirect(w, r, "/login-page", http.StatusFound)
			return
		}

		// --- NEW AUTHORIZATION LOGIC ---
		// If a list of allowed emails is configured, check against it.
		if len(a.allowedEmails) > 0 {
			userEmail, ok := session.Values["email"].(string)
			if !ok {
				log.Warn().Msg("User is authenticated but no email found in session. Denying access.")
				http.Error(w, "Access Denied: Could not verify your email.", http.StatusForbidden)
				return
			}

			isAllowed := false
			for _, allowedEmail := range a.allowedEmails {
				if userEmail == allowedEmail {
					isAllowed = true
					break
				}
			}

			if !isAllowed {
				log.Warn().Str("email", userEmail).Msg("Authenticated user denied access due to email not being in the allowed list.")
				http.Error(w, "Access Denied: Your email is not authorized to access this application.", http.StatusForbidden)
				return
			}
		}

		// If authenticated (and authorized), call the next handler
		next.ServeHTTP(w, r)
	})
}

// randString generates a random string.
func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
