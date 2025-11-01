// Package web provides the web server and UI for the proxy gateway.
package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/manager"
	"strings"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// Security limits and timeouts
	maxCertFileSize     = 5 * 1024 * 1024 // 5MB
	maxPEMBlockSize     = 1 * 1024 * 1024 // 1MB
	maxHeaderBytes      = 1 << 20         // 1MB
	maxCookieHeaderSize = 8192            // 8KB
	readTimeout         = 15 * time.Second
	writeTimeout        = 15 * time.Second
	idleTimeout         = 60 * time.Second
	shutdownTimeout     = 30 * time.Second
	headerReadTimeout   = 10 * time.Second
)

// Server is the primary web server for the application.
type Server struct {
	mainServer      *http.Server
	challengeServer *http.Server // Used only for ACME TLS challenges
	cfg             *config.Config
}

// NewServer creates and configures a new web server with all necessary handlers,
// middleware, and security hardening.
func NewServer(cm *manager.ConfigManager) (*Server, error) {
	cfg := cm.Get()
	s := &Server{cfg: cfg}

	// 1. Set up all routing, middleware, and handlers.
	finalHandler, err := s.newRouter(cm)
	if err != nil {
		return nil, fmt.Errorf("failed to set up router: %w", err)
	}

	// 2. Create the base HTTP server with security timeouts.
	s.mainServer = createBaseServer(cfg.WebAddress, finalHandler)

	// 3. Configure TLS based on the application config.
	if cfg.TLS.Enabled {
		if err := s.configureACMETLS(); err != nil {
			return nil, err
		}
	} else if cfg.SelfSigned.Enabled {
		if err := s.configureSelfSignedTLS(); err != nil {
			return nil, err
		}
	} else {
		log.Warn().Msg("Running in plain HTTP mode - not recommended for production")
	}

	return s, nil
}

// newRouter creates the main router and applies all middleware layers.
func (s *Server) newRouter(cm *manager.ConfigManager) (http.Handler, error) {
	cfg := cm.Get()
	r := mux.NewRouter()

	// --- Layer 1: Core Application Handlers ---
	appRouter := r.PathPrefix("/").Subrouter()
	s.registerAppHandlers(appRouter, cm)

	// --- Layer 2: Authentication Middleware ---
	if cfg.OIDC.Enabled {
		auth, err := s.setupOIDC(r, appRouter, cfg)
		if err != nil {
			return nil, err
		}
		appRouter.Use(auth.Middleware)
	} else {
		log.Warn().Msg("OIDC authentication is DISABLED. The web UI is publicly accessible.")
	}

	// --- Layer 3: CSRF Protection Middleware ---
	isSecure := (cfg.TLS.Enabled || cfg.SelfSigned.Enabled)
	csrfProtectedHandler, err := s.setupCSRF(r, isSecure)
	if err != nil {
		return nil, err
	}

	// --- Layer 4: General Security Middleware ---
	var finalHandler http.Handler = csrfProtectedHandler
	if isSecure {
		finalHandler = securityMiddleware(finalHandler)
		log.Info().Msg("Security middleware enabled (HTTPS mode)")
	}

	// Serve static assets, which do not require CSRF or auth.
	staticFS := GetStaticFS()
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	return finalHandler, nil
}

// registerAppHandlers defines all the application-specific routes.
func (s *Server) registerAppHandlers(r *mux.Router, cm *manager.ConfigManager) {
	wrap := func(h func(*manager.ConfigManager, http.ResponseWriter, *http.Request)) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h(cm, w, r) })
	}
	r.Handle("/", wrap(handleDashboard)).Methods("GET")
	r.Handle("/config/save", wrap(handleSaveConfig)).Methods("POST")
	r.Handle("/group/add", wrap(handleAddGroup)).Methods("POST")
	r.Handle("/group/update", wrap(handleUpdateGroup)).Methods("POST")
	r.Handle("/group/delete", wrap(handleDeleteGroup)).Methods("POST")
	r.Handle("/proxy/add", wrap(handleAddProxy)).Methods("POST")
	r.Handle("/proxy/update", wrap(handleUpdateProxy)).Methods("POST")
	r.Handle("/proxy/toggle", wrap(handleToggleProxy)).Methods("POST")
	r.Handle("/proxy/delete", wrap(handleDeleteProxy)).Methods("POST")
	r.Handle("/policy/add", wrap(handleAddPolicy)).Methods("POST")
	r.Handle("/policy/update", wrap(handleUpdatePolicy)).Methods("POST")
	r.Handle("/policy/toggle", wrap(handleTogglePolicy)).Methods("POST")
	r.Handle("/policy/delete", wrap(handleDeletePolicy)).Methods("POST")
	r.Handle("/proxy/auth/toggle", wrap(handleToggleProxyAuth)).Methods("POST")
	r.Handle("/auth/user/add", wrap(handleAddUser)).Methods("POST")
	r.Handle("/auth/user/delete", wrap(handleDeleteUser)).Methods("POST")
}

// setupOIDC configures the OIDC authentication routes and middleware.
func (s *Server) setupOIDC(rootRouter *mux.Router, appRouter *mux.Router, cfg *config.Config) (*Authenticator, error) {
	log.Info().Msg("OIDC authentication is enabled for the web UI")
	sessionDBPath := cfg.SessionDBPath
	if sessionDBPath == "" {
		sessionDBPath = "sessions.db"
	}
	sessionKey := []byte(cfg.SessionSecretKey)

	auth, err := NewAuthenticator(context.Background(), cfg.OIDC, cfg.AllowedEmails, sessionDBPath, sessionKey)
	if err != nil {
		return nil, err
	}

	rootRouter.HandleFunc("/login-page", LoginPageHandler)
	rootRouter.HandleFunc("/login", auth.LoginHandler)
	rootRouter.HandleFunc("/auth/callback", auth.CallbackHandler)
	appRouter.HandleFunc("/logout", auth.LogoutHandler).Methods("POST")
	return auth, nil
}

// setupCSRF configures the CSRF protection middleware.
func (s *Server) setupCSRF(handler http.Handler, isSecure bool) (http.Handler, error) {
	csrfKey := make([]byte, 32)
	if _, err := rand.Read(csrfKey); err != nil {
		return nil, fmt.Errorf("failed to generate CSRF key: %w", err)
	}

	csrfMiddleware := csrf.Protect(
		csrfKey,
		csrf.Secure(isSecure),
		csrf.Path("/"),
	)

	return csrfMiddleware(handler), nil
}

// createBaseServer returns an http.Server with secure default timeouts.
func createBaseServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ReadHeaderTimeout: headerReadTimeout,
	}
}

// newDefaultTLSConfig returns a tls.Config with strong modern settings.
func newDefaultTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// configureACMETLS sets up the server for ACME (Let's Encrypt).
func (s *Server) configureACMETLS() error {
	log.Info().Str("domain", s.cfg.TLS.Domain).Msg("TLS with ACME is enabled for the web UI")
	if err := os.MkdirAll(s.cfg.TLS.CacheDir, 0700); err != nil {
		return fmt.Errorf("could not create TLS cache directory: %w", err)
	}

	autocertManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.cfg.TLS.Domain),
		Cache:      autocert.DirCache(s.cfg.TLS.CacheDir),
		Email:      s.cfg.TLS.Email,
	}

	if s.cfg.TLS.DirectoryURL != "" {
		log.Info().Str("url", s.cfg.TLS.DirectoryURL).Msg("Using custom ACME directory")
		caCert, err := validateAndLoadCertificate(s.cfg.TLS.RootCA)
		if err != nil {
			return fmt.Errorf("failed to load custom root CA: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return errors.New("failed to parse custom root CA certificate")
		}
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: caCertPool, MinVersion: tls.VersionTLS12},
			},
			Timeout: 30 * time.Second,
		}
		autocertManager.Client = &acme.Client{DirectoryURL: s.cfg.TLS.DirectoryURL, HTTPClient: httpClient}
	}

	s.mainServer.TLSConfig = autocertManager.TLSConfig()
	s.mainServer.TLSConfig.MinVersion = tls.VersionTLS12 // Ensure min version is set

	redirectMux := http.NewServeMux()
	redirectMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
	})
	s.challengeServer = createBaseServer(":80", autocertManager.HTTPHandler(redirectMux))

	return nil
}

// configureSelfSignedTLS sets up the server for self-signed TLS.
func (s *Server) configureSelfSignedTLS() error {
	log.Info().Msg("Self-signed TLS is enabled for the web UI")
	if err := ensureSelfSignedCert(s.cfg.SelfSigned); err != nil {
		return err
	}
	s.mainServer.TLSConfig = newDefaultTLSConfig()
	return nil
}

// ensureSelfSignedCert checks if a self-signed cert exists and generates one if not.
func ensureSelfSignedCert(cfg config.SelfSignedTLSConfig) error {
	if _, err := os.Stat(cfg.CertPath); os.IsNotExist(err) {
		log.Warn().Msg("Self-signed certificate/key not found, generating new ones...")
		if err := generateSelfSignedCert(cfg); err != nil {
			return fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
		log.Info().Str("cert_path", cfg.CertPath).Str("key_path", cfg.KeyPath).Msg("Successfully generated self-signed certificate and key")
	} else {
		log.Info().Msg("Using existing self-signed certificate and key")
		if _, err := validateAndLoadCertificate(cfg.CertPath); err != nil {
			return fmt.Errorf("existing certificate is invalid: %w", err)
		}
	}
	return nil
}

// Start launches the web server(s). This method blocks until the server exits.
func (s *Server) Start() error {
	if s.cfg.TLS.Enabled {
		if s.challengeServer != nil {
			log.Info().Str("addr", s.challengeServer.Addr).Msg("Starting HTTP listener for ACME challenges and redirects")
			go func() {
				if err := s.challengeServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Error().Err(err).Msg("HTTP listener server failed")
				}
			}()
		}
		log.Info().Str("addr", s.mainServer.Addr).Msg("Starting HTTPS web server (ACME)")
		return s.mainServer.ListenAndServeTLS("", "")
	}

	if s.cfg.SelfSigned.Enabled {
		log.Info().Str("addr", s.mainServer.Addr).Msg("Starting HTTPS web server (Self-Signed)")
		return s.mainServer.ListenAndServeTLS(s.cfg.SelfSigned.CertPath, s.cfg.SelfSigned.KeyPath)
	}

	log.Info().Str("addr", s.mainServer.Addr).Msg("Starting plain HTTP web server")
	return s.mainServer.ListenAndServe()
}

// Shutdown gracefully shuts down the web server(s) within the given context.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Info().Msg("Shutting down web server")

	var cancel context.CancelFunc
	if ctx == nil {
		ctx, cancel = context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
	}

	var firstErr error
	if s.challengeServer != nil {
		log.Info().Msg("Shutting down HTTP listener server")
		if err := s.challengeServer.Shutdown(ctx); err != nil {
			firstErr = err
			log.Error().Err(err).Msg("HTTP listener server graceful shutdown failed")
		}
	}

	if err := s.mainServer.Shutdown(ctx); err != nil {
		if firstErr == nil {
			firstErr = err
		}
		log.Error().Err(err).Msg("Main web server graceful shutdown failed")
	}
	return firstErr
}

// securityMiddleware adds essential security headers and performs basic request
// validation for all HTTPS requests.
func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cookieHeader := r.Header.Get("Cookie"); len(cookieHeader) > maxCookieHeaderSize {
			log.Warn().Int("size", len(cookieHeader)).Msg("Cookie header exceeds size limit")
			http.Error(w, "Cookie header too large", http.StatusRequestHeaderFieldsTooLarge)
			return
		}

		if err := validateURL(r.URL); err != nil {
			log.Warn().Err(err).Str("url", r.URL.String()).Msg("Invalid URL")
			http.Error(w, "Invalid URL format", http.StatusBadRequest)
			return
		}

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		next.ServeHTTP(w, r)
	})
}

// validateAndLoadCertificate safely loads and validates certificate files.
func validateAndLoadCertificate(certPath string) ([]byte, error) {
	info, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot stat certificate file: %w", err)
	}
	if info.Size() > maxCertFileSize {
		return nil, fmt.Errorf("certificate file too large: %d bytes (max %d)", info.Size(), maxCertFileSize)
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read certificate file: %w", err)
	}

	if err := validatePEMData(certPEM); err != nil {
		return nil, fmt.Errorf("invalid PEM data: %w", err)
	}
	return certPEM, nil
}

// validatePEMData inspects PEM data to prevent quadratic complexity attacks.
func validatePEMData(data []byte) error {
	var blockCount int
	for remaining := data; len(remaining) > 0; {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		blockCount++
		if blockCount > 100 {
			return errors.New("too many PEM blocks")
		}
		if len(block.Bytes) > maxPEMBlockSize {
			return fmt.Errorf("PEM block too large: %d bytes", len(block.Bytes))
		}
		remaining = rest
	}
	if blockCount == 0 {
		return errors.New("no valid PEM blocks found")
	}
	return nil
}

// validateURL performs strict URL validation.
func validateURL(u *url.URL) error {
	if u == nil {
		return errors.New("nil URL")
	}
	host := u.Host
	if host == "" {
		return nil
	}
	if strings.Contains(host, "[") {
		if !strings.Contains(host, "]") {
			return errors.New("unclosed IPv6 bracket in hostname")
		}
		start, end := strings.Index(host, "["), strings.Index(host, "]")
		if start > end {
			return errors.New("malformed IPv6 hostname")
		}
		if net.ParseIP(host[start+1:end]) == nil {
			return errors.New("invalid IPv6 address in hostname")
		}
		if end < len(host)-1 && host[end+1] != ':' {
			return errors.New("invalid character after IPv6 bracket")
		}
	}
	return nil
}

// generateSelfSignedCert creates a new self-signed certificate and private key.
func generateSelfSignedCert(cfg config.SelfSignedTLSConfig) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Proxy Gateway Development"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if len(cfg.Hostnames) == 0 {
		return errors.New("no hostnames specified for self-signed certificate")
	}
	for _, h := range cfg.Hostnames {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 {
		return errors.New("no valid hostnames or IP addresses provided for certificate")
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.OpenFile(cfg.CertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	keyOut, err := os.OpenFile(cfg.KeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	log.Info().Strs("dns_names", template.DNSNames).Int("ip_addresses", len(template.IPAddresses)).Msg("Generated self-signed certificate")
	return nil
}
