// Package proxy contains the HTTP/S proxy implementation.
package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"proxy-gateway/internal/config"
	"proxy-gateway/internal/dns"
	"proxy-gateway/internal/policy"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// HTTPProxy implements the Proxy interface for HTTP/S services.
type HTTPProxy struct {
	name     string
	server   *http.Server
	pe       *policy.Engine
	resolver *dns.Resolver
	auth     *config.Auth
}

// NewHTTPProxy creates and configures a new HTTPProxy instance.
func NewHTTPProxy(cfg config.ProxyConfig, pe *policy.Engine, resolver *dns.Resolver) *HTTPProxy {
	p := &HTTPProxy{
		name:     cfg.Name,
		pe:       pe,
		resolver: resolver,
	}

	if cfg.Auth.Enabled && len(cfg.Auth.Users) > 0 {
		p.auth = &cfg.Auth
		log.Info().Str("proxy_name", cfg.Name).Int("user_count", len(cfg.Auth.Users)).Msg("HTTP proxy Argon2 authentication enabled")
	} else {
		log.Warn().Str("proxy_name", cfg.Name).Msg("HTTP proxy authentication is disabled")
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   10,
	}
	p.server = &http.Server{
		Addr: cfg.ListenAddress,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p.httpProxyHandler(w, r, transport)
		}),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return p
}

// Name returns the name of the proxy.
func (p *HTTPProxy) Name() string { return p.name }

// Start starts the HTTP proxy server.
func (p *HTTPProxy) Start(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.server.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Str("proxy_name", p.name).Msg("HTTP/S proxy graceful shutdown failed")
		}
	}()

	log.Info().Str("proxy_name", p.name).Str("address", p.server.Addr).Msg("Starting HTTP/S proxy")
	if err := p.server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// This error is expected on graceful shutdown
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "Server closed") {
			return err
		}
	}
	return nil
}

// httpProxyHandler is the main handler for all incoming proxy requests.
// It handles authentication, policy evaluation, and forwarding for both HTTP and HTTPS.
func (p *HTTPProxy) httpProxyHandler(w http.ResponseWriter, r *http.Request, transport *http.Transport) {
	if p.auth != nil && len(p.auth.Users) > 0 {
		if !p.authenticate(w, r) {
			return // Authentication failed, response already sent.
		}
	}

	clientIPStr, _, _ := net.SplitHostPort(r.RemoteAddr)
	clientIP := net.ParseIP(clientIPStr)

	clientHostnames, err := net.LookupAddr(clientIPStr)
	if err != nil {
		log.Debug().Err(err).Str("proxy_name", p.name).Str("client_ip", clientIPStr).Msg("Could not perform reverse DNS lookup for client")
	}

	destHost, destPortStr, err := net.SplitHostPort(r.Host)
	if err != nil {
		destHost = r.Host
		destPortStr = "80"
		if r.Method == "CONNECT" {
			destPortStr = "443"
		}
	}
	destPort, _ := strconv.Atoi(destPortStr)
	var destIP net.IP
	destIP = net.ParseIP(destHost)
	if destIP == nil {
		_, ip, err := p.resolver.Resolve(context.Background(), destHost)
		if err != nil {
			log.Warn().Err(err).Str("proxy_name", p.name).Str("host", destHost).Msg("DNS resolution failed")
			http.Error(w, "DNS resolution failed by proxy", http.StatusServiceUnavailable)
			return
		}
		destIP = ip
	}
	var action config.PolicyAction
	var ruleName string
	if p.pe != nil {
		action, ruleName = p.pe.Evaluate(p.name, clientIP, clientHostnames, destHost, destIP, destPort)
	} else {
		// If no policy engine is configured, deny by default.
		action, ruleName = config.DenyAction, "default_deny_no_engine"
	}
	log.Info().
		Str("proxy_name", p.name).Str("protocol", "http").Str("client_ip", clientIPStr).
		Str("method", r.Method).Str("destination", r.Host).Str("policy_action", string(action)).
		Str("rule_name", ruleName).Msg("Request evaluated")
	if action == config.DenyAction {
		http.Error(w, "Forbidden by proxy policy", http.StatusForbidden)
		return
	}
	if r.Method == http.MethodConnect {
		p.handleHTTPSConnect(w, r)
	} else {
		p.handleHTTPRequest(w, r, transport)
	}
}

// authenticate checks the Proxy-Authorization header for valid credentials.
func (p *HTTPProxy) authenticate(w http.ResponseWriter, r *http.Request) bool {
	authHeader := r.Header.Get("Proxy-Authorization")
	if authHeader == "" {
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return false
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Basic" {
		http.Error(w, "Bad proxy authorization header", http.StatusBadRequest)
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		http.Error(w, "Bad proxy authorization header", http.StatusBadRequest)
		return false
	}

	creds := strings.SplitN(string(decoded), ":", 2)
	if len(creds) != 2 {
		http.Error(w, "Bad proxy authorization header", http.StatusBadRequest)
		return false
	}

	username := creds[0]
	password := creds[1]

	var expectedHash string
	userFound := false
	for _, user := range p.auth.Users {
		if user.Username == username {
			expectedHash = user.Password
			userFound = true
			break
		}
	}

	if !userFound {
		log.Warn().Str("proxy_name", p.name).Str("username", username).Msg("HTTP Proxy: Authentication failed: user not found")
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return false
	}

	match, err := VerifyPassword(password, expectedHash)
	if err != nil {
		log.Error().Err(err).Str("proxy_name", p.name).Str("username", username).Msg("HTTP Proxy: Password verification failed: internal error")
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return false
	}

	if !match {
		log.Warn().Str("proxy_name", p.name).Str("username", username).Msg("HTTP Proxy: Authentication failed: invalid password")
		w.Header().Set("Proxy-Authenticate", `Basic realm="Restricted"`)
		http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return false
	}

	log.Info().Str("proxy_name", p.name).Str("username", username).Msg("HTTP Proxy: User authenticated successfully")
	return true
}

// handleHTTPSConnect handles the HTTP CONNECT method for tunneling HTTPS traffic.
func (p *HTTPProxy) handleHTTPSConnect(w http.ResponseWriter, r *http.Request) {
	destConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	log.Debug().Str("proxy_name", p.name).Str("destination", r.Host).Msg("HTTPS tunnel established")
	var wg sync.WaitGroup
	wg.Add(2)
	go transfer(destConn, clientConn, &wg)
	go transfer(clientConn, destConn, &wg)
	wg.Wait()
	destConn.Close()
	clientConn.Close()
}

// handleHTTPRequest handles plain HTTP requests.
func (p *HTTPProxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request, transport *http.Transport) {
	r.RequestURI = ""
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authorization")
	resp, err := transport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)

	if _, err := io.Copy(w, resp.Body); err != nil {
		// handle the error, e.g., log it
		log.Printf("failed to copy response body: %v", err)
	}
}

// transfer copies data between two connections and closes them when done.
func transfer(destination io.WriteCloser, source io.ReadCloser, wg *sync.WaitGroup) {
	defer wg.Done()
	if _, err := io.Copy(destination, source); err != nil {
		log.Printf("failed to copy: %v", err)
	}
	destination.Close()
	source.Close()
}
